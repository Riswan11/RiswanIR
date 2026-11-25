"""Read bounded gzip logs from an account- and region-specific S3 prefix."""

import gzip
import io
import json
import zlib
from collections.abc import Iterator
from datetime import timedelta, timezone
from typing import Any

from ...core.fields import required, utc_timestamp
from ...models.collection import CollectionRequest
from ...models.connector import ConnectorCapabilities, ConnectorConfig, ConnectorKind
from ..base import CollectedBatch, CollectionFailure
from .authentication import log_prefix
from .cloudtrail import validate_scope
from .requests import RequestBudget


class S3CloudTrailLogs:
    capabilities = ConnectorCapabilities(
        kind=ConnectorKind.S3,
        operations=("s3:ListBucket", "s3:GetObject"),
        data_events=True,
    )

    def __init__(self, config: ConnectorConfig, client: Any, budget: RequestBudget) -> None:
        self.config = config
        self.client = client
        self.budget = budget
        self.prefix = log_prefix(config)

    def collect(self, window: CollectionRequest) -> Iterator[CollectedBatch]:
        source = self.config.s3
        assert source is not None
        start = window.start.astimezone(timezone.utc).date()
        end = window.end.astimezone(timezone.utc).date()
        while start <= end:
            prefix = f"{self.prefix}{start:%Y/%m/%d}/"
            for key in self.keys(prefix):
                yield from self.read(key, window)
            start += timedelta(days=1)

    def keys(self, prefix: str) -> Iterator[str]:
        source = self.config.s3
        assert source is not None
        token = None
        tokens: set[str] = set()
        while True:
            args = {
                "Bucket": source.bucket,
                "Prefix": prefix,
                "ExpectedBucketOwner": source.owner_account_id,
            }
            if token:
                args["ContinuationToken"] = token
            reply = self.budget.call("list_objects_v2", lambda: self.client.list_objects_v2(**args))
            for entry in reply.get("Contents", []):
                key = entry.get("Key")
                if not isinstance(key, str) or not key.startswith(prefix):
                    raise CollectionFailure("list_objects_v2", "object_outside_scope")
                if key.endswith(".json.gz"):
                    if entry.get("Size", 0) > self.config.max_object_bytes:
                        raise CollectionFailure("list_objects_v2", "object_limit_exceeded")
                    yield key
            if not reply.get("IsTruncated"):
                return
            token = reply.get("NextContinuationToken")
            if not token or token in tokens:
                raise CollectionFailure("list_objects_v2", "pagination_loop")
            tokens.add(token)

    def read(self, key: str, window: CollectionRequest) -> Iterator[CollectedBatch]:
        source = self.config.s3
        assert source is not None

        def download() -> bytes:
            response = self.client.get_object(
                Bucket=source.bucket, Key=key, ExpectedBucketOwner=source.owner_account_id
            )
            body = response["Body"]
            try:
                content = body.read(self.config.max_object_bytes + 1)
            finally:
                body.close()
            if len(content) > self.config.max_object_bytes:
                raise CollectionFailure("get_object", "object_limit_exceeded")
            return content

        compressed = self.budget.call("get_object", download)
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
                decoded = stream.read(self.config.max_object_bytes + 1)
            if len(decoded) > self.config.max_object_bytes:
                raise CollectionFailure("get_object", "decompressed_limit_exceeded")
            raw = json.loads(decoded)
            if not isinstance(raw, dict) or not isinstance(raw.get("Records"), list):
                raise ValueError
            records = []
            for item in raw["Records"]:
                timestamp = utc_timestamp(required(item, "eventTime"))
                validate_scope(item, self.config, "get_object")
                if window.start <= timestamp <= window.end:
                    records.append(item)
        except (OSError, ValueError, OverflowError, EOFError, RecursionError, zlib.error):
            raise CollectionFailure("get_object", "malformed_log") from None
        for index in range(0, len(records), 2000):
            yield CollectedBatch(f"s3://{source.bucket}/{key}", records[index : index + 2000])
