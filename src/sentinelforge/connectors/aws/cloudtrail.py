"""Collect bounded, regional CloudTrail Event History windows."""

import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

from ...models import CloudTrailRecord
from ...models.collection import CollectionRequest
from ...models.connector import ConnectorCapabilities, ConnectorConfig, ConnectorKind
from ..base import CollectedBatch, CollectionFailure
from .requests import RequestBudget


def validate_scope(record: CloudTrailRecord, config: ConnectorConfig, operation: str) -> None:
    recipient = record.get("recipientAccountId") or record.get("recipientAccountID")
    region = record.get("awsRegion")
    if (recipient is not None and recipient != config.account.account_id) or (
        region is not None and region != config.account.region
    ):
        raise CollectionFailure(operation, "record_outside_scope")


class CloudTrailHistory:
    capabilities = ConnectorCapabilities(
        kind=ConnectorKind.HISTORY,
        operations=("cloudtrail:LookupEvents",),
    )

    def __init__(self, config: ConnectorConfig, client: Any, budget: RequestBudget) -> None:
        self.config = config
        self.client = client
        self.budget = budget

    def collect(self, window: CollectionRequest) -> Iterator[CollectedBatch]:
        if window.start < datetime.now(timezone.utc) - timedelta(days=90):
            raise CollectionFailure("lookup_events", "window_outside_event_history")
        account = self.config.account
        location = f"cloudtrail://{account.account_id}/{account.region}/event-history"
        tokens: set[str] = set()
        token = None
        while True:
            args: dict[str, object] = {
                "StartTime": window.start,
                "EndTime": window.end,
                "MaxResults": 50,
            }
            if token:
                args["NextToken"] = token
            response = self.budget.call(
                "lookup_events",
                lambda: self.client.lookup_events(**args),
                regional_limit=(account.account_id, account.region),
            )
            records = []
            try:
                for entry in response.get("Events", []):
                    record = json.loads(entry["CloudTrailEvent"])
                    if not isinstance(record, dict):
                        raise ValueError
                    validate_scope(record, self.config, "lookup_events")
                    records.append(record)
            except (ValueError, TypeError, KeyError, RecursionError):
                raise CollectionFailure("lookup_events", "malformed_event") from None
            if records:
                yield CollectedBatch(location, records)
            token = response.get("NextToken")
            if not token:
                return
            if token in tokens:
                raise CollectionFailure("lookup_events", "pagination_loop")
            tokens.add(token)
