"""Bound protected object adapters. Call only through authorized platform storage."""

import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from riswan_platform.data_protection import ProtectionDenied


def object_key(key: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}/[0-9a-f]{64}/[0-9a-f]{32}", key):
        raise ProtectionDenied("Invalid protected object reference.")
    return key


class LocalObjects:
    def __init__(self, path: Path):
        self._path = path
        if os.name == "posix":
            try:
                os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        with closing(sqlite3.connect(self._path)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS protected_objects (id TEXT PRIMARY KEY, payload BLOB NOT NULL)"
            )

    def put(self, key: str, payload: bytes) -> None:
        with closing(sqlite3.connect(self._path)) as db, db:
            db.execute("INSERT INTO protected_objects VALUES (?, ?)", (object_key(key), payload))

    def get(self, key: str) -> bytes:
        with closing(sqlite3.connect(self._path)) as db:
            row = db.execute(
                "SELECT payload FROM protected_objects WHERE id = ?", (object_key(key),)
            ).fetchone()
        if row is None:
            raise ProtectionDenied("Protected object unavailable.")
        return bytes(row[0])

    def delete(self, key: str) -> None:
        with closing(sqlite3.connect(self._path)) as db, db:
            db.execute("DELETE FROM protected_objects WHERE id = ?", (object_key(key),))


class S3Objects:
    def __init__(self, client: Any, bucket: str, owner_account: str):
        self._client, self._bucket, self._owner = client, bucket, owner_account

    def put(self, key: str, payload: bytes) -> None:
        self._client.put_object(
            Bucket=self._bucket,
            Key=object_key(key),
            Body=payload,
            ExpectedBucketOwner=self._owner,
            IfNoneMatch="*",
        )

    def get(self, key: str) -> bytes:
        with closing(
            self._client.get_object(
                Bucket=self._bucket,
                Key=object_key(key),
                ExpectedBucketOwner=self._owner,
            )["Body"]
        ) as body:
            return bytes(body.read())

    def delete(self, key: str) -> None:
        self._client.delete_object(
            Bucket=self._bucket,
            Key=object_key(key),
            ExpectedBucketOwner=self._owner,
        )


class AzureObjects:
    def __init__(self, container: Any):
        self._container = container

    def put(self, key: str, payload: bytes) -> None:
        self._container.get_blob_client(object_key(key)).upload_blob(payload, overwrite=False)

    def get(self, key: str) -> bytes:
        return bytes(self._container.get_blob_client(object_key(key)).download_blob().readall())

    def delete(self, key: str) -> None:
        self._container.get_blob_client(object_key(key)).delete_blob()


class GoogleObjects:
    def __init__(self, bucket: Any):
        self._bucket = bucket

    def put(self, key: str, payload: bytes) -> None:
        self._bucket.blob(object_key(key)).upload_from_string(
            payload, if_generation_match=0, timeout=10
        )

    def get(self, key: str) -> bytes:
        return bytes(self._bucket.blob(object_key(key)).download_as_bytes(timeout=10))

    def delete(self, key: str) -> None:
        self._bucket.blob(object_key(key)).delete(timeout=10)
