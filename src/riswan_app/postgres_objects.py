"""PostgreSQL RLS adapter for encrypted object envelopes."""

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from typing import Any
from uuid import UUID

from riswan_platform.core.context import require_context
from riswan_platform.data_protection import ProtectionDenied

from .postgres_scope import ScopedPostgres
from .postgres_scope import migrate as migrate
from .protected_objects import object_key


class PostgresObjects:
    def __init__(self, pool: Any):
        self._scope = ScopedPostgres(pool, ("protected_objects",))

    @contextmanager
    def _connection(self, key: str) -> Iterator[tuple[Any, UUID, str, UUID]]:
        context = require_context()
        tenant, product, obj = object_key(key).split("/")
        if (
            tenant != context.tenant_id.hex
            or product != sha256(context.product_id.encode()).hexdigest()
        ):
            raise ProtectionDenied("Protected object unavailable.")
        with self._scope.transaction() as (db, _):
            yield db, context.tenant_id, context.product_id, UUID(hex=obj)

    def put(self, key: str, payload: bytes) -> None:
        with self._connection(key) as (db, tenant, product, obj):
            db.execute(
                "INSERT INTO riswan_data.protected_objects VALUES (%s, %s, %s, %s)",
                (tenant, product, obj, payload),
            )

    def get(self, key: str) -> bytes:
        with self._connection(key) as (db, _, _, obj):
            row = db.execute(
                "SELECT envelope FROM riswan_data.protected_objects WHERE object_id = %s",
                (obj,),
            ).fetchone()
            if row is None:
                raise ProtectionDenied("Protected object unavailable.")
            return bytes(row[0])

    def delete(self, key: str) -> None:
        with self._connection(key) as (db, _, _, obj):
            db.execute("DELETE FROM riswan_data.protected_objects WHERE object_id = %s", (obj,))
