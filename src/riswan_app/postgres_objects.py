"""PostgreSQL RLS adapter for encrypted object envelopes."""

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from importlib.resources import files
from typing import Any
from uuid import UUID

from riswan_platform.core.context import require_context
from riswan_platform.data_protection import ProtectionDenied

from .protected_objects import object_key


def migrate(connection: Any) -> None:
    sql = (
        files("riswan_app")
        .joinpath("migrations/0001_protected_objects.sql")
        .read_text(encoding="utf-8")
    )
    with connection.transaction():
        connection.execute(sql)


class PostgresObjects:
    def __init__(self, pool: Any):
        self._pool = pool
        with pool.connection() as db:
            row = db.execute("""
                SELECT r.rolsuper, r.rolbypassrls, pg_has_role(c.relowner, 'MEMBER'),
                       c.relrowsecurity, c.relforcerowsecurity,
                       pg_has_role('riswan_runtime', 'MEMBER')
                FROM pg_catalog.pg_roles r
                JOIN pg_catalog.pg_class c ON c.oid = 'riswan_data.protected_objects'::regclass
                WHERE r.rolname = current_user
            """).fetchone()
        if row is None or tuple(row) != (False, False, False, True, True, True):
            raise ProtectionDenied("Invalid runtime database role or policy.")

    @contextmanager
    def _connection(self, key: str) -> Iterator[tuple[Any, UUID, str, UUID]]:
        context = require_context()
        tenant, product, obj = object_key(key).split("/")
        if (
            tenant != context.tenant_id.hex
            or product != sha256(context.product_id.encode()).hexdigest()
        ):
            raise ProtectionDenied("Protected object unavailable.")
        with self._pool.connection() as db, db.transaction():
            db.execute(
                "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', %s, true)",
                (str(context.tenant_id), context.product_id),
            )
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
