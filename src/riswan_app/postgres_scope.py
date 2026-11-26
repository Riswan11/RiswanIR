"""Versioned PostgreSQL migrations and shared runtime transaction scope."""

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from importlib.resources import files
from typing import Any

from riswan_platform.core.context import PlatformContext, require_context
from riswan_platform.data_protection import ProtectionDenied

MIGRATIONS = (
    "0001_protected_objects.sql",
    "0002_case_ownership.sql",
    "0003_investigations.sql",
    "0004_revisions.sql",
    "0005_legal_holds.sql",
)


def migrate(connection: Any) -> None:
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(947047)")
        connection.execute("CREATE SCHEMA IF NOT EXISTS riswan_data")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS riswan_data.schema_migrations (
                version integer PRIMARY KEY, checksum text NOT NULL
            )
        """)
        applied = dict(
            connection.execute(
                "SELECT version, checksum FROM riswan_data.schema_migrations"
            ).fetchall()
        )
        if set(applied) != set(range(1, len(applied) + 1)) or len(applied) > len(MIGRATIONS):
            raise ProtectionDenied("Unsupported PostgreSQL schema version.")
        resources = files("riswan_app").joinpath("migrations")
        for version, filename in enumerate(MIGRATIONS, 1):
            script = resources.joinpath(filename).read_text(encoding="utf-8")
            digest = sha256(script.encode()).hexdigest()
            if version in applied:
                if applied[version] != digest:
                    raise ProtectionDenied("PostgreSQL migration checksum mismatch.")
                continue
            connection.execute(script)
            connection.execute(
                "INSERT INTO riswan_data.schema_migrations VALUES (%s, %s)", (version, digest)
            )


class ScopedPostgres:
    def __init__(self, pool: Any, tables: tuple[str, ...]):
        self._pool = pool
        with pool.connection() as db:
            rows = db.execute(
                """
                SELECT r.rolsuper, r.rolbypassrls, pg_has_role(c.relowner, 'MEMBER'),
                       c.relrowsecurity, c.relforcerowsecurity,
                       pg_has_role('riswan_runtime', 'MEMBER')
                FROM pg_catalog.pg_roles r
                JOIN pg_catalog.pg_namespace n ON n.nspname = 'riswan_data'
                JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid
                WHERE r.rolname = current_user AND c.relname = ANY(%s)
            """,
                (list(tables),),
            ).fetchall()
        if len(rows) != len(tables) or any(
            tuple(row) != (False, False, False, True, True, True) for row in rows
        ):
            raise ProtectionDenied("Invalid runtime database role or policy.")

    @contextmanager
    def transaction(self) -> Iterator[tuple[Any, PlatformContext]]:
        context = require_context()
        with self._pool.connection() as db, db.transaction():
            db.execute(
                "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', %s, true)",
                (str(context.tenant_id), context.product_id),
            )
            yield db, context
