"""PostgreSQL authentication storage under its dedicated platform role."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from riswan_platform.data_protection import ProtectionDenied
from riswan_platform.identity.models import ProviderUnavailable

from .identity_repository import IdentityConnection, IdentityRepository


class _IdentityQueries:
    def __init__(self, cursor: Any):
        self._cursor = cursor

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        # Only the repository's static SQL enters this adapter. Values stay bound.
        return self._cursor.execute(statement.replace("?", "%s"), parameters)


class PostgresIdentityRepository(IdentityRepository):
    def __init__(self, pool: Any):
        self._pool = pool
        with pool.connection() as db:
            row = db.execute("""
                SELECT current_user = 'riswan_identity_runtime', NOT r.rolsuper,
                       NOT r.rolbypassrls, NOT r.rolcreaterole, NOT r.rolcreatedb,
                       NOT pg_has_role('riswan_runtime', 'MEMBER'),
                       NOT pg_has_role(n.nspowner, 'MEMBER')
                FROM pg_catalog.pg_roles r
                JOIN pg_catalog.pg_namespace n ON n.nspname = 'riswan_auth'
                WHERE r.rolname = current_user
            """).fetchone()
            if row != (True,) * 7:
                raise ProtectionDenied("Invalid PostgreSQL identity runtime role or schema.")

    @contextmanager
    def _connect(self) -> Iterator[IdentityConnection]:
        from psycopg import Error
        from psycopg.rows import dict_row
        from psycopg_pool import PoolClosed, PoolTimeout

        try:
            with self._pool.connection() as db, db.transaction():
                db.execute("SET LOCAL search_path = riswan_auth, pg_catalog, pg_temp")
                with db.cursor(row_factory=dict_row) as cursor:
                    yield _IdentityQueries(cursor)
        except (Error, PoolClosed, PoolTimeout) as exc:
            raise ProviderUnavailable("Identity storage unavailable.") from exc

    def _begin_write(self, db: IdentityConnection) -> None:
        # Preserve the SQLite writer ordering for identity resolution, revocation and audit.
        db.execute("SELECT pg_catalog.pg_advisory_xact_lock(947061)")
