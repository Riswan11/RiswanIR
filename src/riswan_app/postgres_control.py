"""PostgreSQL control transactions shared by authorization and tenancy."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.data_protection import ProtectionDenied
from riswan_platform.identity.models import ProviderUnavailable
from riswan_platform.identity.principal import require_principal
from riswan_platform.secrets import SecretError

from .authorization_repository import AuthorizationRepository


class ControlConnection:
    def __init__(self, db: Any):
        self._db = db

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        return self._db.execute(statement.replace("?", "%s"), parameters)


class PostgresAuthorizationRepository(AuthorizationRepository):
    initializes_sqlite_schema = False

    def __init__(self, pool: Any):
        self._pool = pool
        self._control: ContextVar[ControlConnection | None] = ContextVar(
            "postgres_control_transaction", default=None
        )
        with pool.connection() as db:
            valid = db.execute("""
                SELECT current_user = 'riswan_control_runtime' AND NOT r.rolsuper
                    AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb
                    AND NOT pg_has_role('riswan_runtime', 'MEMBER')
                    AND NOT pg_has_role('riswan_identity_runtime', 'MEMBER')
                    AND NOT pg_has_role(n.nspowner, 'MEMBER')
                FROM pg_catalog.pg_roles r
                JOIN pg_catalog.pg_namespace n ON n.nspname = 'riswan_control'
                WHERE r.rolname = current_user
            """).fetchone()
            if valid != (True,):
                raise ProtectionDenied("Invalid PostgreSQL control runtime role or schema.")

    @contextmanager
    def transaction(self) -> Iterator[None]:
        from psycopg import Error
        from psycopg_pool import PoolClosed, PoolTimeout

        if self._control.get() is not None:
            yield
            return
        principal = require_principal()
        denied = None
        try:
            with self._pool.connection() as db, db.transaction():
                db.execute("SET LOCAL search_path = riswan_control, pg_catalog, pg_temp")
                db.execute("SELECT pg_catalog.pg_advisory_xact_lock(947062)")
                db.execute(
                    """SELECT set_config('riswan.control_actor', %s, true),
                              set_config('riswan.control_tenant', '', true),
                              set_config('riswan.control_org', '', true),
                              set_config('riswan.secret_product', '', true)""",
                    (str(principal.identity.identity_id),),
                )
                token = self._control.set(ControlConnection(db))
                try:
                    yield
                except (AccessDenied, SecretError) as exc:
                    # Atomic business operations have already rolled back to their savepoint.
                    denied = exc
                finally:
                    self._control.reset(token)
        except (Error, PoolClosed, PoolTimeout) as exc:
            raise ProviderUnavailable("Tenant storage unavailable.") from exc
        if denied is not None:
            raise denied

    @contextmanager
    def _connection(self) -> Iterator[ControlConnection]:
        with self.transaction():
            db = self._control.get()
            assert db is not None
            yield db

    def bind_scope(self, tenant: str, organization: str | None = None) -> None:
        db = self._control.get()
        if db is not None:
            db.execute(
                """SELECT set_config('riswan.control_tenant', ?, true),
                          set_config('riswan.control_org', ?, true)""",
                (tenant, organization or ""),
            )

    def bind_secret_product(self, product: str) -> None:
        with self._connection() as db:
            db.execute("SELECT set_config('riswan.secret_product', ?, true)", (product,))
