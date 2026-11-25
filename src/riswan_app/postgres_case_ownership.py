"""PostgreSQL ownership queries used by the investigation resource directory contract."""

from datetime import datetime
from typing import Any
from uuid import UUID

from riswan_platform.core.context import require_context
from riswan_platform.core.exceptions import ContextRequiredError

from .postgres_scope import ScopedPostgres


class PostgresCaseOwnership:
    def __init__(self, pool: Any):
        self._scope = ScopedPostgres(pool, ("investigation_ownership",))

    def register(self, case_id: str, created_at: datetime) -> None:
        """Insert ownership under the trusted transaction scope."""
        with self._scope.transaction() as (db, context):
            db.execute(
                """INSERT INTO riswan_data.investigation_ownership
                   (tenant_id, product_id, investigation_id, creator_id, created_at)
                   VALUES (%s, %s, %s, %s, %s)""",
                (
                    context.tenant_id,
                    context.product_id,
                    case_id,
                    UUID(context.actor_id),
                    created_at,
                ),
            )

    def owned_investigations(self, tenant_id: UUID) -> dict[str, UUID]:
        if require_context().tenant_id != tenant_id:
            raise ContextRequiredError("Invalid hosted tenant scope.")
        with self._scope.transaction() as (db, _):
            rows = db.execute(
                """SELECT investigation_id, creator_id
                   FROM riswan_data.investigation_ownership
                   ORDER BY created_at DESC, investigation_id DESC"""
            )
            return dict(rows)
