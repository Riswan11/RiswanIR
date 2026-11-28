"""Bounded reads of existing tenant administration audit events."""

from uuid import UUID

from riswan_platform.authorization.enforcement import AccessDenied

from .tenancy import Tenancy


def tenant_timeline(
    tenancy: Tenancy,
    principal,
    organization: UUID,
    request_id: str,
    *,
    before: UUID | None,
    limit: int,
    request_filter: str | None,
):
    from riswan_platform.authorization import Permission

    repo = tenancy.authorization
    if repo.initializes_sqlite_schema:
        raise AccessDenied
    with repo.transaction():
        org, _ = tenancy._admin(
            principal, organization, request_id, permission=Permission.AUDIT_READ
        )
        tenant = str(org.tenant_id)
        with repo._connection() as db:
            db.execute("SELECT set_config('riswan.audit_read_tenant', ?, true)", (tenant,))
            cursor = None
            if before is not None:
                cursor = db.execute(
                    """SELECT occurred_at, id FROM organization_audit_events
                    WHERE tenant_id = ? AND id = ?
                    AND (?::text IS NULL OR request_id = ?)""",
                    (tenant, str(before), request_filter, request_filter),
                ).fetchone()
                if cursor is None:
                    raise AccessDenied
            rows = db.execute(
                """SELECT id, actor_id, event, target, occurred_at, request_id
                FROM organization_audit_events WHERE tenant_id = ?
                AND (?::text IS NULL OR request_id = ?)
                AND (?::text IS NULL OR (occurred_at, id) < (?, ?))
                ORDER BY occurred_at DESC, id DESC LIMIT ?""",
                (
                    tenant,
                    request_filter,
                    request_filter,
                    cursor[0] if cursor else None,
                    *(cursor or (None, None)),
                    limit + 1,
                ),
            ).fetchall()
    fields = ("id", "actor_id", "event", "target", "occurred_at", "request_id")
    return {
        "events": [dict(zip(fields, row, strict=True)) for row in rows[:limit]],
        "next_before": rows[limit - 1][0] if len(rows) > limit else None,
    }
