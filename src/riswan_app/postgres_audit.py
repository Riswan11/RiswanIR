"""Bounded reads of existing tenant administration audit events."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qsl
from uuid import UUID

from riswan_platform.authorization.enforcement import AccessDenied

from .tenancy import Tenancy


@dataclass(frozen=True, slots=True)
class TenantAuditQuery:
    before: UUID | None = None
    limit: int = 25
    request_id: str | None = None
    actor_id: UUID | None = None
    operation: str | None = None
    resource: str | None = None
    start: datetime | None = None
    end: datetime | None = None

    @classmethod
    def parse(cls, query: str) -> "TenantAuditQuery":
        if len(query) > 1024:
            raise ValueError("Invalid audit filter.")
        pairs = parse_qsl(query, strict_parsing=True, max_num_fields=8, keep_blank_values=True)
        options = dict(pairs)
        if len(pairs) != len(options) or options.keys() - {
            "before",
            "limit",
            "request_id",
            "actor_id",
            "operation",
            "resource",
            "start",
            "end",
        }:
            raise ValueError("Invalid audit filter.")
        limit = int(options.get("limit", "25"))
        if not 1 <= limit <= 100:
            raise ValueError("Invalid audit limit.")
        for name, pattern in (
            ("request_id", r"[A-Za-z0-9_-]{1,64}"),
            ("operation", r"[a-z][a-z0-9_.]{0,95}"),
            ("resource", r"[A-Za-z0-9_.:-]{1,128}"),
        ):
            if name in options and not re.fullmatch(pattern, options[name]):
                raise ValueError("Invalid audit filter.")
        start = _instant(options["start"]) if "start" in options else None
        end = _instant(options["end"]) if "end" in options else None
        if start is not None and end is not None and start >= end:
            raise ValueError("Invalid audit time range.")
        return cls(
            before=UUID(options["before"]) if "before" in options else None,
            limit=limit,
            request_id=options.get("request_id"),
            actor_id=UUID(options["actor_id"]) if "actor_id" in options else None,
            operation=options.get("operation"),
            resource=options.get("resource"),
            start=start,
            end=end,
        )


def _instant(value: str) -> datetime:
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None:
        raise ValueError("Audit time requires a UTC offset.")
    return instant.astimezone(UTC)


def tenant_timeline(
    tenancy: Tenancy,
    principal,
    organization: UUID,
    request_id: str,
    query: TenantAuditQuery,
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
            filters = (
                query.request_id,
                str(query.actor_id) if query.actor_id else None,
                query.operation,
                query.resource,
                query.start,
                query.end,
            )
            args = (tenant, *(value for item in filters for value in (item, item)))
            cursor = None
            if query.before is not None:
                cursor = db.execute(
                    """SELECT occurred_at, id FROM organization_audit_events
                    WHERE tenant_id = ? AND id = ?
                    AND (?::text IS NULL OR request_id = ?)
                    AND (?::text IS NULL OR actor_id = ?)
                    AND (?::text IS NULL OR event = ?)
                    AND (?::text IS NULL OR target = ?)
                    AND (?::timestamptz IS NULL OR occurred_at::timestamptz >= ?)
                    AND (?::timestamptz IS NULL OR occurred_at::timestamptz < ?)""",
                    (tenant, str(query.before), *args[1:]),
                ).fetchone()
                if cursor is None:
                    raise AccessDenied
            rows = db.execute(
                """SELECT id, actor_id, event, target, occurred_at, request_id
                FROM organization_audit_events WHERE tenant_id = ?
                AND (?::text IS NULL OR request_id = ?)
                AND (?::text IS NULL OR actor_id = ?)
                AND (?::text IS NULL OR event = ?)
                AND (?::text IS NULL OR target = ?)
                AND (?::timestamptz IS NULL OR occurred_at::timestamptz >= ?)
                AND (?::timestamptz IS NULL OR occurred_at::timestamptz < ?)
                AND (?::text IS NULL OR (occurred_at, id) < (?, ?))
                ORDER BY occurred_at DESC, id DESC LIMIT ?""",
                (*args, cursor[0] if cursor else None, *(cursor or (None, None)), query.limit + 1),
            ).fetchall()
    fields = ("id", "actor_id", "event", "target", "occurred_at", "request_id")
    return {
        "events": [dict(zip(fields, row, strict=True)) for row in rows[: query.limit]],
        "next_before": rows[query.limit - 1][0] if len(rows) > query.limit else None,
    }
