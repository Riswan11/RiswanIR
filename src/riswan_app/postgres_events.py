"""Immutable canonical event snapshots scoped by an investigation revision."""

import json

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from riswan_ir.core.fields import utc_timestamp
from riswan_security_data.canonical_event import SecurityEvent


def append(db, context, case: str, events: list[SecurityEvent]) -> None:
    if not events:
        return
    with db.cursor() as cursor:
        cursor.executemany(
            """INSERT INTO riswan_data.investigation_events
               (tenant_id, product_id, investigation_id, ordinal, event_id, observed_at, event)
               VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)""",
            [
                (
                    context.tenant_id,
                    context.product_id,
                    case,
                    index,
                    event.id,
                    utc_timestamp(event.observed_at),
                    event.model_dump_json(exclude_unset=True),
                )
                for index, event in enumerate(events)
            ],
        )


def read(db, case: str) -> list[SecurityEvent]:
    return [
        SecurityEvent.model_validate_json(json.dumps(row[0]))
        for row in db.execute(
            """SELECT event FROM riswan_data.investigation_events
               WHERE investigation_id = %s ORDER BY ordinal""",
            (case,),
        )
    ]


class TimelineQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    type_uid: int | None = Field(default=None, ge=0)
    principal: str | None = Field(default=None, max_length=512)
    resource: str | None = Field(default=None, max_length=512)
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=100_000)


TIMELINE_SQL = """
SELECT event FROM riswan_data.investigation_events e
WHERE tenant_id = %(tenant)s AND product_id = %(product)s AND investigation_id = %(case)s
  AND (%(start)s::timestamptz IS NULL OR observed_at >= %(start)s::timestamptz)
  AND (%(end)s::timestamptz IS NULL OR observed_at < %(end)s::timestamptz)
  AND (%(type)s::text IS NULL OR event #>> '{classification,type_uid}' = %(type)s::text)
  AND (%(principal)s::text IS NULL OR %(principal)s::text IN (
        event #>> '{actor,user,uid}', event #>> '{actor,user,arn}'
      ))
  AND (%(resource)s::text IS NULL OR EXISTS (
        SELECT 1 FROM jsonb_array_elements(COALESCE(event->'resources', '[]'::jsonb)) AS r
        WHERE %(resource)s::text IN (r->>'uid', r->>'name')
      ))
ORDER BY observed_at, ordinal LIMIT %(limit)s OFFSET %(offset)s
"""


def timeline(db, context, case: str, query: TimelineQuery) -> list[SecurityEvent]:
    if query.start and query.end and query.start >= query.end:
        raise ValueError("Timeline start must precede end.")
    rows = db.execute(
        TIMELINE_SQL,
        {
            "tenant": context.tenant_id,
            "product": context.product_id,
            "case": case,
            "start": query.start,
            "end": query.end,
            "type": query.type_uid,
            "principal": query.principal,
            "resource": query.resource,
            "limit": query.limit + 1,
            "offset": query.offset,
        },
    )
    return [SecurityEvent.model_validate_json(json.dumps(row[0])) for row in rows]
