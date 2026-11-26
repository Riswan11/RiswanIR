"""Immutable canonical event snapshots scoped by an investigation revision."""

import json

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
