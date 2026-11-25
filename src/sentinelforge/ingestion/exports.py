"""Read CloudTrail log and lookup export shapes."""

import json

from ..core.fields import required


def export_records(records):
    if isinstance(records, dict) and "Events" in records:
        entries = records["Events"]
        if not isinstance(entries, list) or len(entries) > 2000:
            raise ValueError("Provide at most 2,000 CloudTrail lookup events.")
        try:
            return [json.loads(required(entry, "CloudTrailEvent", 8_000_000)) for entry in entries]
        except json.JSONDecodeError as exc:
            raise ValueError("Malformed CloudTrailEvent in lookup export.") from exc
    return records.get("Records") if isinstance(records, dict) else records
