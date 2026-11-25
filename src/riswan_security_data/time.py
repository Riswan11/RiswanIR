"""UTC timestamp parsing for canonical event contracts."""

from datetime import datetime, timezone


def utc_timestamp(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.utcoffset() is None:
        raise ValueError("CloudTrail eventTime must include a timezone.")
    return timestamp.astimezone(timezone.utc)
