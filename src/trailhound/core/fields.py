"""Shared field validation and UTC time handling."""

from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def required(data, key, limit=300):
    value = data.get(key) if isinstance(data, dict) else None
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"Provide {key} as text of at most {limit} characters.")
    return value.strip()


def mapping(data, key):
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def text_field(data, name, limit=300):
    value = data.get(name)
    return value[:limit] if isinstance(value, str) and value else None


def utc_timestamp(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.utcoffset() is None:
        raise ValueError("CloudTrail eventTime must include a timezone.")
    return timestamp.astimezone(timezone.utc)
