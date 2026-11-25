"""Validate CloudTrail event metadata without echoing input values."""

import re

from ...core.fields import required, utc_timestamp
from ...models import CloudTrailRecord
from ...models.security_event import EventCategory
from ..base import InvalidRecord

SERVICE = re.compile(r"(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+(?:amazonaws\.com(?:\.cn)?|api\.aws)")
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}")
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/-]{1,300}")


def required_field(event: CloudTrailRecord, field: str) -> str:
    try:
        return required(event, field)
    except ValueError:
        raise InvalidRecord(field, "required_text") from None


def event_timestamp(event: CloudTrailRecord) -> str:
    value = required_field(event, "eventTime")
    try:
        return utc_timestamp(value).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        raise InvalidRecord("eventTime", "invalid_timestamp") from None


def event_source(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and len(value) <= 253 and SERVICE.fullmatch(value.lower()):
        return value.lower()
    raise InvalidRecord("eventSource", "invalid_aws_service")


def event_category(value: object) -> EventCategory | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidRecord("eventCategory", "unsupported_category")
    try:
        return EventCategory(value)
    except ValueError:
        raise InvalidRecord("eventCategory", "unsupported_category") from None


def event_version(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and VERSION.fullmatch(value):
        return value
    raise InvalidRecord("eventVersion", "invalid_version")


def identifier(value: object) -> str | None:
    return value if isinstance(value, str) and IDENTIFIER.fullmatch(value) else None


def cloud_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return {"true": True, "false": False, "yes": True, "no": False}.get(value.lower())
    return None
