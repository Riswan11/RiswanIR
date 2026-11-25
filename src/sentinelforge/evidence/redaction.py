"""Remove credential secrets from new archived telemetry."""

import re

from ..models import CloudTrailRecord

SECRET_FIELDS = {
    "secretaccesskey",
    "awssecretaccesskey",
    "sessiontoken",
    "awssessiontoken",
    "securitytoken",
    "awssecuritytoken",
    "credentialtoken",
    "webidentitytoken",
}


def redact(value: object) -> object:
    if isinstance(value, dict):
        return redact_record(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def redact_record(record: CloudTrailRecord) -> CloudTrailRecord:
    return {
        key: "[redacted]"
        if re.sub(r"[^a-z0-9]", "", key.lower()) in SECRET_FIELDS
        else redact(item)
        for key, item in record.items()
    }
