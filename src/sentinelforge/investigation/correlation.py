"""Trace successful calls and downstream credential use."""

from ..core.fields import mapping, text_field, utc_timestamp
from ..evidence.integrity import seal_evidence
from ..models import CloudTrailRecord, Evidence
from ..normalization.cloudtrail import issued_credential, normalize


def correlate(records: list[CloudTrailRecord], principal: str) -> list[Evidence]:
    unique = {}
    for record in records:
        item = normalize(record)
        identity = mapping(record, "userIdentity")
        row = (item, text_field(identity, "accessKeyId"), issued_credential(record, item), bool(record.get("errorCode")))
        if unique.setdefault(item.id, row) != row:
            raise ValueError("Conflicting CloudTrail records share an eventID.")
    ordered = sorted(unique.values(), key=lambda row: (row[0].observed_at, row[0].id))
    evidence = []
    issued = {}
    for item, key, credential, failed in ordered:
        if failed:
            continue
        parent = None
        timestamp = utc_timestamp(item.observed_at)
        for origin, expected_arn, expires_at in issued.get(key, ()):
            if origin.observed_at >= item.observed_at:
                continue
            if expected_arn and item.principal and expected_arn != item.principal:
                continue
            if expires_at and timestamp >= expires_at:
                continue
            parent = origin
            break
        if item.principal != principal and parent is None:
            continue
        linked = seal_evidence(item, parent.id if parent else None)
        evidence.append(linked)
        issued_key, session_arn, expires_at = credential
        if issued_key:
            issued.setdefault(issued_key, []).append((linked, session_arn, expires_at))
    return evidence
