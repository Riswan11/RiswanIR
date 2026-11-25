"""Trace calls and use only successful issuance to expand the chain."""

from datetime import datetime

from ..core.fields import utc_timestamp
from ..evidence.integrity import seal_evidence
from ..models import CloudTrailRecord, Evidence
from ..models.security_event import Outcome
from ..normalization.aws.cloudtrail import normalize_batch


def correlate(records: list[CloudTrailRecord], principal: str) -> list[Evidence]:
    batch = normalize_batch(records)
    if batch.issues:
        details = "; ".join(
            f"record {issue.index + 1}, {issue.field}: {issue.code}" for issue in batch.issues[:10]
        )
        label = (
            "Conflicting CloudTrail records share an eventID"
            if any(issue.code == "conflicting_duplicate" for issue in batch.issues)
            else "Invalid CloudTrail records"
        )
        raise ValueError(f"{label} ({len(batch.issues)} issues). {details}")
    evidence = []
    issued: dict[str | None, list[tuple[Evidence, str | None, datetime | None]]] = {}
    for entry in batch.records:
        item = entry.event
        parent = None
        timestamp = utc_timestamp(item.observed_at)
        for origin, expected_arn, expires_at in issued.get(entry.access_key_id, []):
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
        issued_key, session_arn, expires_at = entry.credential
        if issued_key and item.outcome == Outcome.SUCCESS:
            issued.setdefault(issued_key, []).append((linked, session_arn, expires_at))
    return evidence
