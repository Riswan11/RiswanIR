"""Bridge CloudTrail normalization and the provider-independent engine."""

from ..correlation.aws import AWSIdentityResolver
from ..correlation.engine import describe, select
from ..evidence.integrity import seal_evidence
from ..models import CloudTrailRecord, Evidence
from ..models.correlation import CorrelationConfidence, CorrelationResult
from ..normalization.aws.cloudtrail import normalize_batch


def correlate_with_context(
    records: list[CloudTrailRecord], principal: str
) -> tuple[list[Evidence], CorrelationResult]:
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
    raw = {str(record["eventID"]).strip(): record for record in records}
    resolver = AWSIdentityResolver()
    observations = [resolver.adapt(item, raw[item.event.id]) for item in batch.records]
    selected, links, unresolved = select(observations, principal)
    evidence = []
    for item in selected:
        link = links.get(item.event.id)
        evidence.append(
            seal_evidence(
                item.event,
                link[0] if link else None,
                session_match=bool(link and link[1] == CorrelationConfidence.HIGH),
            )
        )
    return evidence, describe(selected, evidence, links, unresolved)


def correlate(records: list[CloudTrailRecord], principal: str) -> list[Evidence]:
    return correlate_with_context(records, principal)[0]
