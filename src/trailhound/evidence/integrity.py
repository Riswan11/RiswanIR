"""Hash the canonical JSON representation of an evidence item."""

import hashlib
import json

from ..models import Evidence, NormalizedEvent
from ..models.provenance import EvidenceReference


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def attach_reference(evidence: Evidence, reference: EvidenceReference) -> Evidence:
    fields = evidence.payload()
    fields.pop("integrity_hash")
    fields["reference"] = reference.payload()
    return Evidence.model_validate({**fields, "integrity_hash": sha256(canonical_json(fields))})


def seal_evidence(
    event: NormalizedEvent, parent_id: str | None, *, session_match: bool = False
) -> Evidence:
    fields = event.payload()
    fields["query"] = (
        "Corroborated STS session match"
        if session_match
        else "Issued access key match"
        if parent_id
        else "Exact principal ARN match"
    )
    fields["linked_from_evidence_id"] = parent_id
    fields["integrity_hash"] = sha256(canonical_json(fields))
    return Evidence.model_validate(fields)
