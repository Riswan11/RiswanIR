"""Hash the canonical JSON representation of an evidence item."""

from riswan_security_data.integrity import canonical_json as canonical_json
from riswan_security_data.integrity import sha256 as sha256
from riswan_security_data.provenance import EvidenceReference

from ..models import Evidence, NormalizedEvent


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
