"""Hash the canonical JSON representation of an evidence item."""

import hashlib
import json

from ..models import Evidence, NormalizedEvent


def seal_evidence(event: NormalizedEvent, parent_id: str | None) -> Evidence:
    fields = event.payload()
    fields["query"] = "Issued access key match" if parent_id else "Exact principal ARN match"
    fields["linked_from_evidence_id"] = parent_id
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    fields["integrity_hash"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return Evidence.model_validate(fields)
