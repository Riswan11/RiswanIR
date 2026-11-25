"""Expose canonical JSON for persisted cases without rewriting historical evidence."""

from ..models import InvestigationReport
from ..normalization.aws.ocsf_mapper import REGISTRY, map_event
from .export import ocsf_payload
from .registry import OCSF_VERSION


def export_events(report: InvestigationReport) -> dict[str, object]:
    events = report.canonical_events
    representation = "stored"
    if events is None:
        representation = "legacy_projection"
        events = [
            map_event(item, evidence=item.reference, parent=item.linked_from_evidence_id)
            for item in report.evidence
        ]
    for event in events:
        checked = REGISTRY.validate(event)
        if not checked.valid:
            raise ValueError("Unsupported canonical archive: " + ", ".join(checked.issues))
    versions = {event.metadata.schema_version for event in events}
    if len(versions) > 1:
        raise ValueError("A canonical export must use one OCSF schema version.")
    return {
        "schema_version": next(iter(versions), OCSF_VERSION),
        "representation": representation,
        "events": [ocsf_payload(event) for event in events],
    }
