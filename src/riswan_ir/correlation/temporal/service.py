"""Read-only incident, timeline and archived replay API dispatch."""

import re
from typing import Protocol
from urllib.parse import parse_qs

from ...core.errors import NotFoundError
from ...models.detection import DetectionRuleVersion
from .models import TemporalResult


class IncidentSource(Protocol):
    def temporal_result(self, case_id: str) -> TemporalResult: ...
    def replay_temporal(
        self, case_id: str, versions: dict[str, str] | None = None
    ) -> TemporalResult: ...


def serve(store: IncidentSource, case_id: str, suffix: str, query_string: str) -> dict[str, object]:
    if len(query_string) > 2048:
        raise ValueError("Correlation query string is too large.")
    query = parse_qs(query_string, keep_blank_values=True, max_num_fields=16, strict_parsing=True)
    if suffix == "/temporal-correlation/replay":
        if set(query) - {"version"}:
            raise ValueError("Unknown replay query parameter.")
        versions = {}
        for item in query.get("version", []):
            key, _, version = item.partition("=")
            selection = DetectionRuleVersion(id=key, version=version)
            if selection.id in versions:
                raise ValueError("Specify one version per correlation rule.")
            versions[selection.id] = selection.version
        return store.replay_temporal(case_id, versions or None).payload()
    if query:
        raise ValueError("Unexpected correlation query parameter.")
    result = store.temporal_result(case_id)
    if suffix == "/temporal-correlation":
        return {
            "investigation_id": result.investigation_id,
            "lineage_id": result.lineage_id,
            "engine_version": result.engine_version,
            "rules": [rule.payload() for rule in result.rules],
            "configuration_digest": result.configuration_digest,
            "partial_matches": [item.payload() for item in result.partial_matches],
            "metrics": result.metrics.payload(),
        }
    if suffix == "/incidents":
        return {"incidents": [incident.payload() for incident in result.incidents]}
    item_match = re.fullmatch(r"/incidents/([a-f0-9]{64})(/timeline)?", suffix)
    if item_match:
        incident_id, timeline = item_match.groups()
        for incident in result.incidents:
            if incident.incident_id == incident_id:
                if timeline:
                    return {
                        "incident_id": incident_id,
                        "timeline": [item.payload() for item in incident.timeline],
                    }
                return incident.payload()
    raise NotFoundError("Incident not found.")
