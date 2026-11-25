"""Compose the investigation report from the domain modules."""

from ..core.fields import required
from ..detection.rules import assess
from ..ingestion.exports import export_records
from ..knowledge_graph.edges import build_graph
from ..response.advisory import recommend
from .correlation import correlate


def analyze(data):
    title = required(data, "title")
    principal = required(data, "principal")
    records = export_records(data.get("records"))
    if not isinstance(records, list) or len(records) > 2000:
        raise ValueError("Provide a records array with at most 2,000 CloudTrail events.")
    evidence = correlate(records, principal)
    return {
        "title": title, "principal": principal,
        "plan": ["Match the supplied events to the principal", "Follow credentials issued by matching events"],
        "evidence": evidence,
        "graph": build_graph(evidence),
        "assessment": assess(evidence),
        "action": recommend(evidence),
    }
