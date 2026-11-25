"""Compose the investigation report from the domain modules."""

from ..detection.rules import assess
from ..knowledge_graph.edges import build_graph
from ..models import InvestigationRequest, InvestigationResult
from ..response.advisory import recommend
from .correlation import correlate


def analyze(request: InvestigationRequest) -> InvestigationResult:
    evidence = correlate(request.records, request.principal)
    return InvestigationResult(
        title=request.title,
        principal=request.principal,
        plan=["Match the supplied events to the principal", "Follow credentials issued by matching events"],
        evidence=evidence,
        graph=build_graph(evidence),
        assessment=assess(evidence),
        action=recommend(evidence),
    )
