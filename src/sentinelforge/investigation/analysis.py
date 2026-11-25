"""Compose the investigation report from the domain modules."""

from ..detection.rules import assess
from ..knowledge_graph.edges import build_graph
from ..knowledge_graph.identity_relationships import identity_edges
from ..models import InvestigationRequest, InvestigationResult
from ..models.security_event import Outcome
from ..response.advisory import recommend
from .correlation import correlate_with_context


def analyze(request: InvestigationRequest) -> InvestigationResult:
    evidence, correlation = correlate_with_context(request.records, request.principal)
    successful = [item for item in evidence if item.outcome == Outcome.SUCCESS]
    return InvestigationResult(
        title=request.title,
        principal=request.principal,
        plan=[
            "Match the supplied events to the principal",
            "Follow credentials issued by matching events",
        ],
        evidence=evidence,
        graph=build_graph(evidence) + identity_edges(correlation),
        assessment=assess(successful),
        action=recommend(successful),
        correlation=correlation,
    )
