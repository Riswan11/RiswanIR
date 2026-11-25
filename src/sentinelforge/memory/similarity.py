"""Rank prior reviewed investigations by shared event types."""

from collections.abc import Iterable

from ..models import Disposition, InvestigationReport, SimilarInvestigation


def similar_investigations(
    report: InvestigationReport, history: Iterable[tuple[InvestigationReport, Disposition]]
) -> list[SimilarInvestigation]:
    events = {item.event for item in report.evidence}
    similar = []
    for prior, disposition in history:
        shared = sorted(events.intersection(event.event for event in prior.evidence))
        if shared:
            similar.append(SimilarInvestigation(id=prior.id, title=prior.title,
                                                disposition=disposition, shared_events=shared))
    return sorted(
        similar, key=lambda item: len(item.shared_events), reverse=True)[:5]
