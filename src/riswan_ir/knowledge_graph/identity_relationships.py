"""Project correlation relationships into the existing investigation graph."""

from ..models import GraphEdge, Relationship
from ..models.correlation import CorrelationConfidence, CorrelationResult


def identity_edges(correlation: CorrelationResult) -> list[GraphEdge]:
    strength = list(CorrelationConfidence)
    edges: dict[tuple[str, str, str], GraphEdge] = {}
    for item in correlation.relationships:
        key = (item.source, item.relationship, item.target)
        edge = edges.get(key)
        if edge is None:
            edges[key] = GraphEdge(
                source=item.source,
                target=item.target,
                relationship=Relationship(item.relationship),
                evidence_ids=list(item.evidence_ids),
                confidence=item.confidence,
            )
        else:
            edge.evidence_ids = list(dict.fromkeys([*edge.evidence_ids, *item.evidence_ids]))
            if edge.confidence and strength.index(item.confidence) > strength.index(
                edge.confidence
            ):
                edge.confidence = item.confidence
    return [
        *edges.values(),
        *(
            GraphEdge(
                source=f"correlation:{chain.root_event_id}",
                target=event_id,
                relationship=Relationship.SUPPORTED_BY,
                evidence_ids=[event_id],
            )
            for chain in correlation.chains
            for event_id in chain.event_ids
        ),
    ]
