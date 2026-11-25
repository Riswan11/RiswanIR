"""Project evidence into actor, target, and credential-use edges."""




from ..models import Evidence, GraphEdge, Relationship


def build_graph(evidence: list[Evidence]) -> list[GraphEdge]:
    return (
        [GraphEdge(source=item.principal, relationship=Relationship.CALLED, target=item.id)
         for item in evidence if item.principal]
        + [GraphEdge(source=item.id, relationship=Relationship.TARGETED, target=item.target)
           for item in evidence if item.target]
        + [GraphEdge(source=item.linked_from_evidence_id,
                     relationship=Relationship.ISSUED_CREDENTIAL_USED_IN, target=item.id)
           for item in evidence if item.linked_from_evidence_id]
    )
