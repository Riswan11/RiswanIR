"""Project evidence into actor, target, and credential-use edges."""

from riswan_security_data.canonical_event import SecurityEvent

from ..models import GraphEdge, Relationship


def build_graph(events: list[SecurityEvent]) -> list[GraphEdge]:
    return (
        [
            GraphEdge(source=item.actor.user.arn, relationship=Relationship.CALLED, target=item.id)
            for item in events
            if item.actor and item.actor.user and item.actor.user.arn
        ]
        + [
            GraphEdge(source=item.id, relationship=Relationship.TARGETED, target=target)
            for item in events
            for target in dict.fromkeys(
                [item.activity.target, *(resource.uid for resource in item.resources)]
            )
            if target
        ]
        + [
            GraphEdge(
                source=item.linked_from_evidence_id,
                relationship=Relationship.ISSUED_CREDENTIAL_USED_IN,
                target=item.id,
            )
            for item in events
            if item.linked_from_evidence_id
        ]
    )
