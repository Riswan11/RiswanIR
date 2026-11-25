"""Index evidence-backed relationships used by temporal matching."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

from ...core.fields import utc_timestamp
from ...knowledge_graph.models import SecurityGraph, SecurityRelationship
from ...knowledge_graph.ontology import Entity, Relation
from ...models.correlation import CorrelationConfidence
from .models import TemporalPolicy

TRUSTED = {CorrelationConfidence.CONFIRMED, CorrelationConfidence.HIGH}


@dataclass(frozen=True)
class Proof:
    edges: tuple[SecurityRelationship, ...]
    chained: bool = False


class GraphLinks:
    def __init__(self, graph: SecurityGraph, policy: TemporalPolicy):
        self.scope = {
            node.id: f"{node.partition}:{node.account}"
            for node in graph.nodes
            if node.partition and node.account
        }
        self.events = {node.key: node.id for node in graph.nodes if node.kind == Entity.EVENT}
        event_keys = {node_id: key for key, node_id in self.events.items()}
        self.session: dict[str, SecurityRelationship] = {}
        self.identity: dict[str, SecurityRelationship] = {}
        self.resources: dict[str, dict[str, SecurityRelationship]] = defaultdict(dict)
        self.chains: dict[str, list[SecurityRelationship]] = defaultdict(list)
        self.allowed = {(entry.source, entry.target) for entry in policy.cross_account}
        sessions = {node.id for node in graph.nodes if node.kind == Entity.SESSION}
        for edge in graph.relationships:
            if (
                edge.relation == Relation.PERFORMED_ACTION
                and edge.source in sessions
                and edge.source in self.scope
            ):
                event = event_keys.get(edge.target)
                if event is not None:
                    self.session[event] = edge
            elif edge.relation == Relation.AUTHENTICATED_AS:
                for observation in edge.observations:
                    if observation.confidence in TRUSTED:
                        self.identity[observation.event_id] = edge
            elif edge.relation == Relation.TARGETED:
                event = event_keys.get(edge.source)
                if event is not None and self.scope.get(edge.target) == self.scope.get(edge.source):
                    self.resources[event][edge.target] = edge
            elif edge.relation == Relation.CHAINED_TO and all(
                item.confidence in TRUSTED for item in edge.observations
            ):
                self.chains[edge.source].append(edge)

        self.earliest_use: dict[str, datetime] = {}
        self.chain_events: dict[str, set[str]] = {}
        for edges in self.chains.values():
            for edge in edges:
                self.chain_events[edge.id] = {item.event_id for item in edge.observations}
                evidence_times = [
                    utc_timestamp(item.observed_at)
                    for item in edge.observations
                    if (usage := self.session.get(item.event_id)) is not None
                    and usage.source == edge.target
                ]
                if evidence_times:
                    self.earliest_use[edge.id] = min(evidence_times)

    def event_scope(self, event: str) -> str | None:
        return self.scope.get(self.events.get(event, ""))

    def groups(self, event: str, by: str) -> list[str]:
        if not self.event_scope(event):
            return []
        if by == "resource":
            return sorted(self.resources[event])[:8]
        edge = self.identity.get(event) if by == "identity" else self.session.get(event)
        if not edge:
            return []
        return [edge.target if by == "identity" else edge.source]

    def connect(
        self,
        previous: str,
        event: str,
        instant: datetime,
        group: str,
        value: str,
        *,
        cross_account: bool,
        requires_chain: bool,
    ) -> Proof | None:
        old, new = self.event_scope(previous), self.event_scope(event)
        if (
            old is None
            or new is None
            or (old != new and (not cross_account or (old, new) not in self.allowed))
        ):
            return None
        if group == "resource":
            left = self.resources[previous].get(value)
            right = self.resources[event].get(value)
            source_call, target_call = self.session.get(previous), self.session.get(event)
            if (
                left
                and right
                and source_call
                and target_call
                and source_call.source == target_call.source
                and self.scope.get(source_call.source) == old
            ):
                return Proof((left, right, source_call, target_call))
            return None
        if group == "identity":
            origin, current = self.identity.get(previous), self.identity.get(event)
            if (
                origin
                and current
                and origin.target == current.target == value
                and self.scope.get(value) == old
            ):
                return Proof((origin, current))
            return None
        left_session, right_session = self.session.get(previous), self.session.get(event)
        if left_session is None or right_session is None:
            return None
        if not cross_account and (
            self.scope.get(left_session.source) != old
            or self.scope.get(right_session.source) != new
        ):
            return None
        if left_session.source == right_session.source and old == new and not requires_chain:
            return Proof((left_session, right_session))
        if group != "lineage" or left_session.source == right_session.source:
            return None
        path = self.chain(
            left_session.source, right_session.source, instant, cross_account, previous
        )
        return Proof((left_session, *path, right_session), chained=True) if path else None

    def chain(
        self,
        origin: str,
        target: str,
        cutoff: datetime,
        cross_account: bool,
        previous_event: str,
    ) -> tuple[SecurityRelationship, ...]:
        # Directed traversal over recorded credential-use edges, never over target/resource edges.
        pending: deque[tuple[str, tuple[SecurityRelationship, ...]]] = deque([(origin, ())])
        visited = {origin}
        examined = 0
        while pending:
            node, path = pending.popleft()
            if len(path) == 3:
                continue
            for edge in self.chains[node]:
                examined += 1
                if examined > 64:
                    return ()
                use = self.earliest_use.get(edge.id)
                if edge.target in visited or use is None or use > cutoff:
                    continue
                if not path and previous_event not in self.chain_events[edge.id]:
                    # A different activity by the same session cannot establish its issuance edge.
                    continue
                start, end = self.scope.get(node), self.scope.get(edge.target)
                if (
                    not start
                    or not end
                    or (start != end and (not cross_account or (start, end) not in self.allowed))
                ):
                    continue
                trail = (*path, edge)
                if edge.target == target:
                    return trail
                visited.add(edge.target)
                pending.append((edge.target, trail))
        return ()
