"""Case-local graph lookup and bounded breadth-first traversal."""

from collections import defaultdict
from typing import Literal

from pydantic import Field

from ..core.errors import NotFoundError
from ..models.canonical_event import CanonicalModel
from .models import GraphId, GraphNode, SecurityGraph, SecurityRelationship
from .ontology import Entity, Relation

MAX_PAGE = 200
MAX_DEPTH = 4


class GraphFilter(CanonicalModel):
    account: str | None = Field(default=None, pattern=r"^[0-9]{12}$")
    partition: Literal["aws", "aws-cn", "aws-us-gov"] = "aws"
    kind: Entity | None = None
    relation: Relation | None = None
    source: GraphId | None = None
    target: GraphId | None = None
    limit: int = Field(default=100, ge=1, le=MAX_PAGE)
    offset: int = Field(default=0, ge=0)


class Traversal(CanonicalModel):
    node: GraphId
    account: str | None = Field(default=None, pattern=r"^[0-9]{12}$")
    partition: Literal["aws", "aws-cn", "aws-us-gov"] = "aws"
    depth: int = Field(default=1, ge=1, le=MAX_DEPTH)
    direction: Literal["in", "out", "both"] = "both"
    relations: list[Relation] = Field(default_factory=list, max_length=8)


class GraphQuery:
    def __init__(self, graph: SecurityGraph, account: str | None = None, partition: str = "aws"):
        self.graph = graph
        self.nodes = {
            node.id: node
            for node in graph.nodes
            if account is None or (node.account == account and node.partition == partition)
        }
        event_ids = {node.key for node in self.nodes.values() if node.kind == Entity.EVENT}
        self.edges: dict[str, SecurityRelationship] = {}
        for edge in graph.relationships:
            if edge.source not in self.nodes or edge.target not in self.nodes:
                continue
            observations = [item for item in edge.observations if item.event_id in event_ids]
            if observations:
                self.edges[edge.id] = (
                    edge
                    if len(observations) == len(edge.observations)
                    else edge.model_copy(update={"observations": observations})
                )

    def node(self, key: str) -> GraphNode:
        if key not in self.nodes:
            raise NotFoundError("Graph node not found.")
        return self.nodes[key]

    def relationship(self, key: str) -> SecurityRelationship:
        if key not in self.edges:
            raise NotFoundError("Graph relationship not found.")
        return self.edges[key]

    def provenance(self, key: str) -> dict[str, object]:
        edge = self.relationship(key)
        evidence_keys = {item.evidence_id or item.event_id for item in edge.observations}
        evidence = [
            item.payload()
            for item in self.graph.nodes
            if item.kind == Entity.EVIDENCE
            and (
                item.key in evidence_keys
                or (edge.relation == Relation.DERIVED_FROM and item.id == edge.target)
            )
        ]
        return {"relationship": edge.payload(), "evidence": evidence}

    def page(self, filters: GraphFilter, relationships_only: bool = False) -> dict[str, object]:
        if filters.source:
            self.node(filters.source)
        if filters.target:
            self.node(filters.target)
        nodes = (
            [
                node
                for node in self.nodes.values()
                if filters.kind is None or node.kind == filters.kind
            ]
            if not relationships_only
            else []
        )
        relationships = [
            edge
            for edge in self.edges.values()
            if (filters.relation is None or edge.relation == filters.relation)
            and (filters.source is None or edge.source == filters.source)
            and (filters.target is None or edge.target == filters.target)
            and (
                filters.kind is None
                or filters.kind
                in (
                    self.nodes[edge.source].kind,
                    self.nodes[edge.target].kind,
                )
            )
        ]
        start = filters.offset
        end = start + filters.limit
        return {
            "investigation_id": self.graph.investigation_id,
            "ontology_version": self.graph.ontology_version,
            "nodes": [item.payload() for item in nodes[start:end]],
            "relationships": [item.payload() for item in relationships[start:end]],
            "next_offset": end if end < max(len(nodes), len(relationships)) else None,
        }

    def traverse(self, request: Traversal) -> dict[str, object]:
        root = self.node(request.node)
        outgoing: dict[str, list[SecurityRelationship]] = defaultdict(list)
        incoming: dict[str, list[SecurityRelationship]] = defaultdict(list)
        for edge in self.edges.values():
            if not request.relations or edge.relation in request.relations:
                outgoing[edge.source].append(edge)
                incoming[edge.target].append(edge)
        visited = {root.id: root}
        relationships: dict[str, SecurityRelationship] = {}
        frontier = [root.id]
        truncated = False
        for _ in range(request.depth):
            next_frontier = []
            for node_id in frontier:
                matches = (outgoing.get(node_id, []) if request.direction != "in" else []) + (
                    incoming.get(node_id, []) if request.direction != "out" else []
                )
                for edge in matches:
                    if edge.id in relationships:
                        continue
                    other = edge.target if edge.source == node_id else edge.source
                    if len(relationships) >= MAX_PAGE or (
                        other not in visited and len(visited) >= MAX_PAGE
                    ):
                        truncated = True
                        break
                    relationships[edge.id] = edge
                    if other not in visited:
                        visited[other] = self.nodes[other]
                        next_frontier.append(other)
                if truncated:
                    break
            if truncated or not next_frontier:
                break
            frontier = next_frontier
        return {
            "investigation_id": self.graph.investigation_id,
            "ontology_version": self.graph.ontology_version,
            "nodes": [item.payload() for item in visited.values()],
            "relationships": [item.payload() for item in relationships.values()],
            "truncated": truncated,
        }
