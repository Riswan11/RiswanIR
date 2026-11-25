"""Typed graph entities, evidence observations, and validated snapshots."""

from typing import Annotated, Self

from pydantic import Field, JsonValue, StringConstraints, model_validator

from riswan_security_data.canonical_event import CanonicalModel

from ..models.base import Timestamp
from ..models.correlation import CorrelationConfidence
from .ontology import REGISTRY, Entity, Relation

GraphId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Name = Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class GraphNode(CanonicalModel):
    id: GraphId
    kind: Entity
    key: Name
    label: Name
    provider: Name | None = None
    partition: Name | None = None
    account: Name | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class Observation(CanonicalModel):
    event_id: Name
    evidence_id: Name | None = None
    observed_at: Timestamp
    source: Name
    confidence: CorrelationConfidence | None = None


class SecurityRelationship(CanonicalModel):
    id: GraphId
    source: GraphId
    target: GraphId
    relation: Relation
    observations: Annotated[list[Observation], Field(min_length=1)]


class SecurityGraph(CanonicalModel):
    investigation_id: Name
    ontology_version: Name
    nodes: list[GraphNode]
    relationships: list[SecurityRelationship]

    @model_validator(mode="after")
    def validate_ontology(self) -> Self:
        ontology = REGISTRY.get(self.ontology_version)
        if ontology is None:
            raise ValueError("Unsupported security ontology version.")
        nodes = {node.id: node for node in self.nodes}
        if len(nodes) != len(self.nodes) or len({edge.id for edge in self.relationships}) != len(
            self.relationships
        ):
            raise ValueError("Duplicate graph identifiers.")
        evidence = {
            (node.key, node.metadata.get("event_id"))
            for node in self.nodes
            if node.kind == Entity.EVIDENCE
            and node.metadata.get("representation") == "normalized"
            and isinstance(node.metadata.get("event_id"), str)
        }
        events = {node.key: node for node in self.nodes if node.kind == Entity.EVENT}
        if [node.key for node in self.nodes if node.kind == Entity.INVESTIGATION] != [
            self.investigation_id
        ]:
            raise ValueError("The graph requires one matching investigation root.")
        for edge in self.relationships:
            source, target = nodes.get(edge.source), nodes.get(edge.target)
            if (
                source is None
                or target is None
                or (source.kind, target.kind) not in ontology[edge.relation]
            ):
                raise ValueError("Relationship endpoints violate the security ontology.")
            if any(
                obs.event_id not in events
                or events[obs.event_id].metadata.get("observed_at") != obs.observed_at
                or events[obs.event_id].metadata.get("source") != obs.source
                or (obs.evidence_id or obs.event_id, obs.event_id) not in evidence
                for obs in edge.observations
            ):
                raise ValueError("Relationship references evidence outside the investigation.")
            if edge.relation == Relation.DERIVED_FROM and (
                source.metadata.get("representation"),
                target.metadata.get("representation"),
            ) != ("normalized", "raw"):
                raise ValueError("Evidence derivation requires normalized and raw endpoints.")
        return self
