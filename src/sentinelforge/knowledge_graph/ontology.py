"""Versioned, provider-independent graph vocabulary."""

from enum import StrEnum


class Entity(StrEnum):
    IDENTITY = "identity"
    SESSION = "session"
    RESOURCE = "resource"
    ACCOUNT = "account"
    NETWORK = "network"
    EVENT = "event"
    PERMISSION = "permission"
    FINDING = "finding"
    THREAT = "threat"
    EVIDENCE = "evidence"
    INVESTIGATION = "investigation"
    ACTION = "action"


class Relation(StrEnum):
    ASSUMED_ROLE = "ASSUMED_ROLE"
    ESTABLISHED_SESSION = "ESTABLISHED_SESSION"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    CHAINED_TO = "CHAINED_TO"
    PERFORMED_ACTION = "PERFORMED_ACTION"
    ACCESSED_RESOURCE = "ACCESSED_RESOURCE"
    TARGETED = "TARGETED"
    HAS_PERMISSION = "HAS_PERMISSION"
    ORIGINATED_FROM = "ORIGINATED_FROM"
    VIA_NETWORK = "VIA_NETWORK"
    BELONGS_TO = "BELONGS_TO"
    MODIFIED = "MODIFIED"
    SUPPORTED_BY = "SUPPORTED_BY"
    INDICATES_TECHNIQUE = "INDICATES_TECHNIQUE"
    PART_OF = "PART_OF"
    DERIVED_FROM = "DERIVED_FROM"


VERSION = "1.0.0"
RELATIONS: dict[Relation, frozenset[tuple[Entity, Entity]]] = {
    Relation.ASSUMED_ROLE: frozenset({(Entity.IDENTITY, Entity.IDENTITY)}),
    Relation.ESTABLISHED_SESSION: frozenset({(Entity.IDENTITY, Entity.SESSION)}),
    Relation.AUTHENTICATED_AS: frozenset({(Entity.SESSION, Entity.IDENTITY)}),
    Relation.CHAINED_TO: frozenset({(Entity.SESSION, Entity.SESSION)}),
    Relation.PERFORMED_ACTION: frozenset(
        {(Entity.IDENTITY, Entity.EVENT), (Entity.SESSION, Entity.EVENT)}
    ),
    Relation.ACCESSED_RESOURCE: frozenset(
        {(Entity.IDENTITY, Entity.RESOURCE), (Entity.SESSION, Entity.RESOURCE)}
    ),
    Relation.TARGETED: frozenset({(Entity.EVENT, Entity.RESOURCE)}),
    Relation.HAS_PERMISSION: frozenset({(Entity.IDENTITY, Entity.PERMISSION)}),
    Relation.ORIGINATED_FROM: frozenset(
        {(Entity.SESSION, Entity.NETWORK), (Entity.EVENT, Entity.NETWORK)}
    ),
    Relation.VIA_NETWORK: frozenset({(Entity.EVENT, Entity.NETWORK)}),
    Relation.BELONGS_TO: frozenset(
        (kind, Entity.ACCOUNT)
        for kind in (
            Entity.IDENTITY,
            Entity.SESSION,
            Entity.RESOURCE,
            Entity.EVENT,
            Entity.PERMISSION,
            Entity.NETWORK,
        )
    ),
    Relation.MODIFIED: frozenset({(Entity.EVENT, Entity.RESOURCE)}),
    Relation.SUPPORTED_BY: frozenset(
        (kind, Entity.EVIDENCE) for kind in (Entity.FINDING, Entity.EVENT, Entity.ACTION)
    ),
    Relation.INDICATES_TECHNIQUE: frozenset({(Entity.FINDING, Entity.THREAT)}),
    Relation.PART_OF: frozenset(
        (kind, Entity.INVESTIGATION) for kind in (Entity.FINDING, Entity.EVENT, Entity.ACTION)
    ),
    Relation.DERIVED_FROM: frozenset({(Entity.EVIDENCE, Entity.EVIDENCE)}),
}

# Consumers select the registry by the persisted ontology version.
REGISTRY = {VERSION: RELATIONS}
