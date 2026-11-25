# 0013. Store versioned investigation graph snapshots in SQLite

## Status

Accepted.

## Context

The original edge list preserves a compact timeline visualization. Investigation queries need stable node identifiers, typed directional relationships, and reproducible links to evidence.

## Decision

Store one validated, versioned graph snapshot per investigation in SQLite through a repository interface. Build it from canonical observations, identity correlation, and evidence-backed findings. Serve bounded lookups and traversal with a read-only case-scoped API.

## Alternatives considered

Rebuilding every graph on every read keeps the schema smaller but makes current investigation queries dependent on the latest builder. A separate graph database supports larger traversals but introduces a second data store and a distributed transaction concern. SQLite edge tables would support indexed adjacency at higher scale. The current bounded per-case workload favors one atomic snapshot and in-memory traversal.

## Rationale and trade-offs

Snapshots preserve the ontology and observed relationships without introducing infrastructure or a new dependency. They keep transaction boundaries simple. The cost is reading a full case snapshot for a query. Larger cases or cross-case analysis will need an indexed graph repository and an authorization design.

## Consequences

Graph outputs depend on verified provenance shapes and case boundaries. Older cases without a snapshot use read-time projection. Case isolation does not provide authentication. Schema changes must register their ontology version and retain compatibility tests. See [the architecture](../architecture/security-knowledge-graph.md).
