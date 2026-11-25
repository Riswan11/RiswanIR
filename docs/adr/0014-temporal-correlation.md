# 0014. Correlate event-time sequences within case revisions

## Status

Accepted.

## Context

Single-event detections can miss relationships across related activities. An investigation needs a reproducible way to link stages through evidence and distinguish inference from simple timestamp adjacency.

## Decision

Match versioned declarative sequences over canonical events, detection findings, and bounded graph proofs. Persist case-scoped partial matches, incidents, and configuration in SQLite. Recompute after an evidence revision and during verified historical replay.

## Alternatives considered

A streaming state store could handle larger workloads and out-of-order events continuously, but would introduce new infrastructure and recovery semantics. Timestamp-only joins would be cheaper and would conflate unrelated activity. Case revisions already provide a transactional path to preserve old evidence and ingest late observations.

## Rationale and trade-offs

Bounded scans are reproducible and keep state local to a case. The result depends on observed evidence and operator-maintained inventory. Hard resource limits can narrow coverage in noisy cases and are reported in execution metrics.

## Consequences

Cross-account paths require an explicitly allowed direction and evidence of issued credential use. Incident IDs are stable within a lineage for an unchanged starting match. Advisory results preserve enough information for analyst review. See [architecture and API](../detection/temporal-correlation.md).
