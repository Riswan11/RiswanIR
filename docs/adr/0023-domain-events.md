# 0023. Introduce bounded in-process notifications

## Status

Accepted.

## Context

Some modules need event references without directly altering each other’s state.

## Decision

Use validated versioned event references with scoped dispatch and bounded deduplication after commits.

## Alternatives considered

A distributed broker or best-effort replacement for evidence commits would add risk.

## Consequences and security implications

Notifications are process-local and non-durable. Evidence and audit transactions remain authoritative. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

A consumer requires durable retry or reliable asynchronous processing.
