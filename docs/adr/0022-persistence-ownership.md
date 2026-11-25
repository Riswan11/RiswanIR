# 0022. Keep SQLite with explicit data ownership

## Status

Accepted.

## Context

Existing evidence and assessments require continuity.

## Decision

Use owning repositories and scoped ports, retaining existing tables and JSON. The composition layer opens the concrete store.

## Alternatives considered

Migrating to PostgreSQL now would introduce compatibility and operational work outside this task.

## Consequences and security implications

Application scope controls the local adapter boundary. Tenant-aware storage awaits its own task. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

A tenancy design establishes production data partitioning.
