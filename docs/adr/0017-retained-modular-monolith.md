# 0017. Retain one deployable modular monolith

## Status

Accepted.

## Context

The operational workload fits a single workstation process and SQLite.

## Decision

Keep one deployable runtime and enforce internal package direction.

## Alternatives considered

Distributed services would add network trust and deployment failure modes.

## Consequences and security implications

Services and tenant isolation remain logical boundaries in the local deployment. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

Independently measured scaling or isolation requirements justify extracting a service.
