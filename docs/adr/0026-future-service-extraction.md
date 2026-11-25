# 0026. Require a measured reason for service extraction

## Status

Accepted.

## Context

Future workload pressure might require independent deployment.

## Decision

Keep ports, contracts and ownership explicit so extraction can follow measured requirements.

## Alternatives considered

Early service extraction adds auth, durability and observability dependencies.

## Consequences and security implications

Any extraction needs a threat model, failure semantics, tenant authorization and rollout plan. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

Profiling, scale objectives or regulated isolation establish a concrete requirement.
