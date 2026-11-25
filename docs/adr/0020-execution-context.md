# 0020. Bind trusted execution context

## Status

Accepted.

## Context

Tenant and actor headers are requester-controlled.

## Decision

Bind context from trusted infrastructure. Explicitly opt in to one local development scope.

## Alternatives considered

A global default or inferred HTTP headers would weaken isolation.

## Consequences and security implications

Requests and jobs fail closed when context is absent or rejected by the composed scope. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

The identity and tenancy adapters can supply verified scope.
