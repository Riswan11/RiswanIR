# 0032. Distinguish human and workload identities

## Status

Accepted for Phase 4.3.

## Context

Headless clients must not inherit browser or administrative rights.

## Decision

Use interactive OIDC for invited humans and registered, scoped access tokens for services and integrations.

## Alternatives considered

Treating every verified subject as equivalent would introduce token substitution risk.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit when trusted agent identities and workload federation are designed.
