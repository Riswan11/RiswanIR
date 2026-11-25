# 0027. Centralize identity behind a platform boundary

## Status

Accepted for Phase 4.3.

## Context

Identity is shared across products.

## Decision

Use a standalone OIDC identity runtime and publish verified actors without tenant access.

## Alternatives considered

Product-local logins would duplicate authentication and blur the authorization boundary.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit when tenant and product authorization can consume verified actors.
