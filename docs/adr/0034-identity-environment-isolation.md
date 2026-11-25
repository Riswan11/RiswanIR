# 0034. Isolate workstation and OIDC environments

## Status

Accepted for Phase 4.3.

## Context

Development context cannot be trusted in a deployed identity runtime.

## Decision

Require explicit mode; reject local mode outside development or alongside OIDC configuration.

## Alternatives considered

Automatic fallback would undermine failed production authentication.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit when deployment policies enforce modes and identity-provider configuration at infrastructure level.
