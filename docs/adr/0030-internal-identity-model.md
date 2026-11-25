# 0030. Use stable internal identity IDs

## Status

Accepted for Phase 4.3.

## Context

Email can change and cannot identify an immutable principal.

## Decision

Map trusted issuer and subject to an internal UUID with status history.

## Alternatives considered

Email-based keys could fuse distinct accounts.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit on provider migration or a formally authorized account-linking workflow.
