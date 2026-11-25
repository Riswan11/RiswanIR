# 0031. Separate provider tokens from platform sessions

## Status

Accepted for Phase 4.3.

## Context

A browser session and a bearer credential have different lifecycles.

## Decision

Validate signatures with PyJWT; use opaque hashed, bounded, revocable sessions and reauthenticate to renew.

## Alternatives considered

Persisting refresh tokens introduces a secret-management dependency.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit once encrypted refresh storage, rotation, and replay handling are available.
