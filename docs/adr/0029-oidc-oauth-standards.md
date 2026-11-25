# 0029. Use Authorization Code, PKCE, state and nonce

## Status

Accepted for Phase 4.3.

## Context

Browser redirects need interception and replay protection.

## Decision

Require code flow with PKCE S256, browser-bound single-use state, and a validated ID-token nonce.

## Alternatives considered

Implicit flow exposes tokens to the browser redirect path.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit when a second approved client or redirect pattern is introduced.
