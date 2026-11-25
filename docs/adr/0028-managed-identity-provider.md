# 0028. Prefer a managed OIDC identity provider

## Status

Accepted for Phase 4.3.

## Context

Provider-hosted credentials reduce the platform's password and MFA exposure.

## Decision

Use Cognito as the provisional provider while supporting a generic JWT profile.

## Alternatives considered

Custom passwords add recovery and credential-stuffing risk. Self-hosted identity increases operational ownership.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit after measuring actual MFA claims, costs, and federation needs for the deployment.
