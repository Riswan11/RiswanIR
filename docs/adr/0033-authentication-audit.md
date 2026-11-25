# 0033. Audit authentication without storing credentials

## Status

Accepted for Phase 4.3.

## Context

Authentication events must support incident review without creating a credential archive.

## Decision

Store structured outcomes and verified actor references; suppress callback request logging.

## Alternatives considered

Raw provider logging would expose secrets and account data.

## Consequences and security implications

See the [identity architecture and trust boundaries](../architecture/authentication.md).

## Revisit when

Revisit with the platform audit retention and operating model.
