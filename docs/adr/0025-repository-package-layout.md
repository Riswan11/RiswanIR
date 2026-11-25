# 0025. Organize platform, data, IR and composition in one repository

## Status

Accepted.

## Context

The existing repository has mature CI and product history.

## Decision

Extract reusable model and integrity contracts to dedicated packages while retaining old imports and launchers.

## Alternatives considered

A repository split would add release coordination without an independent deployment need.

## Consequences and security implications

Ownership is independent of the repository host account. Stored identifiers retain their encoding. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

Packages require independently versioned release or access policies.
