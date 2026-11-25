# Tenant-bound cloud provider instances

## Status

Accepted

## Context

Secrets, managed keys, and temporary sessions have different capabilities and external ownership hierarchies. A Riswan tenant is an application boundary independent of any cloud account.

## Decision

Use immutable provider instance UUIDs. Bind each instance to a Riswan tenant, product, cloud family, external namespace, and supported operations in trusted server configuration. Bind managed operation requests to typed external references. Resolve an instance only after the application verifies tenant membership and action authorization. Provider instances must match the complete configured external namespace. Cloud SDK credentials and clients belong in adapters.

## Alternatives considered

A global provider selected by the caller would bypass ownership boundaries. Using an external account as the tenant identifier prevents valid many-to-one customer configurations.

## Trade-offs and consequences

Existing AWS secrets must retain their current provider names and deterministic storage paths until explicitly mapped to an instance. A registry entry is not permission to operate on any cloud resource. Adapters still enforce the exact target resource and their native authentication and lifetime constraints. Configuration and data-plane migration need deployment-specific verification.
