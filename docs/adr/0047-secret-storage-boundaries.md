# Secret storage boundaries

## Status

Accepted

## Context

Products need a common credential lifecycle and access boundary.

## Decision

Keep values outside control metadata. Resolve tenant and product scope before provider access. Audit using metadata-only events.

## Alternatives considered

An application database with recoverable values would tie backups and control-plane access to credential exposure.

## Trade-offs and consequences

Activation pointers are transactional. Provider operations are reconciled by deterministic keys rather than distributed commits.
