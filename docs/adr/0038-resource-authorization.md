# Resource-Level Authorization

## Status

Accepted

## Context

Case read privileges can expose unrelated investigations.

## Decision

Resolve scope from a trusted directory and constrain listing SQL to permitted IDs.

## Alternatives considered

Client-supplied resource attributes or filtering unrestricted reports.

## Rationale

Queries need an authorized scope before accessing payloads.

## Trade-offs and consequences

Production resource metadata and aggregate projections still need integration.
