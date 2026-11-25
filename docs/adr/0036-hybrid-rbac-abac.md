# Hybrid RBAC and ABAC Model

## Status

Accepted

## Context

Static roles cannot describe resource or session constraints.

## Decision

Combine named roles, scoped grants and contextual MFA checks.

## Alternatives considered

Role-only authorization or arbitrary expression policies.

## Rationale

Structured constraints keep decisions explainable.

## Trade-offs and consequences

Policy changes require code review and tests.
