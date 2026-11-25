# Tenant-Aware Policy Enforcement

## Status

Accepted

## Context

Verified identity alone does not establish tenant authority.

## Decision

Require an active actor/tenant snapshot and matching resource tenant and product.

## Alternatives considered

Infer membership from token roles or headers.

## Rationale

Membership is an independently trusted input.

## Trade-offs and consequences

Task 4.5 must supply trusted live membership.
