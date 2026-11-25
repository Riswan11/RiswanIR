# 0018. Separate shared platform from product intelligence

## Status

Accepted.

## Context

Identity and execution scope apply across products, while incident decisions belong to IR.

## Decision

Publish reusable contracts and keep detection, investigation, risk policy, memory and response in IR.

## Alternatives considered

Moving every potentially reusable module would create premature coupling.

## Consequences and security implications

A product cannot rely on another product’s private implementation or policy. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

A second product has a concrete reuse need.
