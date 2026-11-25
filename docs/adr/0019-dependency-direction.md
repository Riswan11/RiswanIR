# 0019. Enforce dependency direction

## Status

Accepted.

## Context

Unrestricted imports make ownership difficult to verify.

## Decision

Check the package dependency graph, cycles, concrete storage imports and selected SQL boundaries in CI.

## Alternatives considered

Review-only rules would miss incidental dependencies. An additional lint dependency is unnecessary for these checks.

## Consequences and security implications

Domain code cannot introduce a storage implementation or reverse shared dependency. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

New adapter packages or dynamic plugin discovery need an extension to the gate.
