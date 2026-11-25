# 0021. Publish a minimal product module contract

## Status

Accepted.

## Context

Composition needs stable metadata independent of storage and product endpoints.

## Decision

Register IR through the product protocol with its actual distribution version and implemented capabilities.

## Alternatives considered

A runtime discovery service or entitlement table would preempt Task 4.11.

## Consequences and security implications

The descriptor reports availability without granting permissions. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

Product activation or entitlement management is implemented.
