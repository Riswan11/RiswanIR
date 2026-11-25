# 0024. Publish versioned security finding contracts

## Status

Accepted.

## Context

A future product may send evidence-linked findings to IR.

## Decision

Publish a scoped contract and receiving port. Verify access to evidence at the receiver.

## Alternatives considered

Cross-product table access would couple data and authorization internals.

## Consequences and security implications

The current runtime does not accept external product findings. Tenant and evidence authorization remain mandatory for future receivers. See [platform boundaries](../architecture/platform-boundaries.md).

## Revisit when

A second product and its authorization flow exist.
