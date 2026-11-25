# Secret provider abstraction

## Status

Accepted

## Context

Products need a common credential lifecycle and access boundary.

## Decision

Use a small shared value-provider contract with AWS Secrets Manager, encrypted development storage and an in-memory test adapter.

## Alternatives considered

Direct SDK calls in products couple authorization and credential lifecycle to AWS.

## Trade-offs and consequences

Providers must report failures and support retry-safe keys. Provider-specific operations remain in adapters.
