# Temporary credentials

## Status

Accepted

## Context

Products need a common credential lifecycle and access boundary.

## Decision

Broker registered integrations through short-lived read-only STS sessions using server-owned connector configuration.

## Alternatives considered

Permanent keys and caller-selected role ARNs increase exposure.

## Trade-offs and consequences

Already-issued sessions can require AWS-side containment. Trusted connector code receives the SDK session.
