# Centralized Authorization Architecture

## Status

Accepted

## Context

Product-specific checks would duplicate security logic.

## Decision

Use one typed evaluator across products.

## Alternatives considered

Per-handler authorization or an external policy server.

## Rationale

Pure policy code is testable and keeps infrastructure concerns in adapters.

## Trade-offs and consequences

Trusted callers must supply verified principals and context.
