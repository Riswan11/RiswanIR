# ADR 0007 · Human-in-the-loop response

## Status

Accepted. This record documents the existing implementation.

## Context

Containment actions can disrupt workloads. Analysts need to make and record response decisions.

## Decision

Generate advisory recommendations and persist feedback plus one approval or rejection per investigation. Run no remediation.

## Alternatives considered

Automatic containment and fully external decision tracking.

## Rationale

Advisories make the reasoning inspectable while keeping execution outside the application.

## Trade-offs

Reviewer identity is free text. Local timestamps and SQLite rows provide context but do not establish non-repudiation.

## Consequences

Keep advisory decisions distinct from execution. Reassess identity, authority, audit and rollback before considering any executor.
