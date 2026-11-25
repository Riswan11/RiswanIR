# ADR 0006 · Deterministic detection

## Status

Accepted. This record documents the existing implementation.

## Context

Risk results should be reproducible and reviewable given the same records and code.

## Decision

Use explicit weighted rules for observed calls, distinct event counts and credential-linked order. Cite matching evidence.

## Alternatives considered

Opaque model scoring, statistical baselines, and unweighted event lists.

## Rationale

Rules provide reproducible outputs and support targeted regression tests.

## Trade-offs

Heuristics lack a behavioral baseline and depend on export completeness. A score indicates review priority and may produce false positives or negatives.

## Consequences

Require evidence-linked tests for rule changes. Keep comparative results interpretable when rule weights or versions change.
