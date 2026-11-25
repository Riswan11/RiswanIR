# ADR 0010 · Evidence-backed identity and session correlation

## Status

Accepted for the local investigation workflow.

## Context

AWS credentials and roles can change across accounts and regions within one activity chain. Incomplete exports, reused session names and later delivery can make attribution ambiguous.

## Decision

Keep AWS field interpretation in a provider adapter. Use a deterministic engine that requires direct or corroborated identifiers and exposes supporting evidence and confidence. Recompute late evidence into a linked revision. Redact recognized credential secrets before writing new raw evidence.

## Alternatives considered

Keep exact ARN matching, use heuristic proximity alone, or rewrite prior reports in place.

## Rationale

Explicit evidence, conservative scope, and immutable report revisions make the outcome reproducible and let analysts compare changes without losing custody.

## Trade-offs

Ambiguous input can leave apparently related events unlinked. Revisions require retained source values and stay within local batch bounds. Redaction changes the retained representation for credential fields.

## Consequences

Review provider-field changes and chronology semantics with isolation tests. Revisit scope and custody before supporting automatic cross-investigation correlation.
