# ADR 0005 · Evidence-first reports

## Status

Accepted. This record documents the existing implementation.

## Context

Analysts need to inspect the recorded events behind findings and recommendations.

## Decision

Assign evidence IDs, record credential-link provenance, hash canonical normalized evidence, and validate finding and advisory references.

## Alternatives considered

Narrative-only reports or storage of entire raw exports by default.

## Rationale

Evidence references make conclusions inspectable. Selecting fields reduces unnecessary telemetry and secret retention.

## Trade-offs

Hashes are unkeyed. Without a trusted prior digest they do not authenticate the export or protect against a writer recomputing hashes.

## Consequences

Preserve evidence references and digest semantics. Treat authenticated ingestion, immutable custody and automatic checks as separate design work.
