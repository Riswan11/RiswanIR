# 0016. Retrieve scoped and evidence-backed historical intelligence

## Status

Accepted.

## Context

Future investigations need prior context without allowing duplicate evidence, conflicting analyst outcomes or unauthorized history to distort findings or priorities.

## Decision

Persist minimized SQLite records in separate memory categories with account membership, policy versions, expiry and integrity digests. Retrieve cases with deterministic comparisons and classify baseline data through evidence-linked analyst review. Feed only confirmed independent recurrence into the existing risk factor.

## Alternatives considered

Whole-report indexing would expose unnecessary telemetry. Vector retrieval would expand the infrastructure and make comparisons harder to replay. Automatically learning rule changes from feedback would give erroneous labels direct control over future alerts.

## Rationale and trade-offs

Structured fields and fixed weights give explainable retrieval and support explicit expiration. The results remain limited by retained custody, operator classification, and account configuration. Access revocation supersedes historical reproducibility.

## Consequences

Independent policies can govern each category's enablement and retention. Review affiliations and evidence before promoting baselines or remediation. Memory informs investigations while versioned detection and risk policy retain separate approval paths. See [historical memory](../detection/historical-memory.md).
