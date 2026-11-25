# ADR 0008 · DevSecOps quality gates

## Status

Accepted. This record documents the existing implementation.

## Context

Changes to an investigation tool should meet an engineering and security baseline before entering main.

## Decision

Require tests, quality checks, security scans, CodeQL analysis and a generated SBOM. Run checks on PRs and main, pin actions and grant minimal token permissions.

## Alternatives considered

Ad hoc local checks, advisory-only scanning, and unpinned workflow dependencies.

## Rationale

Automated checks produce artifacts and improve repeatability. Protected branches make required results a condition of merge.

## Trade-offs

Scanners can miss issues or produce false positives, and hosted checks depend on external services. CODEOWNERS identifies ownership but the solo repository requires zero approving reviews.

## Consequences

Follow the documented triage and exception process. Reassess required checks, ownership and permission changes through review.
