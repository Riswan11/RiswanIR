# Authorization Auditing and Revocation

## Status

Accepted

## Context

Privileged decisions need records and stale policy can prolong access.

## Decision

Persist denials and privileged decisions. Read policy on each evaluation.

## Alternatives considered

Best-effort logging with long-lived role caches.

## Rationale

Fresh policy reads and mandatory audit writes reduce stale and unaudited access.

## Trade-offs and consequences

In-flight decisions may complete and audit storage failure denies privileged access.
