# Privilege Delegation and Separation of Duties

## Status

Accepted

## Context

Delegation and self-approval can bypass oversight.

## Decision

Require verified MFA and trusted independent proposer metadata. Disable delegation until bounded grants can be written transactionally.

## Alternatives considered

Self-approval or delegation based on administrator role alone.

## Rationale

Sensitive changes require independently verifiable authority.

## Trade-offs and consequences

Authenticated approval writes and delegated administration remain closed.
