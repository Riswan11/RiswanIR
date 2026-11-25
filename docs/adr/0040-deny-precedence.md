# Policy Evaluation and Deny Precedence

## Status

Accepted

## Context

Overlapping policy grants can conflict.

## Decision

Default deny and resolve matching explicit denies before role grants.

## Alternatives considered

First-match or allow precedence.

## Rationale

Negative constraints remain effective as policy expands.

## Trade-offs and consequences

Broad denies can override narrowly scoped allows.
