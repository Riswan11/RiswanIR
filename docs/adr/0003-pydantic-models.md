# ADR 0003 · Pydantic domain models

## Status

Accepted. This record documents the existing implementation.

## Context

Loose dictionaries made shape changes easy to miss across normalization, storage and the API.

## Decision

Use Pydantic v2 for validated domain types, enums, evidence references, and JSON serialization.

## Alternatives considered

Plain dictionaries, TypedDict, and standard dataclasses with custom validation.

## Rationale

Runtime checks complement type checking, and existing JSON names can be preserved through aliases and serialization choices.

## Trade-offs

Pydantic adds a runtime dependency and validation cost. The package must account for old rows that omit newer fields.

## Consequences

Validate request and persistence boundaries. Regression-test REST shapes and legacy report hydration when models change.
