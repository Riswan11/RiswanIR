# ADR 0011 · OCSF-aligned canonical events

## Status

Accepted for the CloudTrail subset.

## Context

Future sources need a shared contract while historical investigations retain their provenance and hashes.

## Decision

Pin OCSF 1.6.0. Store a versioned canonical projection alongside normalized evidence and anchor it to custody. Project old reports only when requested.

## Alternatives considered

Keep CloudTrail-shaped events, replace evidence in place, or implement the entire OCSF catalog.

## Rationale

The new contract helps downstream engines share fields while preserving historical investigation and evidence contracts.

## Trade-offs

The projection adds storage and mapping maintenance. Incomplete input can result in a Base Event.

## Consequences

Test class semantics, required context, version compatibility, evidence references and confidentiality before releasing each mapping.
