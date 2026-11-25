# ADR 0001 · Modular monolith

## Status

Accepted.

## Context

The prototype combined normalization, scoring, investigation memory, and persistence in one module. These responsibilities change for different reasons.

## Decision

Separate responsibilities into Python packages and keep one local deployment. Preserve API routes, report structure, and SQLite compatibility. Keep a source-checkout launcher alongside the installable package.

## Alternatives considered

Keep one implementation module, or split the API, analysis, and storage into separate deployed services.

## Rationale

Package boundaries let investigation code be tested without HTTP or SQLite. A single deployment avoids introducing network protocols, service discovery and distributed operations for a local workload.

## Trade-offs

Modules share a process and deployment lifecycle. Compute, persistence, and transport cannot scale independently. Package ownership and dependency direction need review.

## Consequences

Preserve domain independence from transport and persistence. Revisit deployment boundaries when workload isolation or independent scaling becomes a concrete requirement.
