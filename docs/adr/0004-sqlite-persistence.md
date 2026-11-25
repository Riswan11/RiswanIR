# ADR 0004 · SQLite persistence

## Status

Accepted. This record documents the existing implementation.

## Context

The local app needs durable investigations, reviews, and advisory decisions with minimal setup.

## Decision

Store report snapshots as JSON in SQLite, with relational review and decision tables, foreign keys and transactions.

## Alternatives considered

In-memory state, loose JSON files, and a managed relational database.

## Rationale

SQLite ships with Python and supplies transactional persistence and referential constraints without running a service.

## Trade-offs

Workstation permissions govern the database file. Shared access, cross-instance writes, and centralized backup need further design.

## Consequences

Preserve legacy report compatibility. Revisit schema versioning, migrations, concurrency and recovery before hosting.
