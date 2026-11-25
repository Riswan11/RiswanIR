# ADR 0002 · Python backend

## Status

Accepted. This record documents the existing implementation.

## Context

Riswan IR needs a portable local runtime and a practical ecosystem for security data processing.

## Decision

Use Python 3.11 or later, a standard-library WSGI server, and an installable package. Keep domain code callable without HTTP.

## Alternatives considered

A compiled Go backend, a Node.js backend, or an ASGI framework from the outset.

## Rationale

Python makes structured parsing and regression tests straightforward and supports possible future security and model integrations.

## Trade-offs

Runtime types need validation and static checks. The development WSGI server handles one request at a time.

## Consequences

Use the local runner under the trusted workstation model. Revisit server and concurrency choices before a hosted deployment.
