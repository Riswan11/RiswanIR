# ADR 0001 · Modular monolith

**Status** Accepted

Separate responsibilities into Python packages and keep the deployment as one local application. Preserve the existing API routes, report structure, and SQLite schema. Keep a source-checkout launcher alongside the installable package.

This allows investigation code to be tested independently of HTTP and persistence. New connectors or planning features can use the existing domain modules without requiring a separate service.
