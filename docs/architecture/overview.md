# System overview

Riswan IR is a local CloudTrail investigation workspace for one trusted operator. It accepts an export and a starting principal ARN, follows credential issuance and use within the supplied records, and produces an evidence-backed report. The analyst can record a disposition and approve or reject an advisory.

One Python process serves the bundled browser UI and REST API over IPv4 loopback using WSGI. Pydantic validates application contracts. SQLite stores report snapshots, reviews, and decisions. The investigation runs synchronously and uses deterministic correlation, scoring, graph projection, and recommendations.

An optional local collector process reads authorized AWS telemetry and persists it in the same evidence repository. The HTTP application has no identity provider, tenant partition, model calls, or remediation executor. The separate public demo serves precomputed synthetic reports and saves demo decisions in browser storage.

See the [system context](system-context.md), [component design](component-design.md), [data flow](data-flow.md), and [technical debt](../engineering/technical-debt.md).
