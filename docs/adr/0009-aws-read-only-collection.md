# ADR 0009 · Read-only AWS collection

## Status

Accepted for the local connector implementation. Dedicated sandbox validation is tracked separately.

## Context

Analysts need recent and historical AWS telemetry with provenance, controlled access and recovery after interruption.

## Decision

Use boto3 with temporary credentials, an account-verified connector per scope, and a local scheduler. Use Event History for regional management events and S3 for historical trail files. Send batches through the same raw evidence and investigation pipeline as manual input. Persist a pending window, idempotency receipts and final checkpoint in SQLite.

## Alternatives considered

Continue manual collection, use Event History alone, or introduce cloud-hosted event streaming.

## Rationale

Two batch sources cover common CloudTrail delivery paths without giving the local application cloud write authority. The SDK credential chain and scoped assumed sessions avoid storing permanent keys.

## Trade-offs

S3 delivery can be delayed. Windows and explicit overlap limit scope and cost. Collection creates batch-scoped cases. The local scheduler provides no availability or distributed rate guarantees.

## Consequences

Document roles, verify receipt and checkpoint behavior, and test offline before validating each configured IAM trust and archive in a dedicated sandbox. New connectors should yield provenance-bearing batches without changing the investigation engine.
