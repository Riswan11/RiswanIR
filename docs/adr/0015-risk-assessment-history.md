# 0015. Preserve independent risk and confidence assessments

## Status

Accepted.

## Context

Analysts need a defensible ordering of findings and incidents even when potentially severe activity has incomplete telemetry. The same scoring primitives should work for additional products.

## Decision

Use independent versioned weighted dimensions, exact severity thresholds, and a policy-driven priority matrix. Project security observations through a product adapter and archive factor inputs, policy and outputs in append-only SQLite records.

## Alternatives considered

Multiplying risk by confidence obscures high-impact low-evidence cases. Writing the latest score into the case report would hide changes and prevent historical replay. Calibrated statistical prediction needs representative validation data.

## Rationale and trade-offs

Deterministic weighted sums and explicit missingness help analysts inspect the calculation. Normalizing available factors requires displaying coverage beside the score. Policy and inventory remain trusted local inputs. Historical replay reproduces the archived calculation from the original factor values.

## Consequences

Analyst decisions, evidence revisions, and on-demand changes can produce new records without overwriting the original. Residual risk is available for narrowly supported containment evidence. See the [risk scoring guide](../detection/risk-scoring.md).
