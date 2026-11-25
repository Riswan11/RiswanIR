# 0012. Evaluate versioned rules over canonical events

## Status

Accepted.

## Context

Flat triage weights preserve a stable way to summarize older investigations. Analysts also need findings that consider identity, session, resources, networks, and known relationships.

## Decision

Evaluate versioned YAML rules over OCSF-aligned canonical events using a bounded evaluator and a trusted local inventory. Persist the resolved rules and inventory transactionally with the case. Seal the contextual findings and execution metrics in the evidence custody history. Keep triage scores and existing claim IDs available through the existing report contract.

## Alternatives considered

Hard-coded context predicates would simplify initial implementation but require engine changes for new rules. An external rules engine would add deployment and policy dependencies. Arbitrary expressions would expand the rule trust boundary and make execution harder to bound.

## Rationale and trade-offs

An allowlisted field and operator set keeps rule evaluation reviewable and makes replay deterministic for the same engine and inputs. It limits what rules can express. New provider attributes need a reviewed canonical mapping. Account and resource baselines depend on the quality of operator inventory.

## Consequences

Rule definitions and configuration changes follow code review. Findings remain advisory. The SQLite archives contain local inventory and rely on workstation access controls. Review the [detection architecture](../detection/overview.md) and [threat model](../security/threat-model.md) when extending the evaluator.
