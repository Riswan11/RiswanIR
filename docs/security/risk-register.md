# Security risk register

Statuses describe review and treatment progress. Residual ratings come from the [STRIDE threat model](threat-model.md). Role names below are responsibilities for the repository maintainers. Acknowledging a documented risk does not constitute formal acceptance.

| ID | Risk / residual | Owner | State | Treatment and review trigger |
| --- | --- | --- | --- | --- |
| SF-01 | Analyst spoofing and unauthorized local actions / High | API maintainer | Open | Add identity and authorization before multi-user access. |
| SF-02 | Forged export provenance / High | Ingestion maintainer | Open | Design source verification before trusting automated intake. |
| SF-03 | Misleading correlation or scoring / Medium | Investigation maintainer | Open | Review when rules, supported event sources or correlation change. |
| SF-04 | Report or audit modification / High | Storage maintainer | Open | Design independently anchored custody before relying on reports for formal evidence. |
| SF-05 | Repudiated approval or review / High | API maintainer | Open | Bind accountability to identity and audited time before shared use. |
| SF-06 | Sensitive data disclosure / High | Security maintainer | Open | Review encryption, retention and access when deployment or telemetry changes. |
| SF-07 | Request or storage exhaustion / Medium | API maintainer | Open | Set resource budgets before hosting or increasing intake. |
| SF-08 | Input interpreted as SQL or code / Medium | API maintainer | Monitored | Rerun targeted tests when SQL or browser rendering changes. |
| SF-09 | Misleading historical feedback / Medium | Investigation maintainer | Open | Review provenance and revocation before expanding memory. |
| SF-10 | Demo asset or browser-storage exposure / Medium | Demo maintainer | Monitored | Reassess when the demo accepts new data or changes hosting. |
| SF-11 | Supply-chain compromise or CI disclosure / Medium | Repository maintainer | Monitored | Review after workflow, dependency or artifact changes. |
| SF-12 | Unavailable or corrupted local storage / Medium | Storage maintainer | Open | Set recovery objectives and exercise restores before durable shared use. |
| SF-13 | Required check infrastructure outage / Medium | Repository maintainer | Monitored | Review repeated outages and document any approved recovery procedure. |
| SF-14 | Cross-tenant exposure / Not applicable | Security maintainer | Future | Threat model and isolation tests required before tenant support. |
| SF-15 | AI prompt injection, poisoning or disclosure / Not applicable | Security maintainer | Future | Review provider and data boundaries before model integration. |
| SF-16 | Tool abuse or unauthorized execution / Not applicable | Response maintainer | Future | Require separate authorization and audit design before execution. |
| SF-17 | Cloud credential exposure or out-of-scope collection / Not applicable | Connector maintainer | Future | Review least privilege and credential lifetime before connector rollout. |

For a new or changed risk, record the corresponding STRIDE ID, affected assets, existing controls, owner, treatment status, and review trigger. Record risk acceptance with rationale, scope, reviewer and expiry. Track private details through the process in [SECURITY.md](../../SECURITY.md).
