# STRIDE threat model

## Scope and assumptions

The current boundary is a trusted single-operator workstation running the local app. The public static demo and the GitHub build pipeline are separate surfaces. Treat input exports, browser inputs, dependencies, and contribution content as untrusted. Anyone who can reach the local service can act as its operator. A compromised OS account is outside the app's protection.

STRIDE evaluates spoofing (S), tampering (T), repudiation (R), information disclosure (I), denial of service (D), and elevation of privilege (E) across the [data flows](../architecture/diagrams/data-flow.md) and [trust boundaries](trust-boundaries.md). [Microsoft STRIDE guidance](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

## Ratings

Likelihood and impact use Low, Medium, and High. Low likelihood requires unusual access or conditions. Medium is plausible under the workstation or contributor model. High needs little effort or special access. Medium impact can disrupt or mislead a case. High can expose sensitive records, compromise custody, or affect system or cloud authority. The matrix is qualitative and ratings are reviewable assumptions.

| Likelihood / impact | Low | Medium | High |
| --- | --- | --- | --- |
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | Critical |

The risk column estimates exposure before the stated controls. Residual risk reflects the current controls. Planned controls do not reduce the current rating. Future-only rows show projected inherent risk and have no current residual exposure from that feature.

## Current threats

| ID | STRIDE and affected component | Scenario | Likelihood / impact / risk | Existing controls | Proposed mitigation | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| SF-01 | S, E · Browser, API, Host policy | A local client submits actions as another analyst, or an untrusted origin tries to reach the loopback service. | High / High / Critical | Loopback bind and Host allowlist reduce remote and DNS rebinding exposure. | For shared use, add authenticated identity, per-operation authorization, and tested browser-origin protections. | High. A reachable client can set reviewer names and invoke the same endpoints. |
| SF-02 | S, T · Ingestion, models, normalization | An altered export supplies plausible but fabricated callers, credentials or events. | Medium / High / High | Request shape checks, UTC validation and conflicting-ID rejection. | Record provenance at intake, support independently verifiable source exports, and expose coverage and source confidence. | High. A fabricated export can satisfy structural validation. |
| SF-03 | T · Correlation, evidence, detection, graph, response | Incomplete or misleading telemetry produces wrong links, risk, graph edges or advisories. | Medium / High / High | Account and partition scope, chronology, explicit ambiguity, evidence-backed confidence and versioned correlation snapshots. Weak network context does not establish identity. | Improve coverage and test larger real-format corpora across AWS accounts and principal types. | Medium. Valid but incomplete or fabricated telemetry can still yield a misleading interpretation. |
| SF-04 | T, R · SQLite, evidence custody | A writer edits reports, digests, reviews or decisions outside the API. | Medium / High / High | Expected OS file protections, transactional writes, separate raw and normalized digests, hashed receipt and transformation manifests, and app-level append-only custody. | Add externally anchored integrity and audit storage with independently controlled signing or retention. | High. A privileged writer can rewrite data and recompute local hashes together. |
| SF-05 | R · Review, memory, advisory decisions | A reviewer denies entering a disposition or approval. | Medium / High / High | Stored reviewer label and local timestamp, append-only feedback through the API, one decision through the API. | Bind events to authenticated identities, log immutable event IDs and timestamps under separate access control. | High. Free-text labels and local time do not establish authorship. |
| SF-06 | I · Export, frontend, API, SQLite and logs | A local process or backup exposes reports, notes or raw payloads that may contain credentials. | Medium / High / High | Raw payloads are separate from HTTP results. Local export uses a new restricted file on POSIX. Normalized responses use selected fields and no-store headers. Unexpected-error logs omit exception details. | Verify file permissions and backup encryption, choose a retention period, add authorization before shared use. | High. Anyone with sufficient OS file access can read the unencrypted database and exports. |
| SF-07 | D · WSGI, ingestion, investigation, storage | Slow or repeated requests consume the only request handler, or reports fill local disk. | High / Medium / High | Body and event limits, bounded recent-case queries. | Add request timeouts, quotas, bounded concurrency and storage retention for shared deployment. | Medium. Valid requests and disk exhaustion can still stall work. |
| SF-08 | T, E · API, storage, frontend | Untrusted strings are interpreted as SQL or executable markup. | Medium / High / High | Parameterized SQL, field validation and browser text rendering for telemetry. Security tests cover literal handling. | Expand browser-level regression tests and consider a restrictive CSP for deployment. | Medium. Future query or rendering changes can reopen interpretation paths. |
| SF-09 | T · Memory and analyst input | Repeated misleading dispositions distort similar-case context. | Medium / Medium / Medium | Latest review is associated with a stored case, deterministic bounded similarity, analyst-visible context. | Add authenticated reviewers, reviewer provenance, reconsideration and revocation. | Medium. Existing reviews remain operator assertions. |
| SF-10 | I, T · Static demo and browser storage | A compromised site release distorts the demo, or visitor notes remain on a shared browser. | Medium / Medium / Medium | Separate static site, synthetic samples, browser-local storage and reset. | Review demo publishing permissions and communicate safe note handling; audit asset changes independently. | Medium. Hosting control and browser access still matter. |
| SF-11 | T, I, E · GitHub workflows, dependencies and artifacts | Compromised dependencies, contributors, tooling or artifact contents affect the build or expose data. | Medium / High / High | Protected main, narrow workflow permissions, pinned actions, release digests, scanners, Dependabot, and synthetic fixtures. | Review workflow changes and artifact contents, consider reproducible dependency resolution and provenance attestation. | Medium. Trust remains in maintainers and external ecosystems. |
| SF-12 | D · Local filesystem, SQLite and OS configuration | Database loss, corrupted storage, or an invalid database path prevents reading reports. | Medium / High / High | SQLite transactions and injectable database path. | Document backup and restore testing, storage monitoring, and recovery responsibilities. | Medium. No application-managed recovery or backup. |
| SF-13 | T, D · Build and dependency services | An unavailable advisory feed or hosted runner prevents required checks from completing. | Medium / Medium / Medium | Required checks gate merging and expose failures; scheduled security runs detect later feed changes. | Document retry and incident handling, and define a reviewed recovery process. | Medium. Availability still depends on third-party services. |

## Canonical schema and export

| ID | STRIDE and affected component | Scenario | Likelihood / impact / risk | Existing controls | Proposed mitigation | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| SF-18 | T, I · Mapping, registry and export | Mapping changes misclassify telemetry or disclose sensitive provider fields. | Medium / High / High | Pinned classes, typed extension allowlists, safe validation messages, a separate custody digest and preserved evidence references. | Review mapping semantics and field sensitivity before adding classes or extensions. | Medium. Exported metadata remains sensitive and a flawed rule can mislead readers. |

## Future features and new boundaries

| ID | STRIDE and proposed component | Scenario | Projected likelihood / impact / risk | Existing controls | Mitigations required before rollout | Current residual |
| --- | --- | --- | --- | --- | --- | --- |
| SF-14 | I, E · Shared API, tenant storage and retrieval | One tenant can read or act on another tenant's case through IDs, queries, graph or similarity. | Medium / High / High | Single local operator; no tenant feature. | Bind tenancy to authenticated identity, scope each query and job, limit artifact access, test cross-tenant denial. | Not applicable to current tenant-free scope. |
| SF-15 | T, I, E · AI planner, model provider and retrieval | Malicious telemetry prompts unauthorized behavior or poisons AI context. Sensitive data leaks to a provider. | High / High / Critical | Deterministic runtime; no provider or planner invoked. | Treat retrieved text as data, minimize outbound fields, validate structured output, enforce evidence citations and gate tools outside the model. | Not applicable to current deterministic scope. |
| SF-16 | E, T · Agent tools and remediation executor | A planner requests an unauthorized action or exceeds the scope of valid approval. | Medium / High / High | Advisory decisions have no executor. | Use allowlisted typed tools, scope approval to the exact action, enforce least privilege, add cooldown, verification and audit. | Not applicable to current advisory scope. |

## Optional AWS collector

| ID | STRIDE and affected component | Scenario | Likelihood / impact / risk | Existing controls | Proposed mitigation | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| SF-17 | I, E, D · AWS authentication, connector scope and checkpoints | Misconfigured IAM trust, credential exposure, inappropriate bucket access, or repeated collection increases exposure or cost. | Medium / High / High | Temporary SDK credentials, account and source checks, scoped assumed-session policy, verified TLS, bounded requests and object sizes, deduplication, and redacted health summaries. | Verify each role and archive in a dedicated sandbox. Monitor usage, configure external ID where appropriate, keep direct profiles narrowly scoped, and protect raw evidence. | Medium. IAM trust and direct profile privileges are operated outside the app, and local privileged access can expose raw telemetry. |

Use the [risk register](risk-register.md) for owners and review triggers, and the [controls inventory](security-controls.md) for verification evidence.

## Detection configuration and replay

| STRIDE | Scenario | Likelihood | Impact | Risk | Existing mitigation | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| Tampering | A local writer alters YAML, inventory, or an exception to hide findings. | Medium | High | High | Trusted filesystem paths, schema validation, bounded versioned YAML, archived exact policy and fingerprint, scoped and expiring exceptions. | Medium. A workstation administrator can alter configuration and local storage. |
| Spoofing | A forged CloudTrail export claims a known principal or expected source network. | Medium | High | High | Inventory uses trusted local configuration, missing attributes fail predicates, and reports retain supporting evidence. | High. Imported claims remain subject to the evidence source-authenticity limitation. |
| Repudiation | An operator disputes who approved a suppression or exception. | Medium | Medium | Medium | Suppression decisions record rule, version and evidence. Exceptions also record their local approval ID and archived approver. | Medium. Workstation operators attest their own identity. |
| Information disclosure | Another local user reads account inventory or approved network ranges from the case database. | Medium | Medium | Medium | Inventory stays out of API responses and execution logs. SQLite relies on restricted filesystem access. | Medium. Elevated local readers retain access. |
| Denial of service | Large rules or high-fanout telemetry exhaust detection memory. | Medium | Medium | Medium | YAML, rule, event, grouping-window and result bounds. Excess results fail the case transaction. | Low to medium. Per-case limits do not rate-limit repeated local submissions. |
| Elevation of privilege | A rule tries to access arbitrary objects or execute code. | Low | High | Medium | Safe YAML loader and fixed field and operator allowlists. Findings are advisory. | Low. Dependencies and future operators require review. |
