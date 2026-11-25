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

## Security graph

| STRIDE | Scenario | Existing control | Residual risk |
| --- | --- | --- | --- |
| Tampering | A forged event or altered graph snapshot misstates a relationship. | Canonical event and correlation inputs, directional validation, case-local observation IDs and source/time validation. | The local database writer can alter records. The graph is a derived index rather than an independent source attestation. |
| Information disclosure | A relationship lookup returns a different case, or an account view includes unrelated observations. | The repository reads by investigation ID. Account views filter nodes and supporting observation events by account and partition. | Local clients can open other cases using this single-operator API. Case IDs are not authorization credentials. |
| Denial of service | Large traversals or high fanout overwhelm the local service. | Graph construction bounds nodes and observations. Graph queries limit request width, depth and returned entries. | Repeated local requests may still consume resources. |
| Elevation of privilege | An advisory graph relationship is interpreted as permission to execute remediation. | Graph API is read-only and action states reflect the separate analyst decision workflow. | Downstream tooling must preserve the advisory boundary. |

## Temporal correlation

| STRIDE | Threat | Existing control | Residual risk |
| --- | --- | --- | --- |
| Spoofing and tampering | Forged timestamps, actor records, or a modified policy create or hide incidents. | Strict UTC ordering, scoped graph evidence, validated YAML, versioned policy archives, and evidence custody verification on replay. | Imported CloudTrail telemetry is not independently attested. A privileged database writer can alter local archives. |
| Information disclosure | Traversal joins unrelated accounts or cases. | Case-scoped repositories and graph edges, scoped attribution, and a directional operator allowlist for cross-account paths. | Filesystem access and the single-operator service remain the trust boundary. |
| Denial of service | Candidate expansion exhausts memory or CPU. | Limits on events, YAML, stages, live states, graph traversal, and retained results with truncation metrics. | Heavy or repeated local requests may delay analysis. |
| Elevation of privilege | A candidate is used to justify automated remediation. | Incident API is read-only and recommendations are advisory. | Downstream consumers must preserve analyst review. |

## Risk assessment

| STRIDE | Threat | Existing control | Residual risk |
| --- | --- | --- | --- |
| Tampering | A client supplies scores, changes policy, or asserts unsupported containment. | Typed requests reject score overrides, policy is loaded from trusted local files, and containment must cite verified same-case evidence. | An operator with filesystem privileges can alter policy or SQLite. |
| Information disclosure | Assessment IDs or evidence references reveal another investigation. | Case-scoped repository reads and subject validation. | Local single-operator access is the authorization boundary. |
| Repudiation | Reassessment conceals the original decision basis. | Append-only history preserves exact factor inputs, policy, original references, and trigger. | No external immutable archive. |
| Spoofing | Valid hashes are mistaken for proof of origin. | Integrity and source corroboration have separate inputs and explanations. | Imported CloudTrail remains unauthenticated unless supported by provenance. |

## Historical memory

| STRIDE | Threat | Existing control | Residual risk |
| --- | --- | --- | --- |
| Tampering and spoofing | A forged or duplicated case influences baselines and recurrence. | Custody verification before admission, evidence-linked reviews, account scope, category digests, and raw-reference and lineage deduplication. | Imported source claims and self-reported local classifications still need review. |
| Information disclosure | History leaks unrelated account evidence or raw credentials. | Bound account-scope queries, current authorization and archival policy intersection, minimized records and scoped pseudonyms. | Privileged workstation access can read SQLite or test pseudonym guesses. |
| Repudiation | Historical retrieval or a classification change is disputed. | Audit records capture case and time with policy or result digests, and classifications retain their evidence references. | Audit storage is local. |
| Denial of service | A large history scan consumes processing or storage. | Candidate and output bounds, category expiration, explicit purge and minimized features. | Heavy repeated local calls can still consume resources. |

## Platform context and event boundary

The composition layer issues context from explicit workstation configuration and never derives tenant,
actor, request, or correlation identifiers from HTTP headers. Missing or mismatched context fails
closed for case operations. Event delivery checks tenant, product and correlation scope. Published
notifications carry references, while integrity and custody records remain in SQLite transactions.
The fixed development tenant covers one mounted database and does not authenticate local users.
Production identity, authorization, and tenant-aware persistence are planned.

## Centralized authentication

| STRIDE | Threat | Existing control | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Forged, substituted, or expired JWT, stolen code, forged browser state or nonce | Exact issuer and client or audience binding, signed claims, explicit algorithm and key selection, PKCE, one-use state, and nonce | An entrusted provider or its signing keys can be compromised. |
| Tampering | Untrusted token points to attacker-controlled JWKS | Configured HTTPS endpoints, no redirects, limited refresh and bounded key sets | A compromised operator configuration or provider domain can change trust. |
| Repudiation | Actor denies login, revocation or suspension | Structured event rows with server-generated request IDs, actor and outcome | Local SQLite custody depends on workstation access controls. |
| Disclosure | Tokens leak through logs, SQLite or browser-accessible state | Opaque session digest, secure cookies, query-free WSGI logging, generic errors, no stored refresh tokens | Configure equivalent behavior at the HTTPS edge. |
| Denial of service | Credential stuffing, callback floods or unknown key floods | Provider-hosted credentials, bounded local request rate and attempts, and JWKS refresh limits | Provider and edge rate limits must be configured in deployment. |
| Elevation of privilege | Actor accesses investigations without tenant authorization, or enables development in production | Separate modes, status checks, isolated identity database, and deny-by-default product routes | Tasks 4.4 and 4.5 will add authorization and membership. |

## Authorization threats

| STRIDE | Scenario | Likelihood / impact | Current control | Residual risk and next step |
| --- | --- | --- | --- | --- |
| Spoofing | Forged roles or a confused deputy act under another identity | Medium / High | Bound verified principal and matching actor context | Trusted adapter errors could still bind the wrong context. Verify live membership and resource resolution together. |
| Tampering | Policy mutation, scope tampering or stale grants bypass restrictions | Medium / High | Typed policy, trusted snapshot interface, no permission cache | In-flight requests can survive revocation. Add transactional checks for sensitive writes. |
| Repudiation | An actor denies approving their own proposal | Medium / High | Separate proposer and approver identities, MFA and decision audit | Durable authenticated approval writes still need integration. |
| Information disclosure | Object enumeration, cross-tenant reads or bulk export | High / High | Resource grants, tenant match, indistinguishable object denials and constrained summary queries | Aggregations and export remain closed in the scoped adapter until selective projections are available. |
| Denial of service | Policy and audit storage are overloaded | Medium / Medium | Evaluation and audit failures deny protected operations | Collection evaluation and audit writes can be expensive. Add bounded indexed policy queries before production. |
| Elevation of privilege | An administrator over-delegates or an agent inherits human tool access | Medium / High | Delegation and execution disabled, separate workload identities, exact permission checks | Transactional delegation and tool enforcement remain open. |
