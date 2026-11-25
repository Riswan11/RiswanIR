# Authorization

Riswan Platform evaluates permissions against a verified principal, a trusted execution context and server-resolved resource metadata. Active tenant membership is supplied by a trusted policy repository. A matching explicit deny takes precedence. Object access requires an active scoped role and a matching resource grant. Restricted objects require a direct grant and a human session with verified MFA. Privileged operations require MFA and audit recording. Approval requires an independent proposer recorded by the resource directory.

## API and worker enforcement

The scoped Riswan IR adapter checks collection scope before applying SQL limits. It checks policy before retrieving individual cases, evidence, exported raw records, graph, correlation, risk and memory. A caller who can read a case but lacks evidence permission receives its summary. Historical memory and related-case queries apply authorized candidate IDs before calculating matches or counts. Scoped risk queries exclude archives that depend on unauthorized cross-case provenance or historical aggregates whose source IDs were never recorded.

Case mutations check permissions inside the authorization lock and use the verified actor for analyst reviews and approval attribution. Store transactions preserve mutation atomicity. Duplicate approval protection remains in SQLite. Mutation responses omit embedded evidence and history. Case workers use the same policy contract for integrity verification and detection replay. Whole-store maintenance and the local connector CLI remain workstation operations. No tenant-scoped job invokes unfiltered maintenance.

The production identity runtime keeps product routes closed until Task 4.5 provides trusted live membership and a resource directory. The existing loopback developer mode has its own trusted workstation context. The authorization policy store and the product store use separate SQLite databases.

## Delegation and revocation

Only a verified MFA session with organization-scoped role-management authority can delegate. Delegation requires an active role in the same target scope, sufficient effective permissions and a grant lifetime within the grantor's authority. Self-delegation, platform operator delegation and delegation of role-management authority are denied. The target must already have active membership. Assignment and revocation audit records are committed with the policy change.

The SQLite policy lock serializes scoped operations with policy updates. If revocation acquires the lock first, the operation sees the new policy. If the operation acquires it first, revocation waits until the operation finishes. Role and resource decisions are re-read under that lock without a cache. Audit records for denials persist. Product and policy writes use separate databases, so the two commits have no distributed atomicity guarantee. The lock serializes requests using this adapter and may limit throughput until production policy storage is introduced.

Task 4.5 owns membership provisioning and organization routing. Product resource metadata, including proposer identity and evidence classification, must come from the trusted adapter. Resource grants and delegated role operations have internal contracts. Response execution remains disabled.
