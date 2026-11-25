# Authorization foundation

The platform policy evaluator consumes a verified principal, trusted execution context, registered action and server-resolved resource. The policy repository supplies a current actor/tenant snapshot. Absence of a snapshot denies access. Explicit denies override grants. Object access requires both an active scoped role and a matching resource grant. Restricted objects require a direct grant and a human session with verified MFA. Privileged operations require verified MFA and an audit write. Approval also requires a trusted proposer different from the approver.

The SQLite adapter persists trusted snapshots and decision audit records in a separate database. Snapshot replacement is an internal provisioning interface for a trusted adapter. Task 4.5 owns membership lifecycle integration. No HTTP endpoint accepts role assignments, and the evaluator disables delegation and response execution. Agent identities have a restricted permission set and require a specific scope grant.

## Enforcement and revocation

The opt-in product enforcement adapter currently serves scoped investigation summaries. The collection query constrains investigation IDs before ordering and applying its limit. Detail access checks the requested resource before issuing the product query. Missing and denied objects return the same response. The existing loopback development app retains its prior behavior. The live identity runtime continues to deny product routes pending a trusted membership and resource directory integration.

Every decision reads policy without a cache. A revocation committed before the policy read affects that evaluation. A decision already in flight can finish under its earlier snapshot. Collection evaluation currently checks each resource independently. Transactional revocation for delegated writes and collection-wide snapshots remain open.

Full reports, evidence, graph and history can include data from separately protected objects. Authenticated product mutations and those read routes remain closed until component-specific permissions and projections can be enforced. Scoped background jobs and transactional mutations need the same enforcement contract before they can be enabled.
