# PostgreSQL platform control cutover

A.6 adds a separately scoped platform identity repository to the PostgreSQL preview. A dedicated PostgreSQL control pool enables organization, tenancy and authorization operations. Secrets metadata, integration and collection controls remain open. Existing preview configurations that explicitly compose SQLite control storage continue to use it. The PostgreSQL identity adapter has no SQLite fallback.

## Repository inventory

| Owner and boundary | Existing contract and persistence | Queries and transaction or audit dependencies | Cutover status |
| --- | --- | --- | --- |
| Global platform identity and actor-owned sessions | Identity service repository in identity_repository.py. SQLite identities, identity_provider_links, identity_sessions, identity_status_history and authentication_events. | Verified OIDC issuer and subject resolve before tenant lookup. A unique mapping assigns the stable actor ID. Browser sessions are looked up by cookie digest and listed by actor. Replacement, revocation, expiry, and status changes preserve their associated audit writes. | PostgreSQL identity adapter and preview composition. Existing SQLite identity imports need to preserve actor IDs before a data cutover. |
| Actor and tenant authorization | AuthorizationRepository in authorization_repository.py. SQLite authorization_snapshots and authorization_audit_events. Role and permission definitions are code. Snapshots hold assignments and resource grants. | Active tenant membership supplies a snapshot. Evaluator validates role, product, resource and parent scope. Business mutations roll back at a savepoint without losing the prior authorization audit. | PostgreSQL with the dedicated control pool. Role publication and revocation share the membership transaction. |
| Tenant lifecycle and memberships | Tenancy in tenancy.py. SQLite tenant_migrations, organizations, tenants, organization_memberships, organization_invitations and organization_audit_events. | List by verified actor, resolve active membership by actor and tenant, bootstrap a tenant and owner, accept by recipient and invitation digest, and enforce a single active owner. Membership, roles and lifecycle audit share the control transaction. | PostgreSQL with actor-scoped discovery, invitation acceptance and tenant-scoped mutations. |
| Tenant and product secret metadata | Secrets in secrets.py. SQLite secret_metadata, secret_versions, secret_rotations, secret_consumer_policies and secret_access_events. | Resolve tenant and product before routing to a provider. Secret version, active pointer and retryable rotation operation updates rely on scoped transactions. Consumer policies bind work to active workload membership and purpose. Provider mutations are external to the database transaction. | SQLite metadata. Values stay in AWS, Azure or Google Cloud secret providers. The encrypted local provider belongs to workstation storage. |
| Workload and integration credential control | RegisteredCredentialBroker and hosted credential broker. Provider and federation references come from trusted configuration. Workload membership and optional consumer policy reuse existing identity, tenancy and secret policy contracts. | Resolve the configured tenant, product, integration and workload before credential issuance. Audit uses the secret access event path. Lease values are transient and there is no existing SQLite lease table. | PostgreSQL workload identity lookup is available. Workload policy, binding and issuance audit persistence still depend on the control and integration ports. |
| Tenant and product integration and collection state | Trusted provider, routing and connector configuration. SQLite collection_receipts, collection_checkpoints, collection_pending and collection_status in the IR product store. | Deduplicate receipts and reject conflicting event digests. Reserve a collection window, persist cases and receipts, advance checkpoint, and clear the matching reservation. Preserve status and idempotency across restart. | PostgreSQL preview currently rejects hosted collectors. The PostgreSQL collection port must share the sink transaction for cases, receipts and checkpoints. |
| Tenant and case legal hold | Existing case repository and legal hold port. PostgreSQL investigation_legal_holds, investigation_hold_audit and investigation_memory_removals already use forced RLS. | Requires verified MFA and case authorization. Hold creation, release, attributed audit, and the memory removal check serialize on the case lock. | PostgreSQL reused. Revalidate when the tenancy and policy stores switch. |
| Existing data protection controls | Provider key and storage bindings come from trusted configuration. The protected object adapter already has scoped PostgreSQL and workstation implementations. | Ownership binds the protected object context before provider access. Existing envelope format and managed-key checks are reused. | No general classification, retention, residency or deletion policy repository exists yet. Those policy controls belong to later checkpoints. |

## Identity privileges and composition

Migration 0013 creates the riswan_auth schema under the migration role. Provision riswan_identity_runtime as a separate login with no role creation, database creation, superuser or RLS bypass privileges. Do not make it a member of the migration or product runtime roles. The identity role can read mappings and sessions, insert records, update selected identity and session columns, and append audit and status events. It cannot update identity provider mappings or read, update, or delete authentication audit rows. The product runtime role has no schema access.

These tables are platform-scoped. They deliberately omit tenant RLS because authentication precedes tenant selection. The authenticated product still resolves active membership separately. The application checks the role at startup and sets a fixed transaction-local schema search path. Identity writers take a transaction-scoped advisory lock to preserve the existing single-writer ordering. That lock also serializes normal browser session renewal and is a throughput constraint to revisit before live scale testing.

In the composition-only preview, pass the dedicated PostgreSQL identity pool as postgres_identity_pool, an existing PostgreSQL product pool as postgres_case_pool, and None as identity_db. Compose the PostgreSQL control pool for tenancy and authorization, or supply control_db explicitly for the compatibility path. Mixing identity backends fails configuration validation. An unavailable PostgreSQL identity pool returns a generic service-unavailable response without creating a SQLite identity database.

The tenancy adapter keeps actor-scoped membership and recipient lookup separate from tenant-admin commands. Bind actor context from a verified principal, and bind tenant context only after active membership proof. Keep invitation consumption, role publication, and membership changes in a single restricted transaction. Keep secret values and temporary cloud credentials out of all control tables and audit payloads.

## PostgreSQL authorization and tenancy

Migration 0014 adds a dedicated riswan_control schema and runtime login. The migration owner controls grants and schema objects. Provision riswan_control_runtime without membership in the product, authentication or migration roles and without RLS bypass. The authentication and product logins receive no control-schema grant.

| Records | Ownership and policy |
| --- | --- |
| Organizations and tenants | Stable IDs joined by a unique organization reference. Forced RLS limits discovery to non-revoked memberships. A recipient can validate the active tenant of an open invitation without gaining organization visibility. |
| Memberships | Composite tenant/actor key and database references to the tenant and global identity. Forced RLS permits self discovery before tenant selection. Tenant-scoped scope enables authorized management. |
| Invitations | Tenant and recipient references plus a composite inviter membership reference. Forced RLS protects tenant management and recipient acceptance. Only the closure column is mutable by the runtime. Token digests are unique. |
| Authorization snapshots | Tenant and actor ownership through a composite membership reference. Forced RLS applies to product assignments and grants. Role and permission definitions remain in application code. |
| Audit | Tenant and actor context on the decision. Forced RLS and insert-only runtime grants protect historical rows. Actor-attributed request denials use an explicit platform audit policy. |

The hosted composition accepts postgres_control_pool alongside postgres_identity_pool and postgres_case_pool. The verified principal establishes actor context before a tenant is chosen. Organization administration and product routing bind tenant scope after membership lookup. Bootstrap binds the newly allocated tenant and organization IDs. Acceptance binds tenant scope after a recipient-scoped single-use update. All context is transaction-local. The database login trusts this application boundary to set context from verified identities and fixed service queries. Possession of the runtime database credentials is outside the end-user trust boundary.

Organization bootstrap, initial owner and policy publication, invitation acceptance, role changes, ownership transfer, revocation, lifecycle updates and their business audits use one control-database transaction. A savepoint rolls back a rejected mutation while the outer transaction preserves prior authorization decisions. A transaction advisory lock preserves the SQLite single-writer ordering during the preview. A partial unique index prevents multiple active owners and a deferred database trigger requires at least one active owner at commit. Retrying a consumed invitation is denied. The advisory lock serializes control operations and merits load testing before a production cutover.

Secrets and collection configuration are unavailable in this composition until their control repositories are ported. SQLite remains an explicitly configured compatibility mode. Existing SQLite control records need a validated import preserving the global actor IDs before production cutover.

### Control lookup plans

The disposable PostgreSQL test adds 512 organizations, tenants, memberships and invitations to the authenticated fixture. It executes EXPLAIN ANALYZE as riswan_control_runtime and records the complete plans in the JUnit artifact.

| Query | Recorded access path | Example execution time |
| --- | --- | ---: |
| Actor membership discovery | Bitmap scan using control_actor_memberships | 0.033 ms |
| Active membership and tenant lifecycle join | Membership index and tenants primary key, with RLS subplans | 0.143 ms |
| Recipient invitation lookup with open and expiration predicates | Unique invitation digest index | 0.016 ms |

Membership listing and authorization snapshot access are measured separately in the same test. Product assignments and resource grants share the actor/tenant snapshot lookup. Runtime audit access is append-only, so there is no application audit read plan. The fixture did not justify a new expiration or audit index. The advisory lock and RLS subplan costs need larger tenant-cardinality and concurrent-load measurements before a live cutover.

## A.6.3 secrets and credential controls

Migration 0015 adds tenant/product-scoped provider bindings, secret metadata,
versions, rotation operations, workload policies and append-only access events.
Credential bindings and lease references further require the current workload.
The active version is a composite foreign key to the same secret in the same
tenant and product. A provider instance is bound to its original scope and
namespace. Grant rows reference both the relevant secret and an existing tenant
membership. The existing enrollment timestamp check invalidates grants and
credential bindings after re-enrollment.

The development preview accepts a trusted, in-process preview_secret_routing
object when all three PostgreSQL pools are configured. Only development-only
adapters are accepted. It still requires the
explicit development gate. CLI and environment-driven cloud provider
configuration remain disabled for the PostgreSQL preview. The existing SDK
contract and registry continue to resolve capabilities. The authorized
credential broker stores integration, target and workload references and lease
ID and expiry. The provider executes the credential operation within its
trusted adapter. Integration registration and collection orchestration remain
A.6.4.

No credential material or recoverable temporary credential appears in the
metadata contract. Authenticated secret endpoints return metadata only. Audit
rows require the session-bound actor and grant no UPDATE or DELETE privilege.
The control transaction preserves the existing writer ordering for rotation and
policy changes. Database transactions cannot undo cloud provider calls.
Provider retry uses existing operation and native version references. Deletion
records an audited pending intent before provider calls so a lost completion
audit can be reconciled without reopening access. Secret IDs cannot be reused
across products in the same tenant because provider slot keys predate product scoping. Test
coverage uses synthetic provider operations and localhost PostgreSQL.
