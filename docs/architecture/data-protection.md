# Tenant ownership and protected persistence

## Inventory at 9bfdaa9

| Store and owner | Resources | Ownership and current gaps |
| --- | --- | --- |
| Identity SQLite, identity repository | identities, provider links, sessions, status history, authentication audit | Platform-owned. Session access must be scoped to the verified identity. JWKS cache is issuer-scoped, in memory. |
| Control SQLite, tenancy and authorization | organizations, tenants, memberships, invitations, migration ledger, organization audit, policy snapshots, decisions | Organization data is tenant-owned; identity, policy configuration and lifecycle infrastructure are platform-controlled. |
| Control SQLite, secrets service | metadata, versions, rotation state, consumption policies, access events | Tenant and product on metadata; child records inherit through secret identity. Values live in cloud providers or a separate encrypted development database. |
| Product SQLite, investigation repository | investigations, ownership, detection context, reviews, decisions | Hosted cases have explicit ownership. Subordinate records inherit via case keys. Unowned legacy rows must remain outside hosted scopes. |
| Product SQLite, evidence repository | raw digests, raw payloads, receipts, transformations, custody | Receipts and derived views belong to cases. Current raw payload deduplication is global and needs tenant-specific storage and retention. |
| Product SQLite, analysis repositories | graph document, temporal snapshot, risk archives | Case-owned. Graph nodes and edges are serialized together in the case snapshot. Verify archive lineage before replay. |
| Product SQLite, historical memory | profiles, accounts, records, feedback, responses, tombstones and audit | Case-owned. Candidate queries must constrain tenant and authorization before ranking. |
| Product SQLite, collection state | receipts, checkpoints, status, pending windows | Existing checkpoint worker is workstation scoped. Hosted collection persists an owned case through the verified workload path. |
| Local files and process state | synthetic imports, CLI exports, operator config, backups, request budgets, rule registries and event subscribers | Workstation files are operator-owned. SDK credential files and backup media are deployment assets. Rules and ontology are shared immutable configuration. Cloud request budgets and caches must avoid exposing tenant data or keys. |

## Implementation plan

1. Add explicit data ownership, classification, retention, residency and authenticated encryption contracts.
2. Make the case repository verify hosted ownership on reads, mutations and subordinate queries. Leave legacy data unassigned and preserve historical identifiers and hashes.
3. Move raw hosted payloads into tenant-owned protected storage with immutable custody metadata and controlled migration.
4. Use a non-owner PostgreSQL runtime role with forced RLS policies and transaction-bound tenant/product context. Keep schema migration credentials separate. Test direct SQL, transaction rollback and pool reuse.
5. Integrate managed-key envelope encryption and tenant-bound object providers, then add authorized deletion, legal holds, backup verification and management routes.

## ADR

The application continues as a modular monolith. Store ownership joins and explicit tenant predicates protect SQLite development paths. SQLite has no native row-level security. Hosted production persistence should pool tenant tables under PostgreSQL RLS with tenant/product ownership on every protected row and tenant-aware foreign keys. Application authorization remains mandatory because RLS mediates records, not business permissions. Provider-specific storage, key options and cloud hierarchy remain in adapters. Restricted payloads use authenticated envelope encryption with identity and ownership bound into the authenticated context. Keep DEKs separate from persistence and wrap them with a registered managed key.

Legacy records without authoritative ownership stay inaccessible to hosted tenants. Any operator migration requires an explicit documented ownership mapping, verification of existing custody and hashes, and quarantine of ambiguous records.

## Implemented in the draft

Hosted SQLite case methods check that the current platform context belongs to the owning tenant and IR product. History and scoped list candidates are intersected with explicit owned case IDs before fetching report records. Hosted unscoped maintenance calls are denied. These are application checks. Direct SQLite access remains an operator trust boundary. The additive SQLite migration splits existing owned raw payloads by tenant after checking their digests. Unowned workstation receipts retain their original payloads. Raw evidence IDs, graph snapshots, case IDs and hashes are preserved.

The PostgreSQL implementation currently covers the new protected-object table only. Its migration requires a separate schema owner and a pre-created non-owner riswan_runtime role. It enables and forces RLS. The adapter rejects owners, superusers and BYPASSRLS roles at startup. Tenant and product settings are transaction-local. The runtime role assumes that only trusted application code can issue queries and bind transaction scope. These settings do not protect a compromised database principal that is allowed to set its own context.

Protected objects use AES-GCM with a random DEK and nonce. The authentication context binds tenant, product, resource type, resource ID and classification. DEKs are wrapped through registered managed-key instances. Rewrap verifies the original envelope before updating the wrapping metadata. The service validates residency across configured storage, processing, key and backup destinations. A global location fails strict residency. The local object store and SDK-shaped cloud adapters carry envelope bytes. Provider clients and destinations must be configured by trusted deployment code.

## Remaining integration

- Move existing hosted repositories onto PostgreSQL with tenant-aware foreign keys and a verified ownership migration.
- Move the tenant-separated raw evidence payloads from SQLite text storage to encrypted protected objects, preserve custody identifiers, and route original and derived views separately.
- Persist retention, legal holds, deletion workflow state, and recovery tombstones before exposing management or authorized destruction.
- Integrate provider residency and key configuration with hosted repositories, backup tooling, jobs and operational audit. Validate cloud version deletion separately from API-level removal.
- Extend graph and memory protection to persisted export and backup artifacts. Define tenant-scoped storage contracts for future RAG, vector indexes and agent memory.

## Deployment and testing

Install the optional postgres dependency group to exercise the protected-object adapter. The CI integration job creates disposable migration and runtime roles and tests missing context, mismatched rows, rollback, pool reuse and concurrent tenant/product operations. It must never be pointed at a persistent database. Cloud object tests use mocked clients. No live cloud storage or database is provisioned by this implementation.
