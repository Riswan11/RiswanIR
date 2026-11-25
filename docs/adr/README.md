# Architecture decision records

An ADR explains a significant decision and the trade-offs it accepts. Use the [template](template.md) for new records. Allocate the next number and keep accepted ADRs as historical records. Record material reversals in a new ADR and link the superseding decision in both directions.

- [0001 Modular monolith](0001-modular-monolith.md)
- [0002 Python backend](0002-python-backend.md)
- [0003 Pydantic domain models](0003-pydantic-models.md)
- [0004 SQLite persistence](0004-sqlite-persistence.md)
- [0005 Evidence-first reports](0005-evidence-first-design.md)
- [0006 Deterministic detection](0006-deterministic-detection.md)
- [0007 Human-in-the-loop response](0007-human-in-the-loop.md)
- [0008 DevSecOps quality gates](0008-devsecops-quality-gates.md)
- [0009 Read-only AWS collection](0009-aws-read-only-collection.md)
- [0010 Evidence-backed identity and session correlation](0010-identity-session-correlation.md)
- [0011 OCSF-aligned canonical events](0011-ocsf-aligned-events.md)

- [0012. Evaluate versioned rules over canonical events](0012-context-aware-detection.md)

- [0013. Store versioned investigation graph snapshots in SQLite](0013-security-knowledge-graph.md)

- [0014. Correlate event-time sequences within case revisions](0014-temporal-correlation.md)

- [0015. Preserve independent risk and confidence assessments](0015-risk-assessment-history.md)

- [0016. Retrieve scoped and evidence-backed historical intelligence](0016-scoped-historical-memory.md)

- [0017. Retain one deployable modular monolith](0017-retained-modular-monolith.md)
- [0018. Separate shared platform from product intelligence](0018-platform-product-boundaries.md)
- [0019. Enforce dependency direction](0019-dependency-direction.md)
- [0020. Bind trusted execution context](0020-execution-context.md)
- [0021. Publish a minimal product module contract](0021-product-module-contract.md)
- [0022. Keep SQLite with explicit data ownership](0022-persistence-ownership.md)
- [0023. Introduce bounded in-process notifications](0023-domain-events.md)
- [0024. Publish versioned security finding contracts](0024-cross-product-findings.md)
- [0025. Organize platform, data, IR and composition in one repository](0025-repository-package-layout.md)
- [0026. Require a measured reason for service extraction](0026-future-service-extraction.md)

- [0027. Centralize identity behind a platform boundary](0027-centralized-identity.md)
- [0028. Prefer a managed OIDC identity provider](0028-managed-identity-provider.md)
- [0029. Use Authorization Code, PKCE, state and nonce](0029-oidc-oauth-standards.md)
- [0030. Use stable internal identity IDs](0030-internal-identity-model.md)
- [0031. Separate provider tokens from platform sessions](0031-token-session-security.md)
- [0032. Distinguish human and workload identities](0032-human-and-workload-identities.md)
- [0033. Audit authentication without storing credentials](0033-authentication-audit.md)
- [0034. Isolate workstation and OIDC environments](0034-identity-environment-isolation.md)

## Authorization

- [Centralized Authorization Architecture](0035-centralized-authorization.md)
- [Hybrid RBAC and ABAC Model](0036-hybrid-rbac-abac.md)
- [Permission Namespace and Product Ownership](0037-permission-namespace.md)
- [Resource-Level Authorization](0038-resource-authorization.md)
- [Tenant-Aware Policy Enforcement](0039-tenant-aware-policy.md)
- [Policy Evaluation and Deny Precedence](0040-deny-precedence.md)
- [Privilege Delegation and Separation of Duties](0041-separation-of-duties.md)
- [Non-Human Identity Authorization](0042-workload-authorization.md)
- [Authorization Auditing and Revocation](0043-authorization-audit-revocation.md)

- [0044 Shared organization tenancy](0044-shared-organization-tenancy.md)

- [Secret provider abstraction](0045-secret-provider-abstraction.md)

- [Temporary credentials](0046-temporary-credentials.md)

- [Secret storage boundaries](0047-secret-storage-boundaries.md)

- [Tenant-bound cloud provider instances](0048-cloud-provider-instance-identity.md)
