# Security controls and limitations

| Implemented control | Evidence or location | Limitation |
| --- | --- | --- |
| Loopback bind and Host allowlist | [Entrypoint](../../src/sentinelforge/__main__.py), [Host policy](../../src/sentinelforge/security/host.py), [security tests](../../tests/security/test_input_validation.py) | No user authentication, authorization, application TLS, or tenant isolation. |
| Bounded JSON parsing and typed requests | [HTTP boundary](../../src/sentinelforge/api/http.py), [domain models](../../src/sentinelforge/models/__init__.py) | The 8 MB request cap and 2,000-event limit address individual submissions. There are no application-level timeouts or rate limits. |
| Selected evidence fields and no-store responses | [Normalization](../../src/sentinelforge/normalization/cloudtrail.py), [HTTP boundary](../../src/sentinelforge/api/http.py) | Metadata and free-text notes may still be sensitive. The OS protects files and backups. |
| Canonical SHA-256 and valid evidence references | [Evidence sealing](../../src/sentinelforge/evidence/integrity.py), [security tests](../../tests/security/test_evidence_integrity.py) | No source attestation, automatic verification on read, signature, external digest anchor or immutable custody store. |
| Transactional parameterized SQL and foreign keys | [SQLite store](../../src/sentinelforge/storage/sqlite.py), [integration tests](../../tests/integration/test_storage.py) | Direct file writers are outside API constraints. No app-enforced file ACL, encryption, or backup. |
| Observable review history and unique advisory decision | [SQLite store](../../src/sentinelforge/storage/sqlite.py), [workflow tests](../../tests/integration/test_investigation_workflow.py) | Reviewer labels are self-reported. Records are advisory and may be edited by a privileged file writer. |
| Repository quality and scanning gates | [CI and security procedures](../engineering/ci-cd-strategy.md) | CI gates are scoped to configured tools and severity thresholds. Required approvals are zero. |
| Separate synthetic demo | [System context](../architecture/system-context.md) | Browser-stored notes remain accessible to users with access to that browser profile. |

Proposed controls are tracked in the [threat model](threat-model.md) and [risk register](risk-register.md). These include identity and authorization, stronger evidence custody, tenant isolation, constrained model tools, and short-lived connector credentials.
