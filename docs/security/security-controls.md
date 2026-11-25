# Security controls and limitations

| Implemented control | Evidence or location | Limitation |
| --- | --- | --- |
| Loopback bind and Host allowlist | [Entrypoint](../../src/trailhound/__main__.py), [Host policy](../../src/trailhound/security/host.py), [security tests](../../tests/security/test_input_validation.py) | No user authentication, authorization, application TLS, or tenant isolation. |
| Bounded JSON parsing and typed requests | [HTTP boundary](../../src/trailhound/api/http.py), [domain models](../../src/trailhound/models/__init__.py) | The 8 MB request cap and 2,000-event limit address individual submissions. There are no application-level timeouts or rate limits. |
| Selected evidence fields and no-store responses | [Normalization](../../src/trailhound/normalization/cloudtrail.py), [HTTP boundary](../../src/trailhound/api/http.py) | Metadata and free-text notes may still be sensitive. The OS protects files and backups. |
| Independent raw and normalized digests, custody chains, and forensic verification | [Evidence sealing](../../src/trailhound/evidence/integrity.py), [tampering tests](../../tests/security/test_evidence_tampering.py) | No source attestation, automatic verification on normal read, signature, external digest anchor or immutable storage. |
| Transactional parameterized SQL and foreign keys | [SQLite store](../../src/trailhound/storage/sqlite.py), [integration tests](../../tests/integration/test_storage.py) | Direct file writers are outside API constraints. No app-enforced file ACL, encryption, or backup. |
| Observable review history and unique advisory decision | [SQLite store](../../src/trailhound/storage/sqlite.py), [workflow tests](../../tests/integration/test_investigation_workflow.py) | Reviewer labels are self-reported. Records are advisory and may be edited by a privileged file writer. |
| Repository quality and scanning gates | [CI and security procedures](../engineering/ci-cd-strategy.md) | CI gates are scoped to configured tools and severity thresholds. Required approvals are zero. |
| Separate synthetic demo | [System context](../architecture/system-context.md) | Browser-stored notes remain accessible to users with access to that browser profile. |

Proposed controls are tracked in the [threat model](threat-model.md) and [risk register](risk-register.md). These include identity and authorization, stronger evidence custody, tenant isolation, constrained model tools, and short-lived connector credentials.
