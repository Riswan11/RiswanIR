# Secrets STRIDE threat model

| STRIDE | Threat | Mitigation and remaining exposure |
| --- | --- | --- |
| Spoofing | A workload impersonates another tenant or integration | Verified registered identity, active membership, product and purpose checks. Compromised active identities retain their scoped permissions until revoked. |
| Tampering | A provider or competing worker changes the replacement | Immutable provider references, AES-GCM associated data, durable candidate and atomic activation. External systems remain responsible for their own credential lifecycle. |
| Repudiation | A privileged actor denies accessing or changing a credential | Audit entries record actor, tenant, product, correlation and outcome. The service fails before provider access when audit storage cannot accept a write. Operational access to audit storage requires its own controls. |
| Information disclosure | IDs are enumerated, metadata is stolen or credential material reaches logs, evidence or AI | Scoped queries and generic denial, separated encrypted values, explicit response schemas, sanitized provider errors and trusted-only consumption. SDK wire logging must remain disabled. Legacy evidence records and hashes are preserved. |
| Denial of service | Provider outage, slow operations or abusive deletion | Bounded SDK calls, recoverable deletion and fail-closed access. The SQLite policy lock serializes operations and is a throughput constraint. |
| Elevation of privilege | An owner reads material or an agent requests arbitrary role assumption | Human management is distinct from workload use. The broker accepts only approved mappings and read-only policies. The service never hands credentials to an AI interface. |

Provider-side effects and control-plane commits cannot share a distributed transaction. Deterministic provider keys and durable candidate state allow a retry to reconcile partial rotation. Revocation denies future use through Riswan Labs. Copies already delivered to an external system require containment at that system.
