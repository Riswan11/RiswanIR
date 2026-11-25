# Multi-cloud provider expansion

This branch adds tenant-bound provider resolution primitives and SDK-shaped adapters. Hosted secret routes continue to use the existing Task 4.6 service and AWS configuration. Its metadata schema and evidence records are preserved.

## Candidate boundaries

| Capability | AWS | Azure | Google Cloud |
| --- | --- | --- | --- |
| Managed encryption and decryption | KMS symmetric key | Versioned RSA-OAEP-256 Key Vault or Managed HSM key | Cloud KMS symmetric key |
| Secret material | Existing hosted Secrets Manager | Binary material encoded for Key Vault, exact native version reads, secret-wide recoverable deletion | Exact version reads and writes on provisioned regional secrets, provider-controlled version destruction |
| Temporary credentials | Registered role wrapper around existing STS session implementation | Entra workload identity token operation for Key Vault | Workload identity pool token exchange with optional project-bound service account impersonation |

The application must resolve target configurations from trusted registration data. The registry checks tenant, product, instance and external namespace before returning an adapter for a declared operation. Exact resource, workload and audience binding remain adapter checks. The registry does not replace tenant authorization.

The new credential broker validates active membership and registration revision before resolving the provider. It executes a configured trusted adapter operation and returns lease metadata. Provider credentials remain private to the operation. Federation configuration, token files and cloud destination mappings are trusted operator inputs. The hosted runtime does not mount this broker yet.

## Deferred integration and verification

- Persist native secret version identifiers and provider-instance bindings in a backward-compatible migration.
- Use provider capability checks in rotation, rollback, reconciliation, and deletion. Azure writes and Google Cloud version creation can allocate another native version after an ambiguous timeout. Do not retry such operations automatically until durable reconciliation is implemented.
- Wire hosted AWS collection to the shared broker and add application configuration and construction for Azure and Google Cloud secret and key clients.
- Add mocked SDK-construction tests and a CI installation matrix for base and each provider extra. Preserve the existing AWS installation path.
- Add provider instance and federation target metadata to access audits, without logging credentials.
- Verify accepted token claims, cloud-side trust configuration, exact targets, permission and recovery behavior in isolated cloud accounts before calling any provider production-ready.

## Provider references

- [Azure Key Vault secrets client](https://learn.microsoft.com/en-us/python/api/azure-keyvault-secrets/azure.keyvault.secrets.secretclient)
- [Azure managed key operations](https://learn.microsoft.com/python/api/overview/azure/keyvault-keys-readme)
- [Azure workload identity credential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.workloadidentitycredential)
- [Google Cloud Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
