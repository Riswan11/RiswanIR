# Multi-cloud provider expansion

The platform supports trusted provider-instance configuration for hosted secret routes. The service can still open existing AWS records using the Task 4.6 configuration. Evidence records are preserved.

## Candidate boundaries

| Capability | AWS | Azure | Google Cloud |
| --- | --- | --- | --- |
| Managed encryption and decryption | KMS symmetric key | Versioned RSA-OAEP-256 Key Vault or Managed HSM key | Cloud KMS symmetric key |
| Secret material | Existing hosted Secrets Manager | Binary material encoded for Key Vault, exact native version reads, secret-wide recoverable deletion | Exact version reads and writes on provisioned regional secrets, provider-controlled version destruction |
| Temporary credentials | Registered role wrapper around existing STS session implementation | Entra workload identity token operation for Key Vault | Workload identity pool token exchange with optional project-bound service account impersonation |

The application must resolve target configurations from trusted registration data. The registry checks tenant, product, instance and external namespace before returning an adapter for a declared operation. Exact resource, workload and audience binding remain adapter checks. The registry does not replace tenant authorization.

The new credential broker validates active membership and registration revision before resolving the provider. It executes a configured trusted adapter operation and returns lease metadata. Provider credentials remain private to the operation. Federation configuration, token files and cloud destination mappings are trusted operator inputs. The hosted runtime mounts the broker for configured AWS collection integrations.

## Hosted configuration

Set RISWAN_IR_SECRETS_PROVIDERS to a trusted local JSON file. Each entry has tenant_id, instance_id, optional product_id set to ir, and a storage object with cloud and namespace. AWS requires the full kms_key ARN. Azure requires client_id and a federated_token_file path. Google uses attached compute credentials or federated application credentials, and the hosted slot provider uses the global Secret Manager endpoint. Configure one storage destination per tenant and product. Keep instance IDs stable across deployments. The old AWS environment values remain supported for records without an explicit binding.

A verified owner can use POST /v1/secrets/{id}/bind-provider to migrate a legacy AWS record after configuring an AWS destination in the original account and Region. The service checks that the existing active value is available in the configured destination. It preserves secret and version UUIDs and the provider path. Backup and validate the existing control database before a live migration. Cloud-to-cloud value migration is a separate operation.

Each Azure or Google version uses a platform-owned provider slot based on the operation UUID. The control database durably reserves an attempt before the first native write. A same-ID retry after an ambiguous failure reconciles the existing slot and checks the exact version and material. It never submits a second native write. If no version is visible, keep the old active credential and use a new operation ID after reviewing provider state. Azure requires vault soft delete and purge protection configured by the operator. Google slots request delayed version destruction and verify the configured delay before destruction. Platform revocation blocks future use before the provider retention window completes.

Set RISWAN_IR_COLLECTION_INTEGRATIONS to a trusted JSON file containing AWS collection registrations. Each includes integration_id, instance_id, tenant_id, workload_id, membership_joined, namespace and connector. Use the current membership joined_at value. The verified enrolled workload can POST /v1/integrations/{id}/collect with X-Riswan-Tenant. The broker selects the stored configuration and uses a bounded read-only CloudTrail collection, persisting results under the authenticated tenant. The response contains no session material. Azure and Google federation operations are available to trusted adapter code. Their telemetry ingestion routes are outside this task.

The CI installation matrix covers base, AWS, Azure and Google SDK groups. AWS remains a base dependency for the existing AWS CLI and container installation. Azure and Google SDKs are installed only through the respective extras.

## Validation boundaries

Tests use synthetic SDK clients. Before production enablement, validate actual cloud trust, exact resources and audiences, encryption and recovery, provider permissions, and error behavior in isolated accounts. Workload identities and provider roles, keys, policies, vaults and projects must be provisioned by the operator. Managed key adapters expose operation contracts for trusted consumers. There is no public key-use endpoint. Target-system secret validation remains distinct from provider write/read-back verification. Historical AWS provenance defaults remain for legacy evidence. Future non-AWS ingestion must supply explicit provider and service metadata.

## Provider references

- [Azure Key Vault secrets client](https://learn.microsoft.com/en-us/python/api/azure-keyvault-secrets/azure.keyvault.secrets.secretclient)
- [Azure managed key operations](https://learn.microsoft.com/python/api/overview/azure/keyvault-keys-readme)
- [Azure workload identity credential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.workloadidentitycredential)
- [Google Cloud Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
