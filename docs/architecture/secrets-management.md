# Secrets and credential management

The platform defines shared secret types, a value-provider contract and a consumer contract. The application composes the service with the existing identity, tenancy and authorization adapters. Existing workstation collectors retain their explicit operator credential flow. Hosted products use the shared contract.

| Material | Handling |
| --- | --- |
| Temporary AWS credentials | Read-only STS session in memory |
| External API keys, OAuth refresh tokens, webhook, database and OIDC credentials | Recoverable encryption through a value provider |
| Platform-issued API keys used only for verification | One-way verification when platform key issuance is introduced |
| Encryption keys and TLS private keys | Managed key or certificate service |
| Azure and GCP integration identities | Prefer workload federation when those connectors exist |

SQLite stores metadata, tenant/product ownership, opaque IDs, version and operation state, scoped grants and audit events. Values live in AWS Secrets Manager with a configured KMS key. Development may use AES-GCM with a separately held 32-byte key. Memory storage is for tests. Production rejects either development provider. No secret or lease payload enters the control database. Provider paths are derived internally from tenant, secret and version UUIDs.

Management routes are product-scoped for Riswan IR. The schema names tenant and platform scopes explicitly for future providers. This implementation provisions product scope only. Organization owners and administrators receive selected management permissions. Credential consumption is internal and requires a verified, enrolled service or integration, a matching product, an exact purpose grant and an unexpired active version. Human ownership does not grant material access. Requests and provider errors are excluded from telemetry. The shared redaction utility projects fields onto an explicit scalar allowlist.

## Rotation and deletion

Registration creates metadata and a durable candidate before writing the provider. Use the same registration UUID or rotation operation UUID when retrying the same request. The provider object is immutable within that operation. Rotation validates material, verifies provider read-back and updates the active pointer transactionally. A target-specific validation callback is available to internal integrations. The default hosted API verifies storage and read-back. Operators validate target-specific behavior before submitting a replacement.

Failed or interrupted operations leave the previous credential active. A stale candidate cannot promote across a changed base version. A separately authorized rollback can restore a retained version after validation. Previous versions are retained for rollback until deletion. Revocation blocks future service-mediated use immediately. Deletion makes values inaccessible through the platform, schedules provider removal and confirms destruction separately. AWS uses a seven-day recovery window and asynchronous deletion. Existing backups follow their storage retention policies.

## Credential broker

The broker takes an opaque integration ID and a registered operation purpose. A trusted application adapter supplies the role, account, Region, external ID and membership revision from its integration registry. The requesting workload cannot provide an ARN or session policy. The broker revalidates the current membership, reuses the existing phase 2 read-only connector policy and limits requests to a 15-minute STS session. It checks the returned expiry and account before handing the session to trusted connector code. No AWS credentials are sent to a UI, HTTP client or agent. A previously issued session can remain valid until expiry or AWS-side containment.

The broker registry is supplied by trusted application code. Task 4.6 provides no public STS issuance endpoint, production scheduler, agent integration or cloud deployment.
