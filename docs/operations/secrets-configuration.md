# Credential setup and operations

## Hosted configuration

Configure the existing OIDC and tenancy runtime first. Set RISWAN_IR_SECRETS_REGION to the AWS region used by Secrets Manager and RISWAN_IR_SECRETS_KMS_KEY to the approved KMS key identifier. Set both or neither. Use a server workload role and constrain its Secrets Manager access to the generated riswan namespace and intended KMS key. Do not supply a permanent AWS access key to the application.

For local adapter tests instantiate the AES-GCM provider with a separate database path and a 32-byte key from a protected process input. Keep the key and database separate from each other and the metadata database. The workstation app does not expose management endpoints by default.

## API

Use the existing authenticated hosted origin and X-Riswan-Tenant header. Browser-session mutations require the configured Origin. Send credential material only in the JSON body over HTTPS. Keep it out of URLs, command history, diagnostic output and evidence uploads.

| Method and path | Purpose |
| --- | --- |
| POST /v1/secrets | Register with id, name, kind and value |
| GET /v1/secrets | List scoped metadata |
| GET or PATCH /v1/secrets/{id} | Read or update metadata |
| GET /v1/secrets/{id}/versions | List version metadata |
| POST /v1/secrets/{id}/rotate | Stage and validate a replacement with operation_id and value |
| POST /v1/secrets/{id}/rollback | Restore a retained version with version_id |
| POST /v1/secrets/{id}/revoke | Reject new consumption |
| DELETE /v1/secrets/{id} | Schedule deletion |
| POST /v1/secrets/{id}/confirm-deletion | Check provider destruction |
| GET /v1/secrets/{id}/audit | Read scoped audit history |
| PUT or DELETE /v1/secrets/{id}/policy | Grant or remove a workload_id, purpose and expiration |
| POST /v1/organizations/{org}/workloads | Enroll an existing verified workload by identity_id |

## Compromise and rotation

Revoke platform use, revoke or rotate the credential at the external system, and record the scope of the compromise using audit identifiers. Use AWS-side session containment for already issued STS sessions where applicable. Stage and verify a replacement against the target, rotate using a stable operation ID, and confirm authorized operations work. Schedule deletion according to your retention requirements. Do not roll back to known compromised material.
