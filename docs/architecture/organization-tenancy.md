# Organization and tenant management

An organization is the customer-facing record with a name, settings and memberships. Its tenant is the security boundary for product data. Each organization has one tenant with a distinct immutable UUID. Membership and role changes affect that tenant only.

## Request flow

1. OIDC validates the session or bearer credential and binds the verified identity.
2. The authenticated tenant API validates the selected tenant against a current membership and an active tenant. The header is a selector. It grants no privileges.
3. The application binds a server-derived platform context. The IR resource directory looks up ownership in the product database.
4. Task 4.4 evaluates the actor, membership policy, action and resource. Case collections apply authorized IDs in SQL before returning results.
5. Revocation and tenant lifecycle changes share the same policy lock as protected product requests. A change that acquires the lock first takes effect before the request is evaluated.

Invitations are issued to a known active human identity UUID. An invited user signs in with their enrolled identity and presents the one-time token in a JSON body. Only a SHA-256 digest is persisted. An invitation expires after 24 hours and is consumed atomically. Revocation, suspension and loss of inviter authority close pending invitations. Tokens belong in private communication and never in a URL.

An organization always has one active owner membership. The owner may promote another member to admin or transfer ownership to an existing active human member. Transfer promotes the recipient and demotes the previous owner to analyst in one transaction. Suspension blocks product access while allowing the owner to reactivate or archive the tenant. Archive is terminal. Audit events record administrative changes and generic denials without invitation secrets or telemetry.

## Hosted API

Configure OIDC as documented in [centralized authentication](authentication.md). For hosted organization and IR API routes, set both RISWAN_IR_CONTROL_DB and RISWAN_IR_HOSTED_DB to distinct SQLite paths. They must also differ from the identity database and workstation database. The control database owns organization, membership, invitation, policy and audit state. All hosted organizations use one product database. If both new variables are omitted, the runtime serves identity routes only.

| Method and path | Purpose |
| --- | --- |
| GET /v1/organizations | List organizations available to the verified identity |
| POST /v1/organizations | Create an organization with name and optional settings |
| GET or PUT /v1/organizations/{org} | Read or update organization metadata |
| POST /v1/organizations/{org}/activate | Validate selection and return its tenant ID |
| GET /v1/organizations/{org}/members | List memberships for authorized administrators |
| PUT /v1/organizations/{org}/members/role | Change an active member role with identity_id and role |
| DELETE /v1/organizations/{org}/members/{identity} | Revoke membership and policy |
| POST /v1/organizations/{org}/invitations | Issue an analyst or viewer invitation with identity_id and role |
| POST /v1/organizations/invitations/accept | Accept an invitation for the authenticated identity with token |
| DELETE /v1/organizations/{org}/invitations/{invitation} | Close an unused invitation |
| POST /v1/organizations/{org}/ownership | Transfer ownership with identity_id |
| POST /v1/organizations/{org}/lifecycle | Set status to active, suspended or archived |

Send the selected tenant UUID in the X-Riswan-Tenant header on each hosted investigation request. Selection is request-scoped so one browser tab can use a different organization from another. Browser session mutations require the configured HTTPS origin. Organization administration and onboarding require MFA. Tenant sharing grants apply only to server-owned resources marked shareable and remain subject to roles, explicit denies and restrictions. Archived and suspended tenant metadata remains visible to current members for lifecycle awareness.

## Persistence and limits

The additive control schema begins at version 1. The product schema adds an ownership table. New hosted cases and revisions record tenant and creator in the same transaction as the case. Existing investigation IDs, evidence hashes and audit records stay in their original databases or retain their unowned status. They are never assigned to a customer by inference. Hosted risk scoring excludes cross-case historical enrichment until model inputs can be scoped and attributed. Hosted memory retrieval continues to use tenant-authorized case IDs.

This is application-layer scoping. Task 4.7 strengthens database-level tenant isolation. This task does not provision Cognito, hosting, email delivery or a management dashboard.
