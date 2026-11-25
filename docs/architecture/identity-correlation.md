# AWS identity and session correlation

The AWS adapter interprets CloudTrail records. The correlation engine consumes typed observations, orders them by UTC time and event ID, and derives relationships without a model or live AWS calls. The current investigation still starts with an exact ARN. Identity nodes use AWS partition, account and principal ID when available, with an ARN fallback. Records without reliable identity attributes remain separate.

| Confidence | Basis |
| --- | --- |
| Confirmed | A direct recorded fact, such as an unambiguous issued credential identifier matching a later API call or a successful STS response establishing a session. This is confidence in the relationship within the supplied data. |
| High | Consistent strong metadata. If a credential ID is missing, matching session ARN, issuing role, principal ID, and creation time can corroborate a link. |
| Medium and low | Reserved for weaker evidence. They do not expand investigation scope in this version. |
| Unknown | Attribution has insufficient or conflicting support. Temporal proximity, IP addresses, user agents and session names alone do not create links. |

Credential links require use after issuance and before any reported expiration. Session creation timestamps may differ from the issuance timestamp by up to two seconds for corroborated matching. Shared CloudTrail event IDs and scoped request IDs can link co-observed events within five seconds. Request relationships do not independently expand a case. Contradictory account, partition, session or principal data prevents linking. A chain is an activity reconstruction. It does not establish intent or authenticate the CloudTrail export. [AWS CloudTrail identity fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) · [AWS cross-account request fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)

The report persists ordered identity timelines, observed role assumptions, and evidence-backed graph edges. The correlation snapshot includes its rule version and tolerances and is anchored in the custody log. The raw access key ID remains available in archived telemetry for replay. Correlation and ordinary HTTP responses use fingerprints rather than emitting credential IDs.

## Late telemetry

Send `GET /v1/investigations/{id}/correlation` to retrieve a snapshot. An earlier report without correlation returns null.

Send `POST /v1/investigations/{id}/revisions` with a JSON `records` field containing supplemental CloudTrail telemetry and an optional `provenance` object. The app verifies the source case and rebuilds a fresh report from retained records plus the supplement. The revision references its predecessor. Earlier evidence, reports, reviews, and advisory decisions stay with their original case. Previous receipts keep their provenance, and the new case records revision custody. The revision requires retained raw data and is subject to the existing 2,000-record limit. Connectors still create independent batches and do not automatically revise earlier cases.

## Credential retention

New archived payloads redact recognized secret-access-key and session-token fields before storage. Hashes cover the retained, redacted representation. Access key identifiers may remain in the restricted raw store because replay uses them. Earlier raw records are neither rewritten nor scrubbed by the upgrade. Apply your existing retention policy to older raw records and secure backups and prior exports. Field-based redaction cannot guarantee removal of secrets placed in arbitrary unrecognized fields.
