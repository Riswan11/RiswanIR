# Data classification and assets

| Data or asset | Classification | Location and handling |
| --- | --- | --- |
| Reviewed source, design docs, synthetic fixtures and demo samples | Public | Repository or demo. Use synthetic or publicly documented test data. |
| Synthetic demo notes and decisions | User-entered, potentially sensitive | Visitor browser storage. Use sample content and clear it with the demo reset. |
| Real CloudTrail exports and supplied findings | Restricted | Operator-controlled original files and browser input. Original record values are retained in SQLite. Keep both outside source control and CI. |
| Normalized evidence, identity fields, IPs, account IDs, graph, scores and audit decisions | Restricted | Local SQLite and API responses. Apply workstation access and backup policies. Hashes and identifiers can still expose operational context. |
| Credential secrets encountered in exports | Secret | Recognized secret and token fields are redacted from new raw payloads. Older retained raw records and exports may still contain them. Access key identifiers remain in restricted raw data for replay. |
| Source, CI configuration, dependency pins and SBOM | Integrity-critical | GitHub and build artifacts. Protect changes with review and check gates. Review artifacts before redistribution. |
| GitHub tokens, signing material and connector credentials | Secret | AWS credentials come from the local SDK chain and remain transient in SentinelForge. Never include credentials in docs, logs or public security reports. |

Raw retention is explicit through the local CLI. The app has no scheduler, app-managed encryption at rest, or secure erasure guarantee. The operator is responsible for permissions, backup handling and disposal. [Evidence custody](../architecture/evidence-custody.md)
