# Data classification and assets

| Data or asset | Classification | Location and handling |
| --- | --- | --- |
| Reviewed source, design docs, synthetic fixtures and demo samples | Public | Repository or demo. Use synthetic or publicly documented test data. |
| Synthetic demo notes and decisions | User-entered, potentially sensitive | Visitor browser storage. Use sample content and clear it with the demo reset. |
| Real CloudTrail exports and supplied findings | Restricted | Operator-controlled file or browser input, transient request and process memory. Keep outside source control and CI. The app has no managed original-export archive. |
| Normalized evidence, identity fields, IPs, account IDs, graph, scores and audit decisions | Restricted | Local SQLite and API responses. Apply workstation access and backup policies. Hashes and identifiers can still expose operational context. |
| Access keys and session tokens encountered in exports | Secret | May appear in original input. Selected credential IDs used for correlation remain transient. Tokens and secret keys are excluded from normalized persistence. |
| Source, CI configuration, dependency pins and SBOM | Integrity-critical | GitHub and build artifacts. Protect changes with review and check gates. Review artifacts before redistribution. |
| GitHub tokens, signing material and future connector credentials | Secret | Keep in the relevant platform’s credential store. Never include them in docs, fixtures, logs or public security reports. |

The app has no retention scheduler or app-managed encryption at rest. The operator is responsible for retention, secure disposal, and backups of production-like exports and local databases. GitHub artifact retention is defined per workflow.
