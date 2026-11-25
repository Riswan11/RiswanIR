# System context

| Actor or system | Interface | Data exchanged |
| --- | --- | --- |
| Analyst | Local UI or REST API | Export, principal ARN, evidence, score, notes and decisions |
| AWS CloudTrail | Operator-managed export | CloudTrail log, lookup output, or record array |
| AWS CloudTrail, S3 and STS | Optional local boto3 collector over TLS | Management or trail records and temporary session credentials |
| Local operating system | Process configuration and filesystem | Port, database path, stored reports, operational logs |
| Demo visitor | Public static site and browser storage | Synthetic cases and simulated decisions |
| Maintainer and GitHub | Git, pull requests and workflows | Source, synthetic fixtures, CI logs and reports |

The analyst can supply an export or run the local collector with an authorized temporary AWS identity. The local processes and database operate under the workstation account's security context. The public demo has no connection to the local backend. GitHub Actions receives repository content and synthetic fixtures.

[System context diagram](diagrams/system-context.md) · [Trust boundaries](../security/trust-boundaries.md)
