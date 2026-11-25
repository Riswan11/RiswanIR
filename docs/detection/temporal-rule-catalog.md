# Temporal AWS rules

Every scenario requires failure or success as configured, a strictly chronological window, and graph-backed linkage across stages. A complete match supports a hypothesis for review. These signals cannot establish intent, prove theft or transfer, or verify that a change was unauthorized.

| Rule | Prerequisites and evidence | Common legitimate explanation |
| --- | --- | --- |
| SF-CORR-AWS-001 | Successful assumption of an inventoried privileged role, evidenced credential usage for access-key creation, then logging disruption in that lineage. | Approved break-glass maintenance. |
| SF-CORR-AWS-002 | Access-key creation, attributable use of the issued key, then assumption of an inventoried privileged role. | Approved key rotation followed by an administrative workflow. |
| SF-CORR-AWS-003 | Cross-account STS assumption, authorized directional correlation scope, and evidenced use of issued credentials for destination IAM activity. | Centralized account administration. |
| SF-CORR-AWS-004 | Administrator-policy attachment finding and later access-key creation attributed to the same identity. | Onboarding or permission maintenance. |
| SF-CORR-AWS-005 | Logging stopped or deleted and later access to an inventoried sensitive S3 resource from the same session lineage. | Concurrent logging maintenance and batch processing. |
| SF-CORR-AWS-006 | Two sensitive reads and a subsequent anomalous-network S3 read finding on the same scoped resource and session. | Backup or egress-network changes. |
| SF-CORR-AWS-007 | Three failed console sign-ins then a successful one for the same attributed identity. | Incorrect credentials or user recovery. |
| SF-CORR-AWS-008 | An STS assumption followed by an evidenced chained STS assumption from an unexpected network according to inventory. | Intended role chaining from a changed corporate network. |
| SF-CORR-AWS-009 | Administrator-policy attachment and unexpected production instance creation findings attributed to the same identity. | Approved provisioning from a new network. |
| SF-CORR-AWS-010 | Public bucket-policy grant finding followed by a successful object read in the same session against the same resource. | Approved publisher testing a policy change. |

The [scenario matrix](../../tests/integration/test_temporal_correlation.py) tests a complete incident and a missing-stage negative for each rule. Additional tests check time windows, cross-account policy, graph linkage, and archive integrity. ATT&CK mappings describe possible activity and are limited to applicable techniques. [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) · [Brute Force](https://attack.mitre.org/techniques/T1110/) · [Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) · [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002/)
