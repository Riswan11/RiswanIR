# AWS detection rule catalog

The bundled rules evaluate successful canonical events. Policy-dependent rules require local inventory. Severity is assigned by each rule and remains independent of the legacy triage score.

| Rule | Finding | Severity | ATT&CK |
| --- | --- | --- | --- |
| `SF-AWS-IAM-001` | Suspicious cross-account role assumption | high | T1078.004 |
| `SF-AWS-IAM-002` | Unexpected access key creation | high | T1098.001 |
| `SF-AWS-IAM-003` | Root account usage | high | — |
| `SF-AWS-IAM-004` | Unusual privileged session activity | high | T1078.004 |
| `SF-AWS-PRIV-001` | Administrator policy attachment | high | T1098.003 |
| `SF-AWS-PRIV-002` | Sensitive IAM policy modification | high | — |
| `SF-AWS-PRIV-003` | Sensitive role trust policy modification | high | — |
| `SF-AWS-PRIV-004` | Permissions boundary removal | high | — |
| `SF-AWS-DEF-001` | CloudTrail logging stopped | critical | T1562.008 |
| `SF-AWS-DEF-002` | CloudTrail trail deleted | critical | T1562.008 |
| `SF-AWS-DEF-003` | GuardDuty monitoring disabled | high | T1562.001 |
| `SF-AWS-DEF-004` | Production CloudTrail configuration changed | medium | — |
| `SF-AWS-DATA-001` | Repeated S3 reads from an unexpected network | medium | T1530 |
| `SF-AWS-DATA-002` | Sensitive S3 object access | high | T1530 |
| `SF-AWS-DATA-003` | Public S3 bucket policy grant | high | — |
| `SF-AWS-DATA-004` | Production encryption configuration changed | high | — |
| `SF-AWS-INFRA-001` | Unrestricted security group ingress | high | — |
| `SF-AWS-INFRA-002` | Production instance creation from an unexpected network | medium | T1578.002 |
| `SF-AWS-INFRA-003` | Sensitive security group modification | medium | — |
| `SF-AWS-INFRA-004` | Snapshot shared publicly or with another account | high | T1530 |

References include [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/), [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/), and [Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/).
