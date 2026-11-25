# CloudTrail mapping

Mapping `1.0.0` targets OCSF `1.6.0`. Type UID equals class UID multiplied by 100 plus activity ID.

| CloudTrail operation | Required context | Class | Activity |
| --- | --- | --- | --- |
| ConsoleLogin | Sign-in service and observed user | Authentication 3002 | 1 Logon |
| AssumeRole and federation variants | STS, actor, IP | API Activity 6003 | 1 Create |
| CreateUser | IAM and named target user | Account Change 3001 | 1 Create |
| CreateAccessKey | IAM, actor, IP | API Activity 6003 | 1 Create |
| AttachUserPolicy | IAM and named target user | Account Change 3001 | 7 Attach Policy |
| AttachUserPolicy without target user | IAM, actor, IP | API Activity 6003 | 3 Update |
| GetObject | S3, actor, IP | API Activity 6003 | 2 Read |
| PutObject | S3, actor, IP | API Activity 6003 | 0 Unknown |
| RunInstances | EC2, actor, IP | API Activity 6003 | 1 Create |
| AuthorizeSecurityGroupIngress | EC2, actor, IP | API Activity 6003 | 3 Update |
| StopLogging | CloudTrail, actor, IP | API Activity 6003 | 3 Update |
| Other explicit AWS API calls | Service, actor, IP | API Activity 6003 | 0 Unknown |
| Unsupported type or missing class context | Base fields present | Base Event 0 | 0 Unknown |

CreateAccessKey creates a credential. PutObject can create or replace an object. AttachUserPolicy uses the dedicated account-change activity when the target is known. [API Activity](https://github.com/ocsf/ocsf-schema/blob/1.6.0/events/application/api_activity.json) · [Authentication](https://github.com/ocsf/ocsf-schema/blob/1.6.0/events/iam/authentication.json) · [Account Change](https://github.com/ocsf/ocsf-schema/blob/1.6.0/events/iam/account_change.json)

Export time is UTC epoch milliseconds. Outcomes are 0 Unknown, 1 Success, and 2 Failure. Source severity is unknown and remains separate from investigation risk scores. Non-IP source labels and provider-specific context use the allowlisted extension. [Base Event fields](https://github.com/ocsf/ocsf-schema/blob/1.6.0/events/base_event.json)
