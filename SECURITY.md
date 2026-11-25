# Security policy

Report suspected vulnerabilities privately to security@riswanlabs.com. When private vulnerability reporting is enabled, use the repository’s **Security** tab. Include the affected version, impact, and a minimal reproduction using synthetic data. Keep credentials and real CloudTrail records out of reports and public issues.

See the [STRIDE threat model](docs/security/threat-model.md), [security controls](docs/security/security-controls.md), and [risk register](docs/security/risk-register.md).

## Scan findings and exceptions

Review the workflow artifacts and GitHub code scanning alerts. Track confirmed findings by advisory ID or rule ID, affected version or location, owner, and fix. Handle exposed credentials privately and revoke them before addressing repository history. Include redacted evidence in tracking records.

A high-severity exception requires an approved pull request identifying the finding, justification, compensating control, owner, and expiry date. Record the approval beside any narrowly scoped scanner suppression so maintainers can review and remove it when it expires. Critical findings and credential leaks are merge blockers.
