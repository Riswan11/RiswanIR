# Development and documentation guidelines

Keep domain logic independent of HTTP and SQLite. Validate at trust boundaries. Preserve REST serialization and legacy storage compatibility unless a reviewed change defines a migration. Use synthetic or publicly documented evidence in tests, examples and CI. [Component design](../architecture/component-design.md)

## Maintain architecture and security documentation

1. In the same pull request as a material change, update component responsibilities, dependency direction, relevant diagrams, and data-handling notes. Material changes include new entry points, persisted fields, permissions, dependencies, external calls, and decision authority.
2. Write an ADR for a consequential choice. Use the [template](../adr/template.md), add the ADR to the index, and link any superseded decision.
3. Review the change against STRIDE. Update the [trust boundaries](../security/trust-boundaries.md), existing controls, risk register and data classification where affected. Clearly mark proposed and implemented controls. Record an owner and review trigger for each new risk.
4. Ask the relevant maintainer to review implementation and documentation together. Confirm diagrams match the code, links resolve, and controls have corresponding implementation or verification. Include security impact and any exception in the PR.
5. Revisit open risks when an affected feature changes, after a relevant incident, and before expanding beyond trusted local operation. Keep stable risk IDs when updating assessments.

Handle details of suspected vulnerabilities through the private reporting process in [SECURITY.md](../../SECURITY.md).
