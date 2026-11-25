# Trust boundaries

| Boundary | Entry points and assets | Trust assumption and control |
| --- | --- | --- |
| TB-01 Operator-managed telemetry to app | JSON paste, API submission, CloudTrail export, starting ARN | Treat exports as untrusted. Validate structure and normalize selected fields. Export authenticity remains external. |
| TB-02 Browser or local process to HTTP | UI, GET routes, creation, review and decision routes | Loopback HTTP and Host allowlist reduce remote exposure. The workstation and any process able to reach the service are trusted for operator access. |
| TB-03 App process to OS and storage | SQLite file, environment settings, DB path, logs and backups | The process inherits local account privileges. Filesystem ownership and permissions are external safeguards. SQLite constraints protect normal app writes. |
| TB-04 Contribution to GitHub workflows and releases | Pull requests, workflow scripts, dependencies, artifacts, branch settings | Treat contributor code and dependency inputs as untrusted. Review changes and use scoped permissions, pinned tools and required checks. |
| TB-05 Public demo to visitor browser | Synthetic case assets, demo interactions and local browser notes | Public read access is intentional. Storage is browser-local. The demo has no connection to the investigation database. |

Future authenticated tenancy, model-provider calls, connector credentials, and remediation execution each introduce a new trust boundary. Update this inventory before enabling any of them.

[System context diagram](../architecture/diagrams/system-context.md) · [STRIDE threats](threat-model.md)
