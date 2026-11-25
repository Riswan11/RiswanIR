# Technical debt and architectural limits

| Area | Current limitation | Revisit when |
| --- | --- | --- |
| Access and identity | The loopback service trusts reachable clients. Reviewer names are free text and records are not independently attributable. | Before shared or remote access |
| Availability and scale | The WSGI server processes one request at a time. Analysis runs synchronously and there is no durable work queue. | Before concurrent analysts or higher-volume intake |
| SQLite operations | File permissions, retention, backups and recovery are operator responsibilities. Shared deployment needs a persistence and migration strategy. | Before shared storage or explicit recovery objectives |
| Evidence custody | Local digests and a custody chain detect partial modifications. Reports lack source attestation, automatic verification on ordinary reads, and an independent anchor. Raw telemetry relies on workstation controls. | Before regulated or high-assurance evidence use |
| Correlation coverage | Collection is manual. Missing issuance or key IDs, identical timestamps and events outside the export can leave gaps. Failed calls are visible but do not expand the credential chain. | When adding a connector or expanding supported event sources |
| Scoring and memory | Fixed rules prioritize review and lack baselines. Similarity uses shared event types and the latest review from a bounded set. | Before larger datasets, model integration or more rigorous alert evaluation |
| Graph and UI | The graph is an edge projection in a report. UI tests exercise HTTP contracts without a browser-driven workflow suite. | Before interactive graph exploration or a larger frontend |
| Supply chain | Runtime dependencies resolve from ranges. Builds need access to external package and vulnerability feeds. | Before releases requiring reproducibility or stronger artifact provenance |
| Future trust boundaries | Tenancy, model calls, connector credentials and execution require separate authorization and security designs. | Before implementing the corresponding feature |

See the [risk register](../security/risk-register.md) for security ownership and treatment state.
