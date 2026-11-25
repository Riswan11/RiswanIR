# Investigation data flow

1. The client posts a title, starting ARN, and CloudTrail records to the investigation API. The Host policy, request parsing, and Pydantic validation run before analysis. Supported forms include a plain array, a log export with Records, and a lookup export with Events.
2. Normalization selects identifiers, event time, operation, caller, target, and available IP, user agent, region and account context. Credential identifiers are used internally. The report omits raw payloads, session tokens and secret access keys.
3. Normalization sorts events by UTC time, deduplicates identical records, and reports conflicting IDs. Correlation includes matching successful and failed calls. A successful recorded issuance can link later calls when existing session constraints agree. Only successful calls contribute to scoring and recommendations.
4. Sealing hashes each normalized item and its link fields. The OCSF-aligned mapping derives canonical events for detection, correlation and graph generation. Findings cite evidence IDs, and advisories can reference access key creation. [Canonical schema](../schema/overview.md)
5. SQLite persists the report as JSON. Reads hydrate analyst reviews, the advisory decision and related reviewed cases. The API can return the full report, evidence, graph, or recent investigation summaries.
6. Feedback appends a review row. A unique key permits one stored advisory decision per case. Approval records the analyst's input without calling AWS.

Before normalization, the application stages the original record values separately from the report, then commits raw records, receipts, normalized evidence and custody entries together. The operator still retains the source export if file-level fidelity is needed. Forensic verification explicitly checks the retained digests and custody links. It does not authenticate the source export. [Evidence custody](evidence-custody.md)

[Data flow diagram](diagrams/data-flow.md) · [Data classification](../security/data-classification.md)
