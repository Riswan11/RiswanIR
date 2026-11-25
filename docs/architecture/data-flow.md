# Investigation data flow

1. The client posts a title, starting ARN, and CloudTrail records to the investigation API. The Host policy, request parsing, and Pydantic validation run before analysis. Supported forms include a plain array, a log export with Records, and a lookup export with Events.
2. Normalization selects identifiers, event time, operation, caller, target, and available IP, user agent, region and account context. Credential identifiers are used internally. The report omits raw payloads, session tokens and secret access keys.
3. Normalization sorts events by UTC time, deduplicates identical records, and reports conflicting IDs. Correlation includes matching successful and failed calls. A successful recorded issuance can link later calls when existing session constraints agree. Only successful calls contribute to scoring and recommendations.
4. Sealing hashes each canonical normalized item and its correlation fields. Detection cites evidence IDs. Graph projection connects actors, targets and downstream events. The advisory may cite access key creation.
5. SQLite persists the report as JSON. Reads hydrate analyst reviews, the advisory decision and related reviewed cases. The API can return the full report, evidence, graph, or recent investigation summaries.
6. Feedback appends a review row. A unique key permits one stored advisory decision per case. Approval records the analyst's input without calling AWS.

The operator retains the source export. A hash supports comparison against a trusted prior digest. The application neither verifies export authenticity nor automatically rechecks stored digests on read.

[Data flow diagram](diagrams/data-flow.md) · [Data classification](../security/data-classification.md)
