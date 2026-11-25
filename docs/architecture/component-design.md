# Component design

The [entry point](../../src/sentinelforge/__main__.py) constructs the SQLite store and injects it into the WSGI application. Checkout launchers remain available in [server.py](../../server.py) and [forge.py](../../forge.py).

| Package | Responsibility | Internal dependencies |
| --- | --- | --- |
| frontend | Render reports and send analyst input | Same-origin REST contract |
| api | Route WSGI requests, validate input, serialize responses | security, core, models, frontend, injected store |
| security | Enforce the loopback Host policy | Standard library |
| core | Validate common fields, handle UTC, define shared errors | Standard library |
| ingestion | Unwrap log and lookup exports, decode nested event JSON | core |
| connectors | Select a source, verify the AWS account, and read bounded telemetry batches | boto3, botocore, collection models |
| models | Validate typed entities, enums and evidence references | core, ingestion |
| normalization | Select event fields and extract credential linkage fields | core, models |
| investigation | Correlate successful calls and assemble reports | core, models, normalization, evidence, detection, knowledge_graph, response |
| evidence | Hash canonical normalized evidence | models |
| detection | Match rules and compute triage scores | models |
| knowledge_graph | Project caller, target and credential-use edges | models |
| response | Recommend analyst review of access key creation | models |
| storage | Own SQL transactions, snapshots, reviews and decisions | core, models, investigation, memory |
| memory | Rank reviewed cases by shared event types | models |

Investigation code operates without HTTP or SQLite. Storage invokes analysis on case creation and calls memory during report hydration. Graph edges and risk assessments are projections of evidence. The collection orchestrator receives connector batches and uses the ingestion pipeline to persist evidence and progress. A future planner would orchestrate existing functions through a separately reviewed tool boundary.

[Component diagram](diagrams/components.md)
