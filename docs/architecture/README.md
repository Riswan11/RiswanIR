# Architecture

SentinelForge is a modular monolith. A single Python process serves the local interface and API, and SQLite persists investigations and analyst decisions.

| Area | Responsibility |
| --- | --- |
| `api`, `frontend`, `security` | HTTP routing, browser assets, and the loopback Host policy |
| `ingestion`, `normalization` | Decode exports and extract a consistent evidence shape |
| `investigation`, `evidence` | Trace credential use, hash evidence, and assemble the report |
| `detection`, `knowledge_graph`, `response` | Score evidence, build graph edges, and generate analyst advisories |
| `storage`, `memory` | Persist cases and rank related reviewed investigations |
| `core` | Shared validation, time handling, and errors |

The API passes submissions to storage, which runs the investigation and persists the resulting report. The investigation modules work on ordinary Python data and can run without HTTP or SQLite. The storage layer delegates similarity ranking to memory.

Add a `connectors` package when the first external evidence source lands. A connector should hand records to ingestion. Add an `agents` package if model-based planning is introduced. It should orchestrate existing investigation capabilities.
