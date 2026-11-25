# Evidence custody and forensic export

When creating a case, the application stages source records before normalization in the same transaction as the report. A rejected investigation rolls back its raw records and receipts. Raw storage preserves each parsed record's original JSON values using canonical JSON. It does not preserve the container file, original whitespace, property order, duplicate properties, or transport bytes.

SHA-256 addresses deduplicated raw records. Each submitted occurrence gets a receipt tied to its investigation and position, including identical records submitted in different cases. The optional request-level provenance object accepts source location, collection method, collection time and collector ID. The receipt also records the provider, service, event ID, AWS account and region when present, observed timestamp, and ingestion time. Collection labels are operator assertions.

Normalized evidence retains its report-local event ID and adds a stable reference to the raw record. An independently hashed normalized record and a transformation row bind that reference to the raw digest, normalization version, schema version, and existing starting-principal configuration. The custody log records ingestion, normalization, verification, export preparation and expiration. Ingestion and transformation entries anchor ordered provenance and transformation manifests. Keep historical source revisions if a prior normalization version must be rerun.

SQLite adds the evidence tables on startup and leaves existing case rows intact. Cases created before this feature still open in the UI. Their original raw records and custody anchors were never stored, so forensic verification and export report them as unavailable.

## Local commands

Install the project before using the evidence CLI. Use the same database path as the server.

```sh
sentinelforge-evidence --db sentinelforge.sqlite3 verify INVESTIGATION_ID
sentinelforge-evidence --db sentinelforge.sqlite3 export INVESTIGATION_ID ../forensic-export.json
sentinelforge-evidence --db sentinelforge.sqlite3 expire --days 90 --confirm
```

Export verifies the case before preparing the bundle. The bundle includes original records, normalized evidence and findings, provenance receipts in submission order, transformations, and custody records. It can contain secrets. The command creates a new output file and prints status only. Store exports outside repositories and shared folders. New POSIX database and export files use owner-only permissions. Existing databases and Windows files depend on workstation permissions or inherited ACLs.

The default is indefinite retention. Expiration is an explicit operator action and uses the newest ingestion receipt for each deduplicated record. It removes only eligible raw payloads and keeps the hash, provenance and custody history. Verification reports expired payloads separately, and exports mark them with a null record. A later valid submission can retain the same content again. Logical deletion does not guarantee secure erasure from SQLite journals, backups or existing exports.

## Integrity boundary

Verification can detect changes to retained payloads, normalized records and linked metadata when the corresponding digests and custody anchors remain trustworthy. The log is append-only through application operations, with deliberate expiration of raw payloads through the retention command. Local timestamps and actor roles are audit context. A privileged database writer can alter data and recompute its hashes or remove the end of the log. The app does not verify CloudTrail source authenticity or use independent time, external anchoring, signed identities or immutable storage.
