# Schema versioning and historical reports

The registry distinguishes the OCSF schema version, per-source mapping versions, and per-namespace extension versions. Validation checks type UID, required context, registered extensions and supported version combinations.

New reports store canonical events in an additive JSON field with a separate custody digest. Older reports are projected on request as `legacy_projection`, without rewriting SQLite rows or changing evidence hashes. Historical evidence that lacks raw references stays unlinked. New responses use `stored`. Revisions rebuild from retained raw values and use the current mapping.

Register changed semantics as a new version. Preserve old readers and validators, add legacy fixtures, and make backfills explicit. Verify lineage and integrity before switching defaults.
