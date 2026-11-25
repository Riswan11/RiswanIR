# CloudTrail normalization

TrailHound accepts individual events, plain arrays, CloudTrail log exports with a `Records` array, and lookup exports with an `Events` array. The AWS normalizer is separate from detection. AWS-shaped event sources can represent previously unseen services and operations.

- Event IDs, timestamps and operation names are required. Missing source, version and category remain compatible with older exports. Supplied sources and versions must have valid syntax. Supported CloudTrail categories are Management, Data, NetworkActivity and Insight. Insights can have no caller or ordinary API outcome.
- Normalized evidence records UTC time, AWS service and category, identity and session metadata, outcome, network and TLS data, resources, and request and shared event IDs when available.
- Normalized evidence summarizes request and response objects and additional event data using allowlisted fields. It omits session tokens, secret keys and arbitrary payload values. Raw error text is replaced with a redaction marker. The separate [raw evidence store](evidence-custody.md) may still hold those values. Treat selected metadata and notes as sensitive.
- Identical records under the same event ID deduplicate regardless of JSON key order. Conflicting copies are excluded from the batch result and reported. Events with different IDs stay distinct even when they share a request in two accounts.
- The batch normalizer returns ordered records and indexed field/code issues. The investigation API rejects invalid submissions atomically and returns a bounded error summary without raw input values.
- Failed calls are visible in evidence for the same existing investigation scope and cannot issue credentials or trigger success-based rules and recommendations. Events without a matching ARN or an existing credential link can normalize successfully without appearing in a principal-scoped investigation.

[AWS CloudTrail record fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) · [AWS identity and session fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
