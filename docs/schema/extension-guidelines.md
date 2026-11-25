# Provider extension guidelines

Register a versioned source mapping against a supported schema. Register extensions under unique namespaces with typed contracts that forbid extra fields. Review fields for sensitivity and test semantics, version and rejection behavior.

CloudTrail canonical exports retain selected event, request, account, VPC and session metadata. They omit raw payloads, tokens and arbitrary nested values. Unmapped provider attributes remain recoverable from the restricted forensic archive under its redaction and retention policies. Invalid fields and unsupported versions produce stable issue codes without echoing input values or field names.
