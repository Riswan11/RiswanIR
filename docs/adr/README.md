# Architecture decision records

An ADR explains a significant decision and the trade-offs it accepts. Use the [template](template.md) for new records. Allocate the next number and keep accepted ADRs as historical records. Record material reversals in a new ADR and link the superseding decision in both directions.

- [0001 Modular monolith](0001-modular-monolith.md)
- [0002 Python backend](0002-python-backend.md)
- [0003 Pydantic domain models](0003-pydantic-models.md)
- [0004 SQLite persistence](0004-sqlite-persistence.md)
- [0005 Evidence-first reports](0005-evidence-first-design.md)
- [0006 Deterministic detection](0006-deterministic-detection.md)
- [0007 Human-in-the-loop response](0007-human-in-the-loop.md)
- [0008 DevSecOps quality gates](0008-devsecops-quality-gates.md)
- [0009 Read-only AWS collection](0009-aws-read-only-collection.md)
- [0010 Evidence-backed identity and session correlation](0010-identity-session-correlation.md)
- [0011 OCSF-aligned canonical events](0011-ocsf-aligned-events.md)

- [0012. Evaluate versioned rules over canonical events](0012-context-aware-detection.md)

- [0013. Store versioned investigation graph snapshots in SQLite](0013-security-knowledge-graph.md)

- [0014. Correlate event-time sequences within case revisions](0014-temporal-correlation.md)

- [0015. Preserve independent risk and confidence assessments](0015-risk-assessment-history.md)
