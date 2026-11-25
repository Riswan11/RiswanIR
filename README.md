# SentinelForge

SentinelForge is a local analyst workspace for investigating suspicious AWS activity from supplied CloudTrail records. It links triage findings to evidence, reconstructs a timeline, and preserves analyst decisions for future investigations.


Context-aware detection evaluates 20 AWS rules over correlated evidence. See the [detection guide](docs/detection/overview.md) for local inventory and replay. The [security graph guide](docs/architecture/security-knowledge-graph.md) documents ontology, provenance, and traversal endpoints. See [temporal correlation](docs/detection/temporal-correlation.md) for multi-event incidents and replay.
## Run locally

Requires Python 3.11 or newer. From the repository root, run:

```sh
python -m pip install .
python server.py
```

Open [the analyst workspace](http://127.0.0.1:8000). Select **Load sample**, then **Investigate** to run a synthetic incident. Review the evidence and graph, enter a reviewer name, and save a disposition. Submit the sample again to see the earlier review in related investigations.

For your own data, paste a single CloudTrail event, a log with a top-level `Records` array, a `lookup-events` export with an `Events` array, or a plain array of records. Supply a starting ARN from `userIdentity.arn`. The API accepts an object with `title`, `principal`, and `records` at `POST /v1/investigations`. Store real exports outside the repository or in the ignored `local-data/` directory.

The local SQLite database defaults to `sentinelforge.sqlite3`. Set `SENTINELFORGE_DB` to choose a different file or `SENTINELFORGE_PORT` to change the port.

New investigations retain CloudTrail record values in local SQLite after redacting recognized credential secrets. Raw telemetry can contain other sensitive data. Keep the database, backups, and forensic exports under restricted workstation access. See [evidence custody, verification, and retention](docs/architecture/evidence-custody.md) for local commands.

For account-scoped CloudTrail Event History or S3 collection, use the local `sentinelforge-collect` CLI. See [AWS collection configuration and IAM guidance](docs/architecture/aws-collection.md).

Investigation reports include [identity and session correlation](docs/architecture/identity-correlation.md), with confidence, supporting evidence and a revision endpoint for late telemetry.

New investigations include [OCSF-aligned events](docs/schema/overview.md). Export them with `GET /v1/investigations/{id}/events`.

After installation, you can also start the app with `sentinelforge` or `python -m sentinelforge`. See the [architecture guide](docs/architecture/README.md) for the package layout.

## Investigation workflow

- Capture successful and failed calls in evidence. Only successful calls contribute to scoring, recommendations, or credential issuance links. Missing key IDs and equal recorded timestamps can leave gaps. See the [CloudTrail normalization contract](docs/architecture/cloudtrail-normalization.md).
- Produce an ordered timeline, hashed normalized evidence, and an identity–event–target graph.
- Score individual calls, repeated calls, and ordered events linked by credentials. Each rule cites the matched events. Scores indicate triage priority and require analyst interpretation. Evidence hashes help verify normalized record integrity. Source authenticity depends on the supplied export.
- Find previously reviewed investigations by shared event types. Keep review history and record one approval or rejection per advisory.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET, POST | `/v1/investigations` | List recent investigations or submit a finding |
| GET | `/v1/investigations/{id}` | Read the report and review history |
| GET | `/v1/investigations/{id}/evidence` | Read the evidence timeline |
| GET | `/v1/investigations/{id}/graph` | Read graph edges |
| POST | `/v1/investigations/{id}/feedback` | Save reviewer, disposition, and optional notes |
| POST | `/v1/investigations/{id}/actions/{action_id}/approve` | Record approval with a reviewer name |
| POST | `/v1/investigations/{id}/actions/{action_id}/reject` | Record rejection with a reviewer name |

This release is for single-user local testing. It uses Pydantic for validation and SQLite for persistence, accepts exported records or read-only AWS collection, and records advisory decisions only. Cloud remediation, authenticated multi-user access, and model-based planning are outside this release.

## Technical documentation

- [Architecture and diagrams](docs/architecture/README.md)
- [Architecture decision records](docs/adr/README.md)
- [STRIDE threat model](docs/security/threat-model.md), [trust boundaries](docs/security/trust-boundaries.md), [security controls](docs/security/security-controls.md), [risk register](docs/security/risk-register.md), and [data classification](docs/security/data-classification.md)
- [Testing strategy](docs/engineering/testing-strategy.md), [CI strategy](docs/engineering/ci-cd-strategy.md), [development guidelines](docs/engineering/development-guidelines.md), and [technical debt](docs/engineering/technical-debt.md)

## Tests

Install the test dependencies and run the full suite with branch coverage.

```sh
python -m pip install ".[test]"
python -m pytest tests/ -v --cov=sentinelforge --cov-report=term-missing --cov-fail-under=90
```

Run a single layer with `python -m pytest tests/unit`, `python -m pytest tests/integration`, or `python -m pytest tests/security`. Tests use synthetic CloudTrail events and temporary SQLite databases. The suite runs without AWS credentials or network access after installation.

## CI and security checks

Pull requests targeting `main` and pushes to `main` run the following checks. The security scans also rerun weekly to pick up newly disclosed vulnerabilities. Dependabot checks Python dependencies and GitHub Actions weekly.

| Required check | What it checks | Run artifact |
| --- | --- | --- |
| Tests | Pytest suite and 90% overall branch coverage gate on Python 3.11 | JUnit and coverage XML |
| Code quality | Ruff formatting and lint, Mypy, and actionlint | Job log |
| Security scans | Bandit medium-or-higher findings, pip-audit findings, Trivy high and critical findings, and Gitleaks history scan | JSON scan reports and resolved runtime requirements |
| CodeQL analysis | Python analysis, with high and critical findings blocking the check | SARIF and GitHub code scanning results |
| Generate SBOM | Syft inventory of installed runtime packages | CycloneDX JSON |

Open **Actions**, select the workflow run, and download its artifacts. Gitleaks redacts reported secrets. See [the security policy](SECURITY.md) for triage and exceptions.

To reproduce the Python checks locally:

```sh
python -m pip install ".[test,quality,security]"
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m bandit -r src -ll
```

GitHub branch protection requires pull requests and the five checks above. Workflow dependencies use full commit SHAs. The standalone scanner installer verifies release archive checksums.
