# SentinelForge

SentinelForge is a local analyst workspace for investigating suspicious AWS activity from supplied CloudTrail records. It links triage findings to evidence, reconstructs a timeline, and preserves analyst decisions for future investigations.

## Run locally

Requires Python 3.11 or newer. From the repository root, run:

```sh
python -m pip install .
python server.py
```

Open [the analyst workspace](http://127.0.0.1:8000). Select **Load sample**, then **Investigate** to run a synthetic incident. Review the evidence and graph, enter a reviewer name, and save a disposition. Submit the sample again to see the earlier review in related investigations.

For your own data, paste a CloudTrail log with a top-level `Records` array, a `lookup-events` export with an `Events` array, or a plain array of records. Supply a starting ARN from `userIdentity.arn`. The API accepts an object with `title`, `principal`, and `records` at `POST /v1/investigations`. Store real exports outside the repository or in the ignored `local-data/` directory.

The local SQLite database defaults to `sentinelforge.sqlite3`. Set `SENTINELFORGE_DB` to choose a different file or `SENTINELFORGE_PORT` to change the port.

After installation, you can also start the app with `sentinelforge` or `python -m sentinelforge`. See the [architecture guide](docs/architecture/README.md) for the package layout.

## Investigation workflow

- Match successful calls to the starting ARN. Follow subsequent calls by joining the access key ID returned by STS or IAM to the caller's access key ID, including across chained roles and accounts. Edges cite the issuance event. Missing key IDs and equal recorded timestamps can leave gaps. [AWS CloudTrail IAM and STS examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
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

This release is for single-user local testing. It uses Pydantic for validation and SQLite for persistence, accepts exported records, and records advisory decisions only. Live AWS collection, cloud remediation, authenticated multi-user access, and model-based planning are outside this release.

## Tests

```sh
python -m unittest discover -s tests -v
```
