# Detection testing

Run the normal coverage gate from the project root.

```bash
python -m pytest tests/ -v --cov=riswan_ir --cov-report=term-missing --cov-fail-under=90
```

The catalog test covers a positive, failed operation, and missing-context or missing-source scenario for every rule. Tests also cover trusted policy ingestion, prior relationships, count windows, time-limited exceptions, condition typing, suppression, SQLite replay, and the YAML trust boundary.

Run the bounded-case throughput benchmark with JUnit output to capture elapsed time and events per second.

```bash
python -m pytest tests/performance/ -v --junitxml=detection-benchmark.xml -o junit_family=xunit1
```

The benchmark evaluates 2,000 canonical events against the 20-rule registry and allows 10 seconds for the evaluation on a CI runner. It measures evaluation and serialization model construction, excluding CloudTrail normalization and SQLite. Rule loading is capped at 256 KB and 100 versions. Evaluation is capped at 2,000 events, 100 selected rules, and 4,000 findings or suppression/exception decisions. The case transaction fails if an evaluation exceeds a hard limit.
