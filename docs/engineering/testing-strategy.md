# Testing strategy

The primary framework is pytest. Unit tests exercise models, parsing, timestamps, normalization, rules, graph edges, similarity, advisories and evidence hashing. Integration tests exercise the WSGI API and SQLite, including write rollback, foreign keys, legacy reports and the investigation-to-decision workflow. Security tests cover request limits, Host validation, literal handling of untrusted input and evidence-digest comparison.

Tests use synthetic CloudTrail fixtures, fixed metadata where needed, temporary SQLite databases and an in-process WSGI client. They need no AWS credentials or network once dependencies are installed. Browser interaction testing and production load testing are separate work.

Run from the repository root.

```sh
python -m pip install ".[test]"
python -m pytest tests/ -v --cov=riswan_ir --cov-report=term-missing --cov-fail-under=90
```

Overall branch-inclusive coverage must reach 90%. Add focused regression tests for domain or transport behavior changes, and include a compatibility test when a change affects stored reports or REST payloads. [CI strategy](ci-cd-strategy.md)
