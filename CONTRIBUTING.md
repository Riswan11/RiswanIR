# Contributing

Use Python 3.11 or later. From the repository root run `python -m unittest discover -s tests -v` and try the built-in sample with `python server.py`.

Keep CloudTrail fixtures synthetic or publicly documented. Place changes in the module that owns the behavior and cover changed investigation logic with a focused regression test. See the [architecture guide](docs/architecture/README.md) for package boundaries.
