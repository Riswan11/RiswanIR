# Contributing

Use Python 3.11 or later. Follow the [test setup](README.md#tests) to install the test dependencies and run the coverage gate. Try the built-in sample with `python server.py`.

Keep CloudTrail fixtures synthetic or publicly documented. Place changes in the module that owns the behavior and cover changed investigation logic with a focused regression test. See the [architecture guide](docs/architecture/README.md) for package boundaries.
