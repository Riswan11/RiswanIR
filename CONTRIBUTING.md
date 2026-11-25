# Contributing

Use Python 3.11 or later. Follow the [test setup](README.md#tests) to install the test dependencies and run the coverage gate. Try the built-in sample with `python server.py`.

Keep CloudTrail fixtures synthetic or publicly documented. Place changes in the module that owns the behavior and cover changed investigation logic with a focused regression test. See the [architecture guide](docs/architecture/README.md) for package boundaries.

For changes to data handling, APIs, deployment, permissions, or dependencies, update the relevant diagrams, decisions, and threat-model entries in the same pull request. Follow the [documentation review process](docs/engineering/development-guidelines.md#maintain-architecture-and-security-documentation).
