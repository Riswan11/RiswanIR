# Infrastructure

TrailHound runs locally as a Python process backed by SQLite. GitHub Actions runs the CI
and security workflows. The separate portfolio demo serves synthetic data through GitHub
Pages. The application currently has no container image, hosted backend deployment
configuration, or telemetry exporter service.
