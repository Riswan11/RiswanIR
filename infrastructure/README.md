# Infrastructure

The application currently runs as a local Python process with SQLite. GitHub Actions runs the test suite. The separate portfolio demo uses static hosting and synthetic data. This directory is reserved for infrastructure configuration when the application gains a hosted deployment.

Build the local tool image with `docker build -t riswan-ir .`. The image runs as a non-root user.
Mount a writable workspace to persist the database. The default browser service binds to loopback
inside the container. Use the native Python launcher for ordinary desktop browser access.
For forensic tooling, use `--entrypoint riswan-ir-evidence` and mount the evidence database.
The service identifier for telemetry is `riswan-ir` via `OTEL_SERVICE_NAME`. The image does
not add an exporter or a hosted deployment.
