FROM python:3.11-slim
WORKDIR /workspace
COPY pyproject.toml README.md /build/
COPY src /build/src
RUN python -m pip install --no-cache-dir /build
USER 10001:10001
ENV OTEL_SERVICE_NAME=riswan-ir RISWAN_IR_MODE=local
ENTRYPOINT ["riswan-ir"]
