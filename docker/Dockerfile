# ARACHNE container image (F-07-04).
#
# One image, three roles, selected by the compose command:
#
#   api       arachne serve --host 0.0.0.0 --port 8080 --insecure
#   worker    arachne schedule run (in a loop), or any other long-running CLI loop
#   migrate   arachne db upgrade  (a one-shot init container)
#
# The image is deliberately boring: no build tool-chain in the runtime layer beyond the
# Python package installers, an unprivileged user, and the evidence store on a volume.
# Postgres support is an extra (`.[postgres]`) so the default install stays slim.
#
# Build from the project root (code/):
#   docker build -f docker/Dockerfile -t arachne:dev .
#
# Plugin installs inside the container are offline-friendly: `hatchling`/`setuptools` are
# present, so `arachne plugin install <local-path> --no-build-isolation` works with no
# network. A git URL still needs network (the clone is the point).

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ARACHNE_PROJECT_ROOT=/app

WORKDIR /app

# Dependencies first so the layer caches across source changes.
COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
COPY docker/demo ./demo

RUN pip install --no-cache-dir ".[postgres]" \
    && pip install --no-cache-dir hatchling setuptools wheel

# Run as an unprivileged user; the evidence store and ingested feeds live on volumes.
RUN useradd --create-home --uid 10001 arachne \
    && mkdir -p /data /app/feeds /reports \
    && chown -R arachne:arachne /data /app /reports
USER arachne

VOLUME ["/data", "/app/feeds", "/reports"]

# The API listens on 8080; the CLI is the entry point for every role.
EXPOSE 8080
ENTRYPOINT ["arachne"]
CMD ["--help"]