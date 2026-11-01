# Docker packaging (F-07-04)

One image, three roles, one compose file. Build from the **project root** (`code/`):

```bash
docker build -f docker/Dockerfile -t arachne:dev .
```

## Demo stack — `docker compose up`

```bash
cd code
# The stack ships no credentials (REQ-OPS-006): supply your own first.
cat >> .env <<'EOF'
POSTGRES_PASSWORD=<random value: openssl rand -hex 24>
ARACHNE_API_KEYS=ops-admin:admin:<random value: openssl rand -hex 32>
EOF
docker compose -f docker/docker-compose.yml up --build
```

Brings up, in dependency order:

| Service | What it does |
|---|---|
| `db` | Postgres 16; the evidence store lives on the `pgdata` volume. |
| `migrate` | one-shot `arachne db upgrade` (idempotent). |
| `scan` | one-shot **end-to-end heuristic scan** of the bundled offline target, then renders `demo-report.md` and `demo-report.html` into the `reports` volume. |
| `api` | REST API + web UI on <http://127.0.0.1:8080> (`/health`, `/docs`). |
| `worker` | `arachne schedule run` every 60 s (recurring scans). |

The demo scan needs **no network**: `ARACHNE_HTTP_FIXTURES` / `ARACHNE_OSINT_FIXTURES`
replay recorded responses (`docker/demo/`), so a disconnected host still produces findings
and reports. Read the result with:

```bash
docker compose -f docker/docker-compose.yml run --rm scan cat /reports/demo-report.md
# or attach the api and browse http://127.0.0.1:8080
```

The API keys are whatever you put in `ARACHNE_API_KEYS` (the format is
`label:role:secret[:project]`, one or more entries separated by `;`). Use the key you
generated above:

```bash
curl -H "X-API-Key: $ARACHNE_KEY" http://127.0.0.1:8080/api/v1/scans
```

Nothing in this repository contains a working credential: `python -m
arachne.tools.credentials_gate` is the CI gate that enforces it, and the compose file uses
compose's required-variable syntax ( `${VAR:?message}` ) so a missing value is a startup
error rather than a fallback to a value everyone can read.

## Production overlay — secrets, not environment

```bash
cd code/docker
mkdir -p secrets
printf '%s' "$(openssl rand -hex 24)" > secrets/postgres_password.txt
printf 'ops-admin:admin:%s\nops-viewer:viewer:%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > secrets/api_keys.txt

cd ..
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml up -d
```

The overlay mounts both files as Docker secrets. ARACHNE reads the API keys from
`ARACHNE_API_KEYS_FILE` and the database password from `ARACHNE_DATABASE_PASSWORD_FILE`
(the settings layer injects it into the URL), so neither value appears in the container
environment or in `docker inspect`. `docker/secrets/*.example` documents the formats; real
files are git-ignored.

TLS is **on by default** (`ARACHNE_API_REQUIRE_TLS=true` in the overlay). Either set
`ARACHNE_API_TLS_CERT`/`ARACHNE_API_TLS_KEY`, or terminate TLS at a proxy in front of the
API — the demo service passes `--insecure` explicitly because it publishes a loopback port.

## Volumes

| Volume | Contents |
|---|---|
| `pgdata` | Postgres data directory. |
| `reports` | Rendered demo reports (`/reports`). |
| `feeds` | Normalised CVE/EPSS artefacts (`/app/feeds`), shared by `api`/`worker`/`scan`. |
| `worker-data` | Scheduler state (`/data/scheduler.json`). |

## Plugins inside the image

The image ships `hatchling`/`setuptools`, so an offline install from a mounted path works:

```bash
docker compose -f docker/docker-compose.yml exec api \
  arachne plugin install /plugins/my_plugin --no-build-isolation
```

A git URL needs outbound network at install time (the clone is the point). Restart `api`
and `worker` afterwards: entry-point discovery happens at process start.

## Lab profile (Phase 0 fixture)

```bash
docker compose --profile lab up
```

DVWA (`127.0.0.1:8081`), Juice Shop (`127.0.0.1:3000`), a misconfigured Nginx
(`127.0.0.1:8080`) and a weak-TLS endpoint (`127.0.0.1:8443`), plus MySQL, Redis and VNC —
all bound to loopback only. Never expose these.
## Kubernetes: the Helm chart

Compose is the single-node path. For a clustered deployment use the Helm chart
(`deploy/helm/arachne`, operator guide §30): the API at 2 replicas with a disruption
budget, the agent pool, Postgres as a StatefulSet, and the migration Job as a
pre-install/pre-upgrade hook. Like the compose file, the chart ships **no credentials**
and fails the install without them:

```bash
helm install arachne deploy/helm/arachne \
  --set postgres.auth.password="$(openssl rand -hex 24)" \
  --set api.auth.apiKeys="ops-admin:admin:$(openssl rand -hex 32)"
```

Verify a released image before deploying it (`cosign verify`, release notes /
operator guide §31) — the digest is what the release pipeline signed, not the tag.
