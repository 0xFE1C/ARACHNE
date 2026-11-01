# Getting Started

From an empty machine to your first evidence-backed scan report. Every command below
was executed against the shipped build during the fresh-install validation.

```mermaid
flowchart LR
    A["1. Install"] --> B["2. Migrate DB"]
    B --> C["3. Plan (dry-run)"]
    C --> D["4. Attest + scan"]
    D --> E["5. Report"]
    E --> F["6. Serve API/UI"]
```

## 0. Prerequisites

- **Python 3.11+** (3.12+ recommended)
- That is it — the default install is SQLite-based and dependency-light. Postgres,
  container images and PDF rendering are optional extras.

## 1. Install

From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
arachne --version        # → 0.1.0
```

Optional extras:

```bash
pip install -e ".[postgres]"        # Postgres driver (deployments)
pip install -e ".[dev,postgres]"    # everything for development
```

## 2. Migrate the database

ARACHNE never touches a schema implicitly — you apply migrations explicitly:

```bash
arachne db upgrade        # apply migrations to a fresh SQLite file
arachne db current        # confirm: up to date
```

A fresh install starts with an **empty database**: no scans, no findings, no users.
All state you will ever see is produced by your own runs.

## 3. Plan a scan (zero requests)

Every scan starts as a plan you can read before anything is contacted:

```bash
arachne scan --target examples/targets/lab-fixture.yaml --dry-run
```

The plan prints the compiled scope (deny-by-default), the authorization attestation it
found, every check that will run with its proof level, and the estimated request
count. **Nothing leaves your machine during a dry-run.**

## 4. Run a scan

```bash
arachne scan --target examples/targets/lab-fixture.yaml
```

What you get: a step-by-step pipeline (recon → discovery → checks → analysis →
correlation), findings with captured evidence, and a sealed, hash-chained audit trail
(`integrity.sealed`).

Notes on authorization:

- **Passive OSINT** (M1 third-party providers) is **off by default** — nothing
  contacts Shodan/Censys/etc. unless `ARACHNE_OSINT_ENABLED=true`.
- **Active checks** (anything beyond plain GETs — probing, fuzzing, credential
  verification) require `--active-checks` **and** an authorization attestation in the
  target definition (see `examples/targets/lab-fixture.yaml` for the format).
- **Proof levels** escalate only when explicitly enabled: L1 read-only → L2
  out-of-band → L3 one-shot command → L4 minimal state change (auto-restored). See
  [architecture.md](architecture.md) for the ladder.

## 5. Read the results

```bash
arachne report --scan 1 --format md --output report.md
arachne report --scan 1 --format html --output report.html
```

Reports carry the finding, the captured evidence (redacted at capture time), severity
with rationale, and remediation guidance. Use `--format json` for machine consumption.

## 6. Serve the API and web UI

```bash
arachne serve --host 127.0.0.1 --port 8080
curl http://127.0.0.1:8080/health       # → {"status":"ok", ...}
```

With no API keys configured the API is **closed by default**: health and OpenAPI are
public, everything else refuses. To enable it, set keys in `label:role:secret` form
(`;`-separated; roles: `viewer`, `scanner`, `admin`):

```bash
export ARACHNE_API_KEYS='admin:admin:<random-secret>;ci:scanner:<other-secret>'
arachne serve --host 127.0.0.1 --port 8080
```

> A non-loopback bind requires TLS unless you explicitly pass `--insecure`; put the
> certificate in `ARACHNE_API_TLS_CERT` / `ARACHNE_API_TLS_KEY`. For file-based keys
> use `ARACHNE_API_KEYS_FILE` (one per line).

Open `http://127.0.0.1:8080/` in a browser for the web UI: sign in with one of the
`secret` values (the UI keeps a session cookie, `ARACHNE_API_SESSION_MAX_AGE` seconds).
For scripts, send the key as the `X-API-Key` header, or use the generated clients in
`clients/`.

## 7. Optional: run with Docker

```bash
docker compose -f docker/docker-compose.yml up --build     # api + worker + db
```

The compose stack runs an **offline demo scan** on first start and reads its secrets
from files — see the [operator guide §Docker](operator-guide.md) and
`docker/docker-compose.prod.yml` for the hardened variant.

## 8. Optional: Postgres instead of SQLite

```bash
pip install -e ".[postgres]"
export ARACHNE_DATABASE_URL='postgresql+psycopg://user:pass@host:5432/arachne'
arachne db upgrade
```

Postgres is required for distributed mode (the scan-fleet work queue) and recommended
for any multi-user deployment.

## Configuration

Every environment variable is documented in the
[Operator Guide §12](operator-guide.md) and templated in
[`.env.example`](../.env.example). The ones that matter on day one:

| Variable | Default | Meaning |
|---|---|---|
| `ARACHNE_DATABASE_URL` | `sqlite:///arachne.db` | Where state lives |
| `ARACHNE_OSINT_ENABLED` | `false` | Third-party OSINT providers |
| `ARACHNE_AI_ENGINE` | `heuristic` | `heuristic`, `ai`, or `hybrid` |
| `ARACHNE_API_KEYS` | *(unset = closed)* | Comma-separated API keys |

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `arachne: command not found` | The venv is not active: `. .venv/bin/activate` (or call `.venv/bin/arachne`) |
| `ModuleNotFoundError: No module named 'arachne'` | The project was moved after install: re-run `pip install -e .` from the repository root |
| `arachne scan` refuses to start | Live scans need a **complete, unexpired attestation** in the target file covering every target; `--dry-run` shows what the plan found |
| Active checks are "withheld" | Active checks (M2, probing) need `--active-checks` **and** an authorization attestation — by design |
| Nothing contacts third parties | Passive OSINT is off by default: `ARACHNE_OSINT_ENABLED=true` plus `ARACHNE_OSINT_PROVIDERS` |
| Port 8080 already in use | `arachne serve --port 8090` (or check `ARACHNE_API_PORT`) |
| API returns 404/403 on every route | No keys configured (closed by default): set `ARACHNE_API_KEYS` |
| TLS error on a non-loopback bind | Configure `ARACHNE_API_TLS_CERT`/`_KEY`, or test with `--insecure` locally |
| Where is my database? | `sqlite:///arachne.db` in the working directory unless `ARACHNE_DATABASE_URL` says otherwise (`arachne info` prints the effective URL) |
| `verify-chain` reports a break | Something modified the audit log after the fact — the tamper-evidence working as intended; inspect before trusting the affected scan |

Still stuck? Run `arachne info` (effective configuration, no secrets), then check
[operator-guide.md](operator-guide.md) for the exact variable.

## Where to next

- [architecture.md](architecture.md) — how the pipeline, safety gates and proof ladder
  actually work
- [operator-guide.md](operator-guide.md) — every variable, every command, runbooks
- [ci-integration.md](ci-integration.md) — wire ARACHNE as a CI gate
