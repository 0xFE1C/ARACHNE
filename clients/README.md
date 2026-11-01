# Generated API clients (REQ-ECOS-002)

Official Python and TypeScript clients for the ARACHNE REST API, **generated from the
application's own OpenAPI schema** and contract-tested in CI. Do not edit them by hand:
edit the routes (or this repo's generator) and regenerate.

```
clients/
├── python/arachne_client/        # importable package (needs `httpx`, already a dependency)
│   ├── __init__.py               # generated re-exports
│   └── client.py                 # generated: models (TypedDict) + Client
└── typescript/src/
    ├── types.ts                  # generated: one interface per components.schemas entry
    └── client.ts                 # generated: ArachneClient
```

At the time of writing the schema has **57 paths / 74 operations / 32 schemas**, and every
operation has exactly one method in each client. Those numbers move as the API grows; only
the parity (one client method per documented operation) is the contract, and `--check` keeps
the two in step.

## Regenerating

```bash
python -m arachne.tools.sdkgen            # write the clients (deterministic; commit the diff)
python -m arachne.tools.sdkgen --check    # CI drift gate: exit 1 and name every drifted file
python -m arachne.tools.sdkgen --out DIR  # write below DIR instead of this tree
```

The generator reads the schema from the live app factory
(`arachne.api.app.create_app().openapi()`) — never a checked-in `openapi.json`, so the
clients cannot describe an API the process does not serve. It builds that app over a
temporary, metadata-initialised SQLite database, so the gate works on a fresh checkout and
fails on *drift*, never on "the database was not migrated".

Output is a pure function of the schema: sorted operations and schemas, no timestamps, no
absolute paths, so regenerating is byte-identical. `--check` covers the four generated code
files above; this README is prose and is not generated.

## The contract both clients implement

1. **A key is required and auth is never bypassed.** `Client(base_url=..., api_key=...)` /
   `new ArachneClient({ baseUrl, apiKey })` raises immediately on a blank or missing key
   (`ArachneConfigError`). Every request then goes through a single private chokepoint
   (`Client._request` / `ArachneClient.request`) that always sets the `x-api-key` header —
   and `x-project` when the client was constructed with one (or the call passes one).
   Nothing else in either file issues a request; `tests/unit/test_sdkgen.py` asserts that
   from the AST for Python and from the source for TypeScript, and
   `tests/integration/test_sdk_contract.py` proves it against a live server.
2. **Rate limits are never bypassed.** A `429` is **not** retried: a blind retry loop would
   defeat the server's token bucket. It is surfaced as `ArachneRateLimitError`, carrying the
   server's `Retry-After` (seconds; `null`/`None` for an HTTP-date) and the
   `X-RateLimit-Limit` value, so the caller decides what to do.

Typed errors for every server response:

| Status | Python | TypeScript |
| --- | --- | --- |
| 401, 403 | `ArachneAuthError` | `ArachneAuthError` |
| 429 | `ArachneRateLimitError` (`retry_after`, `limit`) | `ArachneRateLimitError` (`retryAfter`, `limit`) |
| other 4xx / 5xx | `ArachneAPIError` | `ArachneAPIError` |
| any of the above | `ArachneClientError` (base; `status_code`, `response_headers`) | `ArachneClientError` (base; `statusCode`, `responseHeaders`) |

Transport-level failures (connection refused, timeout) propagate as the HTTP library's own
exception; they are not server responses.

## Python

```python
from arachne_client import ArachneRateLimitError, Client

with Client(base_url="https://arachne.example", api_key=key, project="tenant-a") as client:
    health = client.health()
    for scan in client.list_scans(limit=10):
        print(scan["id"], scan["status"])
    try:
        client.start_scan(body={"target_id": 1})
    except ArachneRateLimitError as exc:
        time.sleep(exc.retry_after or 1.0)
```

`clients/python/arachne_client` is not a separate distribution (there is no `pyproject.toml`
here on purpose): add `clients/python` to `sys.path`, vendor the directory, or copy it into
your project. It imports only `httpx` and the standard library.

Calls are synchronous, one method per operation, snake_case from the route's own
`operationId` (`list_scans`, `get_scan`, `start_scan`, …). Path parameters are positional;
the JSON body and the query parameters are keyword-only:

```python
client.get_scan(42)  # GET /api/v1/scans/42
client.list_findings(severity="high", limit=50)  # query parameters
client.create_target(body={...})  # JSON request body
```

A small naming rule: parameters that would shadow a Python builtin carry a trailing
underscore in the signature (`format_`, `next_`) while the wire name is unchanged
(`?format=`, `?next=`).

## TypeScript

```ts
import { ArachneClient, ArachneRateLimitError } from "./clients/typescript/src/client.ts";

const client = new ArachneClient({ baseUrl: "https://arachne.example", apiKey: key });
const health = await client.health();
const scans = await client.listScans({ limit: 10 });
try {
  await client.startScan({ target_id: 1 });
} catch (error) {
  if (error instanceof ArachneRateLimitError) await sleep((error.retryAfter ?? 1) * 1000);
}
```

Written in **erasable** TypeScript syntax only (no `enum`, `namespace` or parameter
properties), so Node 23.6+ (and Node 22.6+ with `--experimental-strip-types`) can run it
directly; nothing in the file is a runtime dependency. It uses the global `fetch`. Methods
and their option keys are camelCase; the **model field names in `types.ts` are the wire
names** (snake_case) so a parsed response needs no transformation.

## Schema coverage — what is exact, and what is not

The generator maps what it can do faithfully and *says so* where it cannot; it never invents
a plausible-but-wrong type.

Covered exactly:

* `$ref` to a `components.schemas` model → that model's name in both languages;
* `string` → `str` / `string`, `integer` → `int` / `number`, `number` → `float` / `number`,
  `boolean` → `bool` / `boolean`;
* string `enum` → `Literal["a", "b"]` / `"a" | "b"`;
* arrays → `list[T]` / `Array<T>`; object maps with a value schema →
  `dict[str, T]` / `Record<string, T>`; nullable → `T | None` / `T | null`;
* unions (`anyOf`/`oneOf`, `type` lists) of the above;
* request bodies, path parameters, query parameters and the success response type.

Deliberately generic, marked in the generated source with a `# generic JSON:` comment (Python)
or a `// generic JSON:` comment (TypeScript):

* a free-form object (`additionalProperties: true` or `false` with no modelled properties)
  → `object` / `unknown` (parameter and return positions) or `dict[str, object]` /
  `Record<string, unknown>` (field positions);
* an array with no `items` schema, a property with no `type` at all (e.g. pydantic's
  `ValidationError.input`), an enum of non-strings;
* a `$ref` to a schema that is not in `components.schemas`.

Not modelled at all: `format` hints (a `date-time` is a `str`/`string`), numeric/string
constraints (`minimum`, `maxLength`, `pattern`), and the error-response models
(`HTTPValidationError`/`ValidationError` are generated as types, but errors are raised, not
returned). Response bodies are chosen from the lowest `2xx` that declares
`application/json`; a non-JSON body (the report endpoint's HTML/PDF) is returned as raw text
(`str`/`string`) even though the method's declared type is the spec's.

## Tests

* `tests/unit/test_sdkgen.py` — generation is deterministic and idempotent; `--check` accepts
  the committed tree and names a hand-edited or deleted file; every operation has a method in
  both clients and every schema a type in both; the Python client has exactly one HTTP call
  site and it is `_request` (asserted from the AST, with a negative control); the TypeScript
  client has exactly one `fetch(`; a blank key and an unusable base URL are refused without
  sending anything; both headers are set on every call; a `429` raises after exactly one
  attempt with the server's `Retry-After`; the error taxonomy matches the server's
  `{"error": {...}}` envelope.
* `tests/integration/test_sdk_contract.py` — the generated **Python** client and the
  generated **TypeScript** client (executed by `node`) against the real app on a real socket:
  a wrong key is the server's 401 (asserted in the audit sink and via `WWW-Authenticate`), a
  role-less key is 403, the happy path returns the server's shapes, the `x-project` header is
  acted on, and with a one-request bucket both clients receive and raise the rate-limit error.
  The `node` half skips cleanly when `node` is not on `PATH`.
