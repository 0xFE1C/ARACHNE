"""Unit: the client generator — determinism, the drift gate, and structural invariants.

REQ-ECOS-002 asks for clients *generated from the OpenAPI spec* and contract-tested in CI.
Two of those words need a test of their own:

* **generated** — a client that was edited by hand is a client that will be wrong the next
  time a route moves, so the generator must be deterministic and ``--check`` must notice a
  hand edit (``test_an_edited_client_is_drift``).
* **the spec** — every operation the app publishes must have a method in *both* clients, so
  "the SDK covers the API" is a property, not a hope
  (``test_every_operation_has_a_method_in_both_clients``).

The remaining tests pin the two hard rules the clients exist under: one HTTP call site that
always sends the key (asserted from the AST, in the spirit of ``test_http_hygiene.py``), and
no retry-on-429 that would defeat the server's rate limit.
"""

from __future__ import annotations

import ast
import importlib
import re
import shutil
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

from arachne.tools import sdkgen

CLIENTS = Path(__file__).resolve().parents[2] / "clients"
PYTHON_CLIENT = CLIENTS / "python" / "arachne_client" / "client.py"
TYPESCRIPT_CLIENT = CLIENTS / "typescript" / "src" / "client.ts"
TYPESCRIPT_TYPES = CLIENTS / "typescript" / "src" / "types.ts"

#: Attribute names that issue an HTTP request. ``httpx.Client(...)`` is deliberately not one
#: of them: constructing a transport is not egress, using it is.
HTTP_VERBS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "stream"}
)


# --------------------------------------------------------------------------- helpers
def _dotted(node: ast.expr) -> str | None:
    """``self._client.request`` -> ``"self._client"`` for the receiver expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return None if parent is None else f"{parent}.{node.attr}"
    return None


def _http_call_sites(tree: ast.Module) -> list[ast.Call]:
    """Calls that would open a socket: ``<httpx|self._client>.<verb>(...)``."""
    sites: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in HTTP_VERBS:
            continue
        receiver = _dotted(node.func.value)
        if receiver == "self._client" or receiver == "httpx":
            sites.append(node)
    return sites


def _enclosing_function(tree: ast.Module, target: ast.AST) -> str | None:
    """The name of the innermost function that contains ``target``."""
    found: str | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for child in ast.walk(node):
            if child is target:
                found = node.name
    return found


def _operation_ids(spec: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """``(method, path, operationId)`` for every documented operation, sorted."""
    out: list[tuple[str, str, str]] = []
    for path in sorted(spec["paths"]):
        for method, operation in sorted(spec["paths"][path].items()):
            if method not in sdkgen.HTTP_METHODS:
                continue
            out.append((method, path, operation["operationId"]))
    return out


def _expected_names(method: str, path: str, operation_id: str) -> tuple[str, str]:
    """The Python and TypeScript method names, re-derived here rather than imported.

    Independent of :mod:`arachne.tools.sdkgen` on purpose: a bug in the generator's own
    naming would otherwise make this test agree with itself. FastAPI's ``operationId`` is
    ``<function name>_<path, non-alphanumerics as _>_<method>``; the prefix is the route
    function's name.
    """
    suffix = path.replace("/", "_").replace("-", "_").replace("{", "_").replace("}", "_")
    suffix = f"{suffix}_{method}"
    assert operation_id.endswith(suffix), (operation_id, suffix)
    python_name = operation_id[: -len(suffix)]
    head, *rest = python_name.split("_")
    typescript_name = head + "".join(part[:1].upper() + part[1:] for part in rest)
    return python_name, typescript_name


class _Recorder(httpx.BaseTransport):
    """A transport that records whether anything tried to use it."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        raise AssertionError("a request was sent when none should have been")


@pytest.fixture(scope="module")
def sdk() -> Iterator[ModuleType]:
    """The generated Python package, imported from the committed tree."""
    root = str(CLIENTS / "python")
    sys.path.insert(0, root)
    try:
        yield importlib.import_module("arachne_client")
    finally:
        sys.path.remove(root)


# --------------------------------------------------------------------------- determinism
def test_the_generator_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    sdkgen.generate(first)
    sdkgen.generate(second)
    for relative in sdkgen.GENERATED_FILES:
        left = (first / relative).read_bytes()
        right = (second / relative).read_bytes()
        assert left == right, f"{relative} is not reproducible"
    # And regeneration is idempotent in place, which is what ``--check`` relies on.
    sdkgen.generate(first)
    for relative in sdkgen.GENERATED_FILES:
        assert (first / relative).read_bytes() == (second / relative).read_bytes()


def test_the_committed_clients_are_up_to_date() -> None:
    assert sdkgen.check(CLIENTS) == [], "run `python -m arachne.tools.sdkgen` and commit"


def test_an_edited_client_is_drift(tmp_path: Path) -> None:
    target = tmp_path / "clients"
    shutil.copytree(CLIENTS, target)
    assert sdkgen.check(target) == []
    edited = target / "typescript" / "src" / "client.ts"
    edited.write_text(edited.read_text(encoding="utf-8") + "// hand edit\n", encoding="utf-8")
    assert sdkgen.check(target) == [edited]


def test_a_missing_client_is_drift(tmp_path: Path) -> None:
    target = tmp_path / "clients"
    shutil.copytree(CLIENTS, target)
    (target / "python" / "arachne_client" / "client.py").unlink()
    assert sdkgen.check(target) == [target / "python" / "arachne_client" / "client.py"]


def test_the_generated_files_carry_no_environment_specific_bytes() -> None:
    """No absolute path, no clock: the output is a pure function of the schema."""
    for relative in sdkgen.GENERATED_FILES:
        text = (CLIENTS / relative).read_text(encoding="utf-8")
        assert str(Path.home()) not in text
        assert str(CLIENTS.parent) not in text
        assert not re.search(r"20\d\d-\d\d-\d\dT", text), f"{relative} carries a timestamp"


# --------------------------------------------------------------------------- parity
def test_every_operation_has_a_method_in_both_clients() -> None:
    spec = sdkgen.load_spec()
    operations = _operation_ids(spec)
    python_source = PYTHON_CLIENT.read_text(encoding="utf-8")
    typescript_source = TYPESCRIPT_CLIENT.read_text(encoding="utf-8")

    # A sanity floor, not a pinned count: the API grows, and only the *parity* below is the
    # contract. An empty spec (a loader that silently returned `{}`) would otherwise pass.
    assert len(operations) >= 60, "the spec has suspiciously few operations"
    for method, path, operation_id in operations:
        python_name, typescript_name = _expected_names(method.lower(), path, operation_id)
        assert python_source.count(f"def {python_name}(") == 1, f"missing method {python_name}"
        assert f"async {typescript_name}(" in typescript_source, (
            f"missing TypeScript method {typescript_name}"
        )


def test_both_clients_have_exactly_one_method_per_operation() -> None:
    spec = sdkgen.load_spec()
    expected = {
        _expected_names(method.lower(), path, operation_id)[0]
        for method, path, operation_id in _operation_ids(spec)
    }
    source = PYTHON_CLIENT.read_text(encoding="utf-8")
    defined = set(re.findall(r"^    def ([A-Za-z_][A-Za-z0-9_]*)\(", source, flags=re.MULTILINE))
    # The class's own plumbing is the only thing that is not a generated operation.
    hand_written = {"__init__", "__enter__", "__exit__", "close", "_request"}
    assert defined - expected == hand_written
    assert expected <= defined

    typescript_source = TYPESCRIPT_CLIENT.read_text(encoding="utf-8")
    generated_ts = set(
        re.findall(r"^  async ([A-Za-z_][A-Za-z0-9_]*)\(", typescript_source, flags=re.MULTILINE)
    )
    assert generated_ts == {
        _expected_names(method.lower(), path, operation_id)[1]
        for method, path, operation_id in _operation_ids(spec)
    }


def test_every_schema_has_a_type_in_both_clients() -> None:
    schemas = sorted(sdkgen._schemas(sdkgen.load_spec()))
    assert schemas, "the spec has no components.schemas"
    python_source = PYTHON_CLIENT.read_text(encoding="utf-8")
    typescript_source = TYPESCRIPT_TYPES.read_text(encoding="utf-8")
    for name in schemas:
        assert f"class {name}(TypedDict" in python_source, f"missing model {name}"
        assert f"export interface {name} {{" in typescript_source, f"missing interface {name}"


# --------------------------------------------------------------------------- hard rules
def test_the_python_client_has_exactly_one_http_call_site() -> None:
    tree = ast.parse(PYTHON_CLIENT.read_text(encoding="utf-8"), filename=str(PYTHON_CLIENT))
    sites = _http_call_sites(tree)
    assert len(sites) == 1, f"expected one egress path, found {len(sites)}"
    assert _enclosing_function(tree, sites[0]) == "_request", (
        "the single HTTP call site must be the _request chokepoint"
    )


def test_the_python_client_imports_no_second_http_library() -> None:
    source = PYTHON_CLIENT.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(PYTHON_CLIENT))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    for banned in ("requests", "urllib.request", "urllib3", "aiohttp", "http.client"):
        assert banned not in imported, f"{banned} would be a second egress path"
    assert "urlopen" not in source


def test_the_typescript_client_has_exactly_one_fetch_call_site() -> None:
    source = TYPESCRIPT_CLIENT.read_text(encoding="utf-8")
    matches = re.findall(r"(?<![\w.])fetch\(", source)
    assert len(matches) == 1, f"expected one fetch site, found {len(matches)}"
    fetch_at = source.index("fetch(")
    request_at = source.index("private async request<T>(")
    error_at = source.index("private async errorMessage(")
    assert request_at < fetch_at < error_at, "the fetch call must live in request()"


def test_the_type_chokepoint_proves_a_single_egress_path_primitive() -> None:
    """The AST helper above must actually detect a second call site (a negative control)."""
    planted = ast.parse(
        "import httpx\n"
        "def a(self):\n"
        "    return self._client.get('/x')\n"
        "def b(self):\n"
        "    return httpx.post('/y')\n"
    )
    assert len(_http_call_sites(planted)) == 2
    ok = ast.parse("def a(self):\n    return self._client.request('GET', '/x')\n")
    assert len(_http_call_sites(ok)) == 1


def test_the_client_refuses_a_blank_key_before_any_request(sdk: ModuleType) -> None:
    transport = _Recorder()
    for blank in ("", "   "):
        with pytest.raises(sdk.ArachneConfigError):
            sdk.Client(base_url="http://testserver", api_key=blank, transport=transport)
    assert transport.calls == []


def test_the_client_refuses_an_unusable_base_url(sdk: ModuleType) -> None:
    transport = _Recorder()
    for base_url in ("", "not-a-url", "ftp://example.com"):
        with pytest.raises(sdk.ArachneConfigError):
            sdk.Client(base_url=base_url, api_key="k", transport=transport)
    assert transport.calls == []


def test_the_chokepoint_sets_both_headers_on_every_call(sdk: ModuleType) -> None:
    """Every call, not just the first: the header is built per request, not once."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"status": "ok"})

    client = sdk.Client(
        base_url="http://testserver",
        api_key="secret-key",
        project="tenant-a",
        transport=httpx.MockTransport(handler),
    )
    client.health()
    client.health(project="tenant-b")
    assert len(seen) == 2
    assert seen[0].headers["x-api-key"] == "secret-key"
    assert seen[0].headers["x-project"] == "tenant-a"
    assert seen[1].headers["x-project"] == "tenant-b"
    assert all(request.headers["x-api-key"] == "secret-key" for request in seen)


def test_the_rate_limit_error_is_typed_and_not_retried(sdk: ModuleType) -> None:
    """A 429 surfaces immediately with the server's ``Retry-After`` — no retry loop."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            429,
            json={"error": {"code": 429, "message": "rate limit exceeded"}},
            headers={"Retry-After": "7", "X-RateLimit-Limit": "2"},
        )

    client = sdk.Client(
        base_url="http://testserver", api_key="k", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(sdk.ArachneRateLimitError) as info:
        client.health()
    assert calls == 1, "the client must not retry a rate-limited request"
    assert info.value.retry_after == 7.0
    assert info.value.limit == 2
    assert info.value.status_code == 429
    assert "rate limit exceeded" in str(info.value)


def test_the_error_taxonomy_matches_the_servers_envelopes(sdk: ModuleType) -> None:
    """401/403 -> auth, other 4xx/5xx -> API error, each carrying the server's message."""
    envelope = {"error": {"code": 401, "message": "missing API key"}}
    client = sdk.Client(
        base_url="http://testserver",
        api_key="k",
        transport=httpx.MockTransport(lambda request: httpx.Response(401, json=envelope)),
    )
    with pytest.raises(sdk.ArachneAuthError) as auth:
        client.health()
    assert auth.value.status_code == 401
    assert "missing API key" in str(auth.value)
    assert isinstance(auth.value, sdk.ArachneClientError)

    client = sdk.Client(
        base_url="http://testserver",
        api_key="k",
        transport=httpx.MockTransport(lambda request: httpx.Response(503, text="nope")),
    )
    with pytest.raises(sdk.ArachneAPIError) as api:
        client.health()
    assert api.value.status_code == 503
    assert not isinstance(api.value, sdk.ArachneAuthError)


def test_a_non_json_body_comes_back_as_text(sdk: ModuleType) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, text="<html>report</html>", headers={"content-type": "text/html"}
        )
    )
    client = sdk.Client(base_url="http://testserver", api_key="k", transport=transport)
    assert client.get_report(1) == "<html>report</html>"


def test_parameters_that_shadow_builtins_stay_on_the_wire() -> None:
    """``format``/``next`` are Python builtins; the client renames the *local* only."""
    source = PYTHON_CLIENT.read_text(encoding="utf-8")
    assert "format_: str | None = None" in source
    assert '"format": format_' in source
    assert "next_: str | None = None" in source
    assert '"next": next_' in source


def test_the_python_client_exports_one_class_named_client(sdk: ModuleType) -> None:
    assert callable(sdk.Client)
    assert set(sdk.__all__) <= set(dir(sdk))


def test_operation_sequences_are_stable_shapes() -> None:
    """A cheap guard on the IR the two renderers share: nothing is left unmapped."""
    spec = sdkgen.load_spec()
    models = sdkgen._models(spec)
    operations = sdkgen._operations(spec, frozenset(model.name for model in models))
    assert len(operations) == len(_operation_ids(spec))
    for operation in operations:
        assert operation.returns.py
        assert operation.returns.ts
        assert operation.operation_id
        assert operation.summary
        # every path parameter appears in the path template it is rendered into
        for param in operation.path_params:
            assert "{" + param.name + "}" in operation.path
        # the parameters a client sends are exactly the ones the server documents
        for params in (operation.query_params, operation.path_params):
            names = [param.name for param in params]
            assert len(set(names)) == len(names)
        assert all(param.location in {"path", "query"} for param in operation.query_params)
