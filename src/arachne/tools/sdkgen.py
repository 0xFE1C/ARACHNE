"""Generate the official Python and TypeScript API clients from the live OpenAPI schema.

REQ-ECOS-002: "Official Python and TypeScript API clients MUST be generated from the
OpenAPI spec and contract-tested in CI." This module is the generator. It reads the
schema from the **running application** (:func:`arachne.api.app.create_app`) rather than a
checked-in document, so the clients can never describe an API the process does not serve:

    python -m arachne.tools.sdkgen            # write clients/<lang>/...
    python -m arachne.tools.sdkgen --check    # CI drift gate (exit 1 and name the file)

Output is deterministic — sorted operations, sorted schemas, no timestamps, no absolute
paths — so regenerating is byte-identical and ``--check`` is a real gate rather than a
"usually stable" one.

Two rules are baked into both clients and asserted by the contract tests:

* **Auth is never bypassed.** Every request goes through a single private chokepoint that
  always sets the ``x-api-key`` header (plus ``x-project`` when the client has one). Both
  clients refuse to be constructed without a key.
* **Rate limits are never bypassed.** The chokepoint does **not** retry a ``429``: a blind
  retry loop would defeat the server's token bucket. The refusal is surfaced as a typed
  error carrying the server's ``Retry-After``.

Coverage is deliberately partial and stated where it is partial: JSON-Schema shapes that
have no faithful language type (a free-form object, an array without ``items``, a property
with no ``type``) become a generic JSON type with a comment saying so. Nothing is silently
widened into a plausible-looking but wrong type.
"""

from __future__ import annotations

import argparse
import builtins
import keyword
import re
import sys
import tempfile
import textwrap
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from arachne.api.app import create_app
from arachne.core.config import ApiSettings, Settings
from arachne.data.db import create_all, create_db_engine

__all__ = [
    "GENERATED_FILES",
    "check",
    "clients_root",
    "generate",
    "load_spec",
    "main",
]

#: One file this generator owns, relative to the clients root. ``--check`` verifies exactly
#: these; the README next to them is prose and is not generated.
GENERATED_FILES: tuple[str, ...] = (
    "python/arachne_client/__init__.py",
    "python/arachne_client/client.py",
    "typescript/src/client.ts",
    "typescript/src/types.ts",
)

#: The HTTP methods modelled, in the fixed order that makes the output deterministic
#: (``paths`` is a mapping, so keys must be walked in a chosen order, never dict order).
HTTP_METHODS: tuple[str, ...] = ("get", "post", "put", "patch", "delete")

#: The line length ``ruff format`` is configured with; the emitters keep under it.
MAX_LINE = 100

#: Names a generated Python parameter may not use (a builtin, a keyword, or a reserved
#: name of the emitted signature). ``format`` and ``next`` occur in this API today.
_RESERVED_PYTHON_NAMES = frozenset(dir(builtins)) | frozenset({"self", "body"})

#: The package's runtime dependency for HTTP; named here so the generated file and this
#: module agree on what "one egress path" means.
_TRANSPORT_IMPORT = "httpx"

#: Throwaway API keys for the spec-only app instance (:func:`load_spec`); never used.
_SPEC_API_KEYS: tuple[str, ...] = ("sdkgen:admin:spec-only",)


class SpecError(RuntimeError):
    """The live OpenAPI document is not the shape this generator understands.

    A loud failure is right here: the alternative is emitting a client method with the
    wrong path or a truncated type, which would look fine until it was used.
    """


# --------------------------------------------------------------------------- spec access
# The raw document is a JSON tree. ``object`` (not ``Any``) is the honest type for a JSON
# value, and these accessors are the only place that narrows it; everything downstream is
# the typed IR below. Each one names the JSON pointer it failed on so a spec change is
# diagnosable from the exception alone.
def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise SpecError(f"{where}: expected a JSON object, got {type(value).__name__}")
    return cast("Mapping[str, object]", value)


def _sequence(value: object, where: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise SpecError(f"{where}: expected a JSON array, got {type(value).__name__}")
    return cast("Sequence[object]", value)


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise SpecError(f"{where}: expected a non-empty string, got {value!r}")
    return value


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _flag(value: object) -> bool:
    return value is True


# --------------------------------------------------------------------------- typed IR
@dataclass(frozen=True, slots=True)
class IrType:
    """A language type pair, the models it points at, and why it was generalised."""

    py: str
    ts: str
    #: Why this is a generic JSON type, if it is one (``None`` when the type is exact).
    note: str | None = None
    #: Generated model names this type mentions, so an importer knows what to pull in.
    refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FieldIr:
    """One property of a modelled schema."""

    name: str
    type: IrType
    required: bool


@dataclass(frozen=True, slots=True)
class ModelIr:
    """A ``components.schemas`` entry."""

    name: str
    doc: str
    fields: tuple[FieldIr, ...]


@dataclass(frozen=True, slots=True)
class ParamIr:
    """A path or query parameter."""

    name: str
    location: str
    required: bool
    type: IrType


@dataclass(frozen=True, slots=True)
class BodyIr:
    """A JSON request body."""

    model: str
    required: bool
    type: IrType


@dataclass(frozen=True, slots=True)
class OperationIr:
    """One documented operation, ready to render into either language."""

    name: str
    method: str
    path: str
    operation_id: str
    summary: str
    path_params: tuple[ParamIr, ...]
    query_params: tuple[ParamIr, ...]
    body: BodyIr | None
    returns: IrType
    #: True for a cursor-paginated collection operation (``x-arachne-paginated``): its return
    #: type is wrapped in a page carrying the next/prev cursors (REQ-UIX-001).
    paginated: bool = False


def _generic(note: str) -> IrType:
    """The honest type for a JSON value whose schema carries no usable type."""
    return IrType("object", "unknown", note=note)


def _page_of(element: IrType) -> IrType:
    """Wrap a collection's element type in the page the client returns (REQ-UIX-001)."""
    py, ts = element.py, element.ts
    if py.startswith("list[") and py.endswith("]"):
        py = py[len("list[") : -1]
    if ts.startswith("Array<") and ts.endswith(">"):
        ts = ts[len("Array<") : -1]
    return IrType(f"Page[{py}]", f"Page<{ts}>", refs=element.refs)


def _is_null_only(schema: Mapping[str, object]) -> bool:
    kind = schema.get("type")
    if kind == "null":
        return True
    if isinstance(kind, list):
        return [item for item in kind if item != "null"] == []
    return False


def _merge(parts: Sequence[IrType], *, nullable: bool, note: str) -> IrType:
    """A union of already-mapped types, deduplicated and with ``None``/``null`` added."""
    ordered: list[IrType] = []
    seen: set[tuple[str, str]] = set()
    for part in parts:
        key = (part.py, part.ts)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(part)
    refs = tuple(sorted({ref for part in ordered for ref in part.refs}))
    if not ordered:
        return IrType(
            "None" if nullable else "object",
            "null" if nullable else "unknown",
            note=note,
            refs=refs,
        )
    py = " | ".join(part.py for part in ordered)
    ts = " | ".join(part.ts for part in ordered)
    if nullable:
        py = f"{py} | None"
        ts = f"{ts} | null"
    carried = next((part.note for part in ordered if part.note is not None), None)
    return IrType(py, ts, note=carried, refs=refs)


def _enum_type(values: Sequence[object], where: str) -> IrType:
    """A string enum becomes ``Literal[...]`` / a TypeScript literal union."""
    if values and all(isinstance(value, str) for value in values):
        items = [cast(str, value) for value in values]
        py = "Literal[" + ", ".join(f'"{item}"' for item in items) + "]"
        ts = " | ".join(f'"{item}"' for item in items)
        return IrType(py, ts)
    return _generic(f"enum at {where} whose values are not strings")


def _object_type(schema: Mapping[str, object], *, where: str, known: frozenset[str]) -> IrType:
    additional = schema.get("additionalProperties")
    if isinstance(additional, Mapping):
        value = _type_of(additional, where=f"{where}.additionalProperties", known=known)
        return IrType(
            f"dict[str, {value.py}]",
            f"Record<string, {value.ts}>",
            note=value.note,
            refs=value.refs,
        )
    if additional is True:
        return _generic("free-form object with no value schema")
    return _generic("object whose properties are not modelled")


def _primitive(
    kind: str, schema: Mapping[str, object], *, where: str, known: frozenset[str]
) -> IrType:
    if kind == "string":
        enum = schema.get("enum")
        if enum is not None:
            return _enum_type(_sequence(enum, f"{where}.enum"), where)
        return IrType("str", "string")
    if kind == "integer":
        return IrType("int", "number")
    if kind == "number":
        return IrType("float", "number")
    if kind == "boolean":
        return IrType("bool", "boolean")
    if kind == "null":
        return IrType("None", "null")
    if kind == "array":
        items = schema.get("items")
        if items is None:
            return _generic("array with no `items` schema")
        item = _type_of(items, where=f"{where}.items", known=known)
        return IrType(f"list[{item.py}]", f"Array<{item.ts}>", note=item.note, refs=item.refs)
    if kind == "object":
        return _object_type(schema, where=where, known=known)
    return _generic(f"unsupported schema type {kind!r}")


def _type_of(node: object, *, where: str, known: frozenset[str]) -> IrType:
    """Map one JSON-Schema node onto the two languages.

    Covered: ``$ref`` to a generated model, string/integer/number/boolean, string enums,
    arrays (``items``), ``dict``-like objects (``additionalProperties`` with a schema),
    nullable (``anyOf`` with ``null``, or a ``type`` list) and unions of the above.
    Anything else falls back to a generic JSON type and carries a note saying why.
    """
    if node is None:
        return _generic("no schema")
    schema = _mapping(node, where)
    ref = _optional_text(schema.get("$ref"))
    if ref is not None:
        name = ref.rsplit("/", 1)[-1]
        if name not in known:
            return _generic(f"references {name}, which components.schemas does not define")
        return IrType(name, name, refs=(name,))
    members = schema.get("anyOf")
    if members is None:
        members = schema.get("oneOf")
    if members is not None:
        parts: list[IrType] = []
        nullable = False
        for index, member in enumerate(_sequence(members, f"{where}.anyOf")):
            candidate = _mapping(member, f"{where}.anyOf[{index}]")
            if _is_null_only(candidate):
                nullable = True
                continue
            parts.append(_type_of(candidate, where=f"{where}.anyOf[{index}]", known=known))
        return _merge(parts, nullable=nullable, note=f"union at {where}")
    kind = schema.get("type")
    if isinstance(kind, list):
        nullable = "null" in kind
        rest = [item for item in kind if isinstance(item, str) and item != "null"]
        parts = [_primitive(item, schema, where=where, known=known) for item in rest]
        return _merge(parts, nullable=nullable, note=f"union at {where}")
    if kind is None:
        return _generic("schema declares no `type`")
    return _primitive(_text(kind, f"{where}.type"), schema, where=where, known=known)


# --------------------------------------------------------------------------- extraction
def load_spec() -> Mapping[str, object]:
    """The live OpenAPI 3.1 document — ``create_app().openapi()``, never a file.

    The factory is given a throwaway SQLite database initialised with the ORM metadata
    rather than the developer's own ``ARACHNE_DATABASE_URL``. The published document is a
    property of the code, not of the deployment's data, so the generator works on a fresh
    checkout (and the CI drift gate fails on drift, never on "the database was not
    migrated"). The API key below is a throwaway literal: it never reaches a socket, and
    the schema does not depend on it.
    """
    with tempfile.TemporaryDirectory(prefix="arachne-sdkgen-") as directory:
        url = f"sqlite:///{Path(directory) / 'spec.db'}"
        settings = Settings(
            database_url=url,
            log_level="CRITICAL",
            api=ApiSettings(keys=_SPEC_API_KEYS, require_tls=False),
        )
        engine = create_db_engine(url, settings=settings)
        try:
            create_all(engine)
        finally:
            engine.dispose()
        app = create_app(settings=settings)
        try:
            return _mapping(cast(object, app.openapi()), "openapi")
        finally:
            app.state.context.close()


def _schemas(spec: Mapping[str, object]) -> Mapping[str, object]:
    components = _mapping(spec.get("components"), "components")
    return _mapping(components.get("schemas"), "components.schemas")


def _first_line(description: str | None) -> str:
    if description is None:
        return ""
    for line in description.splitlines():
        stripped = " ".join(line.split())
        if stripped:
            return stripped
    return ""


def _models(spec: Mapping[str, object]) -> tuple[ModelIr, ...]:
    schemas = _schemas(spec)
    known = frozenset(schemas)
    models: list[ModelIr] = []
    for name in sorted(schemas):
        if not name.isidentifier():
            raise SpecError(f"components.schemas[{name!r}] is not a Python identifier")
        schema = _mapping(schemas[name], f"components.schemas.{name}")
        properties = _mapping(schema.get("properties") or {}, f"{name}.properties")
        required_value = schema.get("required")
        required: set[str] = set()
        if required_value is not None:
            required = {
                _text(item, f"{name}.required[]")
                for item in _sequence(required_value, f"{name}.required")
            }
        fields: list[FieldIr] = []
        for field_name in properties:
            if not field_name.isidentifier():
                raise SpecError(f"{name}.{field_name} is not a Python identifier")
            fields.append(
                FieldIr(
                    name=field_name,
                    type=_type_of(
                        properties[field_name], where=f"{name}.{field_name}", known=known
                    ),
                    required=field_name in required,
                )
            )
        models.append(
            ModelIr(
                name=name,
                doc=_first_line(_optional_text(schema.get("description"))),
                fields=tuple(fields),
            )
        )
    return tuple(models)


def _operation_name(operation_id: str, path: str, method: str) -> str:
    """The stable snake_case method name.

    FastAPI builds ``operationId`` as ``<function name>_<path with non-alphanumerics as _>
    _<method>``. Stripping that suffix yields the route function's own name, which is
    exactly the readable, stable method name we want; the fallback keeps the generator
    working even if that convention changes.
    """
    suffix = path.replace("/", "_").replace("-", "_").replace("{", "_").replace("}", "_")
    suffix = f"{suffix}_{method.lower()}"
    if operation_id.endswith(suffix) and len(operation_id) > len(suffix):
        return operation_id[: -len(suffix)]
    slug = path.strip("/").replace("/", "_").replace("-", "_")
    slug = slug.replace("{", "by_").replace("}", "")
    return f"{method.lower()}_{slug}"


def _parameters(op: Mapping[str, object], where: str, known: frozenset[str]) -> list[ParamIr]:
    raw = op.get("parameters")
    if raw is None:
        return []
    params: list[ParamIr] = []
    for index, item in enumerate(_sequence(raw, f"{where}.parameters")):
        param = _mapping(item, f"{where}.parameters[{index}]")
        location = _text(param.get("in"), f"{where}.parameters[{index}].in")
        if location not in {"path", "query"}:
            continue  # header/cookie parameters are not modelled (there are none today)
        name = _text(param.get("name"), f"{where}.parameters[{index}].name")
        is_path = location == "path"
        params.append(
            ParamIr(
                name=name,
                location=location,
                required=True if is_path else _flag(param.get("required")),
                type=_type_of(
                    param.get("schema"),
                    where=f"{where}.parameters[{index}].schema",
                    known=known,
                ),
            )
        )
    return params


def _body(op: Mapping[str, object], where: str, known: frozenset[str]) -> BodyIr | None:
    request = op.get("requestBody")
    if request is None:
        return None
    body = _mapping(request, f"{where}.requestBody")
    content = _mapping(body.get("content"), f"{where}.requestBody.content")
    media = content.get("application/json")
    if media is None:
        return None
    media_object = _mapping(media, f"{where}.requestBody.content['application/json']")
    type_ = _type_of(
        media_object.get("schema"),
        where=f"{where}.requestBody.schema",
        known=known,
    )
    return BodyIr(
        model=type_.py,
        required=_flag(body.get("required")),
        type=type_,
    )


def _success_response(op: Mapping[str, object], where: str) -> object | None:
    """The schema of the lowest 2xx response that carries ``application/json``."""
    responses = _mapping(op.get("responses"), f"{where}.responses")
    for status_code in sorted(responses, key=_status_sort_key):
        if not status_code.startswith("2"):
            continue
        response = _mapping(responses[status_code], f"{where}.responses[{status_code}]")
        content = response.get("content")
        if content is None:
            continue
        media = _mapping(content, f"{where}.responses[{status_code}].content")
        entry = media.get("application/json")
        if entry is None:
            continue
        return _mapping(entry, f"{where}.responses[{status_code}]['application/json']").get(
            "schema"
        )
    return None


def _status_sort_key(status_code: str) -> tuple[int, str]:
    return (int(status_code), status_code) if status_code.isdigit() else (1000, status_code)


def _operation(
    method: str, path: str, op: Mapping[str, object], known: frozenset[str]
) -> OperationIr:
    where = f"{method.lower()} {path}"
    operation_id = _text(op.get("operationId"), f"{where}.operationId")
    summary = _optional_text(op.get("summary")) or f"{method} {path}"
    params = _parameters(op, where, known)
    paginated = _flag(op.get("x-arachne-paginated"))
    schema = _success_response(op, where)
    returns = (
        _type_of(schema, where=f"{where}.responses", known=known)
        if schema is not None
        else _generic("no success response schema is declared")
    )
    if paginated:
        returns = _page_of(returns)
    return OperationIr(
        name=_operation_name(operation_id, path, method),
        method=method.upper(),
        path=path,
        operation_id=operation_id,
        summary=summary,
        path_params=tuple(param for param in params if param.location == "path"),
        query_params=tuple(param for param in params if param.location == "query"),
        body=_body(op, where, known),
        returns=returns,
        paginated=paginated,
    )


def _expand_parameter_refs(
    spec: Mapping[str, object], op: Mapping[str, object], where: str
) -> Mapping[str, object]:
    """Inline a shared ``components.parameters`` ``$ref`` before the parameter IR is built.

    The API hoists the ``cursor`` parameter into one shared component (REQ-UIX-001), so an
    operation's ``parameters`` list carries a ``$ref`` instead of the full object. Resolving
    it here keeps every downstream reader working on a plain parameter.
    """
    raw = op.get("parameters")
    if not isinstance(raw, list):
        return op
    components = spec.get("components")
    available = components.get("parameters") if isinstance(components, Mapping) else None
    resolved: list[object] = []
    for index, item in enumerate(raw):
        ref = item.get("$ref") if isinstance(item, Mapping) else None
        if ref is None:
            resolved.append(item)
            continue
        name = str(ref).rsplit("/", 1)[-1]
        target = available.get(name) if isinstance(available, Mapping) else None
        if target is None:
            raise SpecError(f"{where}.parameters[{index}]: unresolved reference {ref!r}")
        resolved.append(target)
    return {**op, "parameters": resolved}


def _operations(spec: Mapping[str, object], known: frozenset[str]) -> tuple[OperationIr, ...]:
    paths = _mapping(spec.get("paths"), "paths")
    operations: list[OperationIr] = []
    for path in sorted(paths):
        item = _mapping(paths[path], f"paths[{path}]")
        for method in HTTP_METHODS:
            raw = item.get(method)
            if raw is None:
                continue
            where = f"{method} {path}"
            operation = _expand_parameter_refs(spec, _mapping(raw, where), where)
            operations.append(_operation(method, path, operation, known))
    names = [operation.name for operation in operations]
    if len(set(names)) != len(names):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        raise SpecError(f"operationId-derived names collide: {duplicates}")
    return tuple(operations)


# --------------------------------------------------------------------------- naming
def _parameter_name(name: str) -> str:
    """A Python parameter name for a wire parameter.

    ``format`` and ``next`` shadow builtins and would fail ``ruff``'s A002; they carry a
    trailing underscore. The wire name is what goes into the query string, so only the
    local spelling changes.
    """
    candidate = name
    while keyword.iskeyword(candidate) or candidate in _RESERVED_PYTHON_NAMES:
        candidate = f"{candidate}_"
    return candidate


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _optionalize_py(type_: str) -> str:
    if type_ == "None" or "None" in {part.strip() for part in type_.split("|")}:
        return type_
    return f"{type_} | None"


def _optionalize_ts(type_: str) -> str:
    parts = {part.strip() for part in type_.split("|")}
    if parts & {"null", "unknown"}:
        return type_
    return f"{type_} | null"


def _py_string_literal(value: str) -> str:
    """``value`` as a double-quoted Python literal (Black's preferred quote style)."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _dotted_sort_key(name: str) -> tuple[tuple[int, object], ...]:
    """Ruff's ``__all__`` ordering: case-sensitive, with digit runs compared as numbers."""
    return tuple(
        (0, int(chunk)) if chunk.isdigit() else (1, chunk)
        for chunk in re.split(r"(\d+)", name)
        if chunk
    )


def _import_sort_key(name: str) -> tuple[str, str]:
    """Ruff's isort ordering for a ``from x import (a, b)`` list: case-insensitive."""
    return (name.lower(), name)


def _is_block(part: str) -> bool:
    first = part.splitlines()[0]
    return first.startswith(("class ", "def ", "@"))


def _py_join(parts: Sequence[str]) -> str:
    """Join top-level statements the way ``ruff format``/isort leave them.

    Two blank lines around any top-level class or function, one elsewhere — and exactly
    one blank line after the module docstring and after the import block.
    """
    rendered = parts[0]
    for index in range(1, len(parts)):
        blanks = 2 if _is_block(parts[index - 1]) or _is_block(parts[index]) else 1
        rendered += "\n" * (blanks + 1) + parts[index]
    return rendered + "\n"


# --------------------------------------------------------------------------- rendering
def _wrap(text: str, width: int) -> list[str]:
    if not text:
        return []
    return textwrap.wrap(text, width=width, break_long_words=False, break_on_hyphens=False)


def _escape_docstring(text: str) -> str:
    """Docstring text: no triple quotes, and backslashes doubled so no escape is live."""
    return text.replace("\\", "\\\\").replace('"""', "'''")


def _py_docstring(text: str, *, indent: int, width: int) -> list[str]:
    """A docstring in the shape ``ruff format`` leaves alone.

    A one-liner stays a one-liner; anything longer keeps its closing quotes on their own
    line. Black does not reflow prose, so the wrapping here is the final layout: each blank
    line in ``text`` separates paragraphs, and each paragraph is wrapped on its own.
    """
    body: list[str] = []
    for index, paragraph in enumerate(text.split("\n\n")):
        if index:
            body.append("")
        body.extend(_wrap(_escape_docstring(paragraph), width))
    if not body:
        return []
    pad = " " * indent
    if len(body) == 1:
        return [f'{pad}"""{body[0]}"""']
    rendered = [f'{pad}"""{body[0]}']
    rendered.extend(f"{pad}{line}" if line else "" for line in body[1:])
    rendered.append(f'{pad}"""')
    return rendered


def _py_models(models: Sequence[ModelIr]) -> list[str]:
    blocks: list[str] = []
    for model in models:
        all_optional = all(not field.required for field in model.fields)
        header = f"class {model.name}(TypedDict"
        if all_optional:
            header += ", total=False"
        header += "):"
        block = [header]
        docstring = _py_docstring(model.doc, indent=4, width=MAX_LINE - 8)
        block.extend(docstring)
        if docstring and model.fields:
            block.append("")  # Black wants a blank line after a class docstring
        for field in model.fields:
            if field.type.note is not None:
                block.append(f"    # generic JSON: {field.type.note}")
            annotation = field.type.py
            if not field.required and not all_optional:
                annotation = f"NotRequired[{annotation}]"
            block.append(f"    {field.name}: {annotation}")
        blocks.append("\n".join(block))
    return blocks


def _py_path_expression(operation: OperationIr) -> str:
    if not operation.path_params:
        return f'"{operation.path}"'
    pieces: list[str] = []
    remainder = operation.path
    for param in operation.path_params:
        token = "{" + param.name + "}"
        before, _, remainder = remainder.partition(token)
        pieces.append(before)
        pieces.append("{quote(str(" + _parameter_name(param.name) + "), safe='')}")
    pieces.append(remainder)
    return 'f"' + "".join(pieces) + '"'


def _py_method(operation: OperationIr) -> str:
    lines: list[str] = []
    signature: list[str] = ["self"]
    for param in operation.path_params:
        signature.append(f"{_parameter_name(param.name)}: {param.type.py}")
    if operation.query_params or operation.body is not None:
        signature.append("*")
    if operation.body is not None:
        if operation.body.required:
            signature.append(f"body: {operation.body.model}")
        else:
            signature.append(f"body: {operation.body.model} | None = None")
    for param in operation.query_params:
        name = _parameter_name(param.name)
        if param.required:
            signature.append(f"{name}: {param.type.py}")
        else:
            signature.append(f"{name}: {_optionalize_py(param.type.py)} = None")
    signature.append("project: str | None = None")
    lines.append(f"    def {operation.name}(")
    lines.extend(f"        {item}," for item in signature)
    lines.append(f"    ) -> {operation.returns.py}:")
    doc = f"{operation.summary}\n\n``{operation.method} {operation.path}``"
    doc += f" (operationId ``{operation.operation_id}``)."
    if operation.returns.note is not None:
        doc += f"\n\nThe success body is generic JSON: {operation.returns.note}."
    lines.extend(_py_docstring(doc, indent=8, width=MAX_LINE - 16))
    path_expression = _py_path_expression(operation)
    if operation.path_params:
        lines.append(f"        path = {path_expression}")
        call_target = "path"
    else:
        call_target = path_expression
    typed_return = operation.returns.py != "object"
    if typed_return:
        lines.append("        return cast(")
        lines.append(f"            {_py_string_literal(operation.returns.py)},")
        lines.append("            self._request(")
        inner = 16
    else:
        lines.append("        return self._request(")
        inner = 12
    pad = " " * inner
    lines.append(f'{pad}"{operation.method}",')
    lines.append(f"{pad}{call_target},")
    if operation.query_params:
        lines.append(f"{pad}query={{")
        for param in operation.query_params:
            lines.append(f'{pad}    "{param.name}": {_parameter_name(param.name)},')
        lines.append(f"{pad}}},")
    if operation.body is not None:
        lines.append(f"{pad}body=body,")
    lines.append(f"{pad}project=project,")
    if operation.paginated:
        lines.append(f"{pad}page=True,")
    if typed_return:
        lines.append("            ),")
        lines.append("        )")
    else:
        lines.append("        )")
    return "\n".join(lines)


def render_python_client(models: Sequence[ModelIr], operations: Sequence[OperationIr]) -> str:
    """The full ``client.py`` text."""
    header = '''"""The generated ARACHNE Python API client — DO NOT EDIT.

Generated by ``python -m arachne.tools.sdkgen`` from the application's own OpenAPI schema
(``arachne.api.app.create_app().openapi()``): one method per documented operation and the
``components.schemas`` models as ``TypedDict``s. Re-run the generator and commit the diff
after any route or schema change; ``python -m arachne.tools.sdkgen --check`` fails on drift
(REQ-ECOS-002).

Two invariants are the point of this client:

* Every request goes through :meth:`Client._request`, which **always** sends the
  ``x-api-key`` header (and ``x-project`` when the client was given one). The constructor
  refuses an empty key, so an unauthenticated request is never sent.
* A ``429`` is **not** retried. A blind retry loop would defeat the server's rate limit;
  the refusal is raised as :class:`ArachneRateLimitError`, which carries the server's
  ``Retry-After`` so the caller can decide.

Parameter names that shadow a Python builtin (``format``, ``next``) carry a trailing
underscore; the wire name in the query string is unchanged.

Schema coverage is partial by design, and the gaps are marked: a free-form object, an
array without ``items`` and a property with no ``type`` become ``object`` with a
``# generic JSON`` comment naming the reason. A non-JSON response body (the report
endpoint's HTML/PDF) is returned as ``str``.
"""'''
    body: list[str] = [header]
    body.append(
        "from __future__ import annotations\n"
        "\n"
        "from collections.abc import Mapping\n"
        "from typing import Generic, Literal, NotRequired, TypedDict, TypeVar, cast\n"
        "from urllib.parse import quote\n"
        "\n"
        f"import {_TRANSPORT_IMPORT}"
    )
    exported = sorted(
        ["ArachneAPIError", "ArachneAuthError", "ArachneClientError", "ArachneConfigError"]
        + ["ArachneRateLimitError", "Client"]
        + [model.name for model in models],
        key=_dotted_sort_key,
    )
    body.append("__all__ = [\n" + "".join(f'    "{item}",\n' for item in exported) + "]")
    body.append(
        'API_KEY_HEADER = "x-api-key"\nPROJECT_HEADER = "x-project"\nDEFAULT_TIMEOUT_S = 30.0'
    )
    body.append(
        '''_T = TypeVar("_T")


class Page(TypedDict, Generic[_T]):
    """One page of a cursor-paginated collection (REQ-UIX-001).

    ``next_cursor`` is the token to pass back as the ``cursor`` query parameter for the
    following page (``None`` once the collection is exhausted); ``prev_cursor`` walks back.
    Both are read from the response's ``Link`` / ``X-Next-Cursor`` headers, so a caller can
    iterate a collection without hand-writing any client code.
    """

    items: list[_T]
    next_cursor: str | None
    prev_cursor: str | None
    has_more: bool
    limit: int | None'''
    )
    body.append(
        '''class ArachneConfigError(ValueError):
    """The client was misconfigured (an empty key, or an unusable base URL)."""'''
    )
    body.append(
        '''class ArachneClientError(Exception):
    """Base class for every error raised for a server response.

    ``status_code`` is the HTTP status the server answered with (``None`` when the
    request never produced a response status) and ``response_headers`` the response's
    headers, so a caller can read ``WWW-Authenticate`` or a rate-limit hint without
    reaching for a raw client.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_headers: dict[str, str] = dict(headers or {})'''
    )
    body.append(
        '''class ArachneAuthError(ArachneClientError):
    """401/403: the key is missing, wrong, or lacks the role/project the call needs."""'''
    )
    body.append(
        '''class ArachneRateLimitError(ArachneClientError):
    """429: the server refused the request against its rate limit.

    ``retry_after`` is the server's ``Retry-After`` header in seconds (``None`` when the
    header is absent or is an HTTP-date). The client deliberately does not retry: hiding
    the refusal behind a retry loop would defeat the very rate limit the server enforces.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        limit: int | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message, status_code=429, headers=headers)
        self.retry_after = retry_after
        self.limit = limit'''
    )
    body.append(
        '''class ArachneAPIError(ArachneClientError):
    """Any other non-2xx response (4xx other than 401/403/429, or 5xx)."""'''
    )
    body.extend(_py_models(models))
    body.append(
        '''def _error_message(response: httpx.Response) -> str:
    """The server's ``{"error": {"message": ...}}`` text, else a plain status line."""
    payload: object = None
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str) and message:
                return message
        detail = payload.get("detail")
        if isinstance(detail, str) and detail:
            return detail
    return f"HTTP {response.status_code}"


def _parse_retry_after(value: str | None) -> float | None:
    """The ``Retry-After`` header in seconds; an HTTP-date (or garbage) is ``None``."""
    if value is None:
        return None
    try:
        return float(value.strip())
    except ValueError:
        return None


def _parse_int(value: str | None) -> int | None:
    """A numeric response header, or ``None`` when it is absent or unparseable."""
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None'''
    )
    client = [
        '''class Client:
    """A typed, authenticated client for the ARACHNE REST API.

    ``base_url`` is the deployment root (``https://arachne.example``); ``api_key`` is
    required and may not be blank. ``project`` pre-selects the ``x-project`` header for
    every request and can be overridden per call. ``transport`` exists so the client can
    be driven over an ASGI transport in a contract test; it cannot bypass auth or rate
    limiting because every request still traverses the server's middleware stack.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        project: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ArachneConfigError(
                "an API key is required; this client never sends an unauthenticated request"
            )
        if not isinstance(base_url, str) or not base_url.strip():
            raise ArachneConfigError("base_url is required")
        cleaned = base_url.strip().rstrip("/")
        if not cleaned.startswith(("http://", "https://")):
            raise ArachneConfigError(f"base_url must be an http(s) URL, got {base_url!r}")
        self._client = httpx.Client(
            base_url=cleaned,
            headers={},
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
        )
        self._api_key = api_key
        self._project = project

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, object] | None = None,
        body: object | None = None,
        project: str | None = None,
        page: bool = False,
    ) -> object:
        """The one egress path: every method funnels through here, and only here.

        It validates the configuration, sets ``x-api-key`` on every call and ``x-project``
        when one is selected, and turns a refusal into a typed error instead of retrying.
        Nothing else in this module opens a socket, which is what makes the header
        guarantee checkable.
        """
        if not self._api_key.strip():
            # Defence in depth: the constructor already refused this, and it stays refused
            # here, so no code path can build a request without a key.
            raise ArachneConfigError("an API key is required; no request is sent without one")
        if not self._client.base_url.is_absolute_url:
            raise ArachneConfigError(f"unusable base URL: {self._client.base_url!r}")
        headers = {API_KEY_HEADER: self._api_key}
        selected = project if project is not None else self._project
        if selected:
            headers[PROJECT_HEADER] = selected
        params: dict[str, object] | None = None
        if query:
            params = {name: value for name, value in query.items() if value is not None}
        response = self._client.request(
            method,
            path,
            params=params,
            json=body,
            headers=headers,
        )
        if response.status_code in {401, 403}:
            raise ArachneAuthError(
                _error_message(response),
                status_code=response.status_code,
                headers=response.headers,
            )
        if response.status_code == 429:
            raise ArachneRateLimitError(
                _error_message(response),
                retry_after=_parse_retry_after(response.headers.get("Retry-After")),
                limit=_parse_int(response.headers.get("X-RateLimit-Limit")),
                headers=response.headers,
            )
        if response.status_code >= 400:
            raise ArachneAPIError(
                _error_message(response),
                status_code=response.status_code,
                headers=response.headers,
            )
        if response.status_code == 204 or not response.content:
            return None
        if "json" not in response.headers.get("Content-Type", ""):
            return response.text
        payload = cast(object, response.json())
        if not page:
            return payload
        return {
            "items": payload,
            "next_cursor": response.headers.get("X-Next-Cursor"),
            "prev_cursor": response.headers.get("X-Prev-Cursor"),
            "has_more": response.headers.get("X-Has-More") == "true",
            "limit": _parse_int(response.headers.get("X-Limit")),
        }'''
    ]
    for operation in operations:
        client.append(_py_method(operation))
    # One blank line between the methods of the class body.
    body.append("\n\n".join(client))
    return _py_join(body)


def render_python_init(models: Sequence[ModelIr]) -> str:
    """The full ``__init__.py`` text."""
    exported = sorted(
        ["ArachneAPIError", "ArachneAuthError", "ArachneClientError", "ArachneConfigError"]
        + ["ArachneRateLimitError", "Client"]
        + [model.name for model in models],
        key=_dotted_sort_key,
    )
    lines = [
        '"""The generated ARACHNE Python API client (REQ-ECOS-002) — DO NOT EDIT.',
        "",
        "Generated by ``python -m arachne.tools.sdkgen``; see ``arachne_client.client`` for",
        "the client itself and the auth/rate-limit contract it implements.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from .client import (",
    ]
    lines.extend(f"    {name}," for name in sorted(exported, key=_import_sort_key))
    lines.append(")")
    lines.append("")
    lines.append("__all__ = [")
    lines.extend(f'    "{name}",' for name in exported)
    lines.append("]")
    return "\n".join(lines) + "\n"


def _ts_doc(text: str, *, indent: int) -> list[str]:
    pad = " " * indent
    lines = _wrap(text.replace("*/", "* /"), MAX_LINE - indent - 6)
    if not lines:
        return []
    if len(lines) == 1:
        return [f"{pad}/** {lines[0]} */"]
    rendered = [f"{pad}/**"]
    rendered.extend(f"{pad} * {line}" for line in lines)
    rendered.append(f"{pad} */")
    return rendered


def render_typescript_types(models: Sequence[ModelIr]) -> str:
    """The full ``types.ts`` text."""
    header = """/**
 * The generated ARACHNE API models — DO NOT EDIT.
 *
 * Generated by `python -m arachne.tools.sdkgen` from the application's own OpenAPI
 * schema (`arachne.api.app.create_app().openapi()`), one interface per
 * `components.schemas` entry. Re-run the generator and commit the diff after any schema
 * change; `python -m arachne.tools.sdkgen --check` fails on drift (REQ-ECOS-002).
 *
 * Field names are the **wire** names (snake_case), so there is no transform between a
 * parsed response and these types. The file is written in erasable TypeScript syntax so
 * Node can run it directly (native type stripping), which is how the contract test
 * exercises it. A schema shape with no faithful type (a free-form object, an array
 * without `items`, a property with no `type`) is `unknown` or `Record<string, unknown>`
 * with a `// generic JSON` comment naming the reason.
 */
"""
    blocks: list[str] = [header.rstrip("\n")]
    blocks.append(
        """/**
 * One page of a cursor-paginated collection (REQ-UIX-001).
 *
 * `next_cursor` is the token to pass back as the `cursor` query option for the following
 * page (`null` once the collection is exhausted); `prev_cursor` walks back. Both are read
 * from the response's `Link` / `X-Next-Cursor` headers, so a caller can iterate a
 * collection without hand-writing any client code.
 */
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  prev_cursor: string | null;
  has_more: boolean;
  limit: number | null;
}"""
    )
    for model in models:
        lines: list[str] = []
        lines.extend(_ts_doc(model.doc, indent=0))
        lines.append(f"export interface {model.name} {{")
        for field in model.fields:
            if field.type.note is not None:
                lines.append(f"  // generic JSON: {field.type.note}")
            optional = "" if field.required else "?"
            annotation = field.type.ts
            if not field.required and field.type.note is None:
                annotation = _optionalize_ts(annotation)
            lines.append(f"  {field.name}{optional}: {annotation};")
        lines.append("}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n"


def _ts_options_entries(operation: OperationIr) -> list[str]:
    """One ``name?: type;`` entry per query parameter, plus the shared ``project``."""
    entries: list[str] = []
    for param in operation.query_params:
        name = _camel(param.name)
        if param.required:
            entries.append(f"{name}: {param.type.ts};")
        else:
            entries.append(f"{name}?: {_optionalize_ts(param.type.ts)};")
    entries.append("project?: string | null;")
    return entries


def _ts_path_expression(operation: OperationIr) -> str:
    if not operation.path_params:
        return '"' + operation.path + '"'
    expression = "`" + operation.path + "`"
    for param in operation.path_params:
        token = "{" + param.name + "}"
        name = _camel(param.name)
        expression = expression.replace(token, "${encodeURIComponent(String(" + name + "))}")
    return expression


def _ts_method(operation: OperationIr) -> str:
    path_args = [f"{_camel(param.name)}: {param.type.ts}" for param in operation.path_params]
    if operation.body is not None:
        path_args.append(f"body: {operation.body.model}")
    entries = _ts_options_entries(operation)
    inline = "{ " + " ".join(entries) + " }"
    suffix = "" if any(param.required for param in operation.query_params) else " = {}"
    returns = operation.returns.ts
    options_arg = f"options: {inline}{suffix}"
    one_line = (
        f"  async {_camel(operation.name)}"
        f"({', '.join([*path_args, options_arg])}): Promise<{returns}> {{"
    )
    options_fits = len(options_arg) + 4 <= MAX_LINE
    lines: list[str] = []
    if options_fits and len(one_line) <= MAX_LINE:
        lines.append(one_line)
    else:
        lines.append(f"  async {_camel(operation.name)}(")
        lines.extend(f"    {arg}," for arg in path_args)
        if options_fits:
            lines.append(f"    {options_arg},")
        else:
            lines.append("    options: {")
            lines.extend(f"      {entry}" for entry in entries)
            lines.append(f"    }}{suffix},")
        lines.append(f"  ): Promise<{returns}> {{")
    doc = (
        f"{operation.summary} {operation.method} {operation.path} "
        f"(operationId `{operation.operation_id}`)."
    )
    if operation.returns.note is not None:
        doc += f" The success body is generic JSON: {operation.returns.note}."
    lines.extend(_ts_doc(doc, indent=4))
    lines.append(f"    return this.request<{returns}>(")
    lines.append(f'      "{operation.method}",')
    lines.append(f"      {_ts_path_expression(operation)},")
    lines.append("      {")
    if operation.query_params:
        wire = [f"{param.name}: options.{_camel(param.name)}" for param in operation.query_params]
        query_one_line = "{ " + ", ".join(wire) + " }"
        if len(query_one_line) + 15 <= MAX_LINE:
            lines.append(f"        query: {query_one_line},")
        else:
            lines.append("        query: {")
            lines.extend(f"          {entry}," for entry in wire)
            lines.append("        },")
    if operation.body is not None:
        lines.append("        body,")
    lines.append("        project: options.project,")
    lines.append("      },")
    if operation.paginated:
        lines.append("      true,")
    lines.append("    );")
    lines.append("  }")
    return "\n".join(lines)


def _ts_referenced_models(
    models: Sequence[ModelIr], operations: Sequence[OperationIr]
) -> list[str]:
    """The top-level model names ``client.ts`` must import from ``types.ts``."""
    known = {model.name for model in models}
    referenced: set[str] = set()
    for operation in operations:
        types = [operation.returns]
        types.extend(param.type for param in operation.path_params)
        types.extend(param.type for param in operation.query_params)
        if operation.body is not None:
            types.append(operation.body.type)
        for type_ in types:
            referenced.update(name for name in type_.refs if name in known)
        if operation.paginated:
            # The page envelope is not a schema from the document, so it is not in ``known``;
            # it is still a type ``client.ts`` imports from ``types.ts``.
            referenced.add("Page")
    return sorted(referenced)


def render_typescript_client(models: Sequence[ModelIr], operations: Sequence[OperationIr]) -> str:
    """The full ``client.ts`` text."""
    used = _ts_referenced_models(models, operations)
    lines = [
        "/**",
        " * The generated ARACHNE TypeScript API client — DO NOT EDIT.",
        " *",
        " * Generated by `python -m arachne.tools.sdkgen` from the application's own OpenAPI",
        " * schema (`arachne.api.app.create_app().openapi()`): one method per documented",
        " * operation. Re-run the generator and commit the diff after any route change;",
        " * `python -m arachne.tools.sdkgen --check` fails on drift (REQ-ECOS-002).",
        " *",
        " * Two invariants are the point of this client:",
        " *",
        " *  - Every request goes through `request()`, which **always** sends the `x-api-key`",
        " *    header (and `x-project` when the client has one). The constructor refuses an",
        " *    empty key, so an unauthenticated request is never sent.",
        " *  - A `429` is **not** retried; a blind retry loop would defeat the server's rate",
        " *    limit. It is raised as `ArachneRateLimitError`, carrying `retryAfter`.",
        " *",
        " * Erasable-syntax TypeScript only (no enums, namespaces or parameter properties) so",
        " * Node can execute this file directly via native type stripping. It uses the global",
        " * `fetch`. Method/option names are camelCase; the wire field names in `types.ts`",
        " * are the snake_case JSON keys.",
        " */",
        "",
    ]
    if used:
        lines.append("import type {")
        lines.extend(f"  {name}," for name in used)
        lines.append('} from "./types.ts";')
        lines.append("")
    lines.append('export const API_KEY_HEADER = "x-api-key";')
    lines.append('export const PROJECT_HEADER = "x-project";')
    lines.append("export const DEFAULT_TIMEOUT_MS = 30_000;")
    lines.append("")
    lines.append("/** A value that can be sent as a query-string parameter. */")
    lines.append("export type QueryValue = string | number | boolean;")
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/** The client was misconfigured (an empty key, or an unusable base URL). */",
                "export class ArachneConfigError extends Error {}",
            ]
        )
    )
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/** Base class for every error raised for a server response. */",
                "export class ArachneClientError extends Error {",
                "  /** The HTTP status the server answered with (null if none). */",
                "  readonly statusCode: number | null;",
                "  /** Response headers, e.g. `WWW-Authenticate` or a rate-limit hint. */",
                "  readonly responseHeaders: Record<string, string>;",
                "",
                "  constructor(",
                "    message: string,",
                "    statusCode: number | null = null,",
                "    responseHeaders: Record<string, string> = {},",
                "  ) {",
                "    super(message);",
                '    this.name = "ArachneClientError";',
                "    this.statusCode = statusCode;",
                "    this.responseHeaders = responseHeaders;",
                "  }",
                "}",
            ]
        )
    )
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/** 401/403: the key is missing, wrong, or lacks the needed role/project. */",
                "export class ArachneAuthError extends ArachneClientError {",
                "  constructor(",
                "    message: string,",
                "    statusCode: number | null = null,",
                "    responseHeaders: Record<string, string> = {},",
                "  ) {",
                "    super(message, statusCode, responseHeaders);",
                '    this.name = "ArachneAuthError";',
                "  }",
                "}",
            ]
        )
    )
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/**",
                " * 429: the server refused the request against its rate limit.",
                " *",
                " * `retryAfter` is the server's `Retry-After` header in seconds (null when absent",
                " * or an HTTP-date). The client deliberately does not retry: hiding the refusal",
                " * behind a retry loop would defeat the very rate limit the server enforces.",
                " */",
                "export class ArachneRateLimitError extends ArachneClientError {",
                "  readonly retryAfter: number | null;",
                "  readonly limit: number | null;",
                "",
                "  constructor(",
                "    message: string,",
                "    retryAfter: number | null = null,",
                "    limit: number | null = null,",
                "    responseHeaders: Record<string, string> = {},",
                "  ) {",
                "    super(message, 429, responseHeaders);",
                '    this.name = "ArachneRateLimitError";',
                "    this.retryAfter = retryAfter;",
                "    this.limit = limit;",
                "  }",
                "}",
            ]
        )
    )
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/** Any other non-2xx response (4xx other than 401/403/429, or 5xx). */",
                "export class ArachneAPIError extends ArachneClientError {",
                "  constructor(",
                "    message: string,",
                "    statusCode: number | null = null,",
                "    responseHeaders: Record<string, string> = {},",
                "  ) {",
                "    super(message, statusCode, responseHeaders);",
                '    this.name = "ArachneAPIError";',
                "  }",
                "}",
            ]
        )
    )
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/** Options common to every generated method. */",
                "export interface RequestOptions {",
                "  query?: Record<string, QueryValue | null | undefined>;",
                "  body?: unknown;",
                "  project?: string | null;",
                "}",
            ]
        )
    )
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/**",
                " * A typed, authenticated client for the ARACHNE REST API.",
                " *",
                " * `baseUrl` is the deployment root; `apiKey` is required and may not be blank.",
                " * `project` pre-selects the `x-project` header for every request and can be",
                " * overridden per call.",
                " */",
                "export class ArachneClient {",
                "  private readonly baseUrl: string;",
                "  private readonly apiKey: string;",
                "  private readonly project: string | null;",
                "  private readonly timeoutMs: number;",
                "",
                "  constructor(options: {",
                "    baseUrl: string;",
                "    apiKey: string;",
                "    project?: string | null;",
                "    timeoutMs?: number;",
                "  }) {",
                '    if (typeof options.apiKey !== "string" || options.apiKey.trim() === "") {',
                "      throw new ArachneConfigError(",
                '        "an API key is required; unauthenticated requests are never sent",',
                "      );",
                "    }",
                '    if (typeof options.baseUrl !== "string" || options.baseUrl.trim() === "") {',
                '      throw new ArachneConfigError("baseUrl is required");',
                "    }",
                '    const cleaned = options.baseUrl.trim().replace(/\\/+$/, "");',
                "    let parsed: URL;",
                "    try {",
                "      parsed = new URL(cleaned);",
                "    } catch {",
                "      throw new ArachneConfigError(",
                "        `baseUrl must be an absolute http(s) URL: ${options.baseUrl}`,",
                "      );",
                "    }",
                '    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {',
                "      throw new ArachneConfigError(`not an http(s) URL: ${options.baseUrl}`);",
                "    }",
                "    this.baseUrl = cleaned;",
                "    this.apiKey = options.apiKey;",
                "    this.project = options.project ?? null;",
                "    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;",
                "  }",
                "",
                "  /**",
                "   * The one egress path: every method funnels through here, and only here.",
                "   *",
                "   * It sets `x-api-key` on every call and `x-project` when set, and it",
                "   * turns a refusal into a typed error instead of retrying: `fetch`",
                '   * appears nowhere else, so "the header is sent" is checkable here.',
                "   */",
                "  private async request<T>(",
                "    method: string,",
                "    path: string,",
                "    options: RequestOptions = {},",
                "    page = false,",
                "  ): Promise<T> {",
                '    if (this.apiKey.trim() === "") {',
                "      // Defence in depth: the constructor already refused this, and it stays",
                "      // refused here, so no path can build a request without a key.",
                "      throw new ArachneConfigError(",
                '        "an API key is required; no request is sent without one",',
                "      );",
                "    }",
                "    const headers: Record<string, string> = { [API_KEY_HEADER]: this.apiKey };",
                "    const selected = options.project ?? this.project;",
                "    if (selected) {",
                "      headers[PROJECT_HEADER] = selected;",
                "    }",
                "    const url = new URL(this.baseUrl + path);",
                "    for (const [name, value] of Object.entries(options.query ?? {})) {",
                "      if (value !== undefined && value !== null) {",
                "        url.searchParams.set(name, String(value));",
                "      }",
                "    }",
                "    const init: RequestInit = {",
                "      method,",
                "      headers,",
                '      redirect: "manual",',
                "      signal: AbortSignal.timeout(this.timeoutMs),",
                "    };",
                "    if (options.body !== undefined && options.body !== null) {",
                '      headers["content-type"] = "application/json";',
                "      init.body = JSON.stringify(options.body);",
                "    }",
                "    // `fetch` is the single network call in this module. The API key header is",
                "    // set above in all cases: there is no unauthenticated request path.",
                "    const response = await fetch(url, init);",
                "    if (response.status === 401 || response.status === 403) {",
                "      throw new ArachneAuthError(",
                "        await this.errorMessage(response),",
                "        response.status,",
                "        headersToRecord(response.headers),",
                "      );",
                "    }",
                "    if (response.status === 429) {",
                "      throw new ArachneRateLimitError(",
                "        await this.errorMessage(response),",
                '        parseRetryAfter(response.headers.get("retry-after")),',
                '        parseIntOrNull(response.headers.get("x-ratelimit-limit")),',
                "        headersToRecord(response.headers),",
                "      );",
                "    }",
                "    if (!response.ok) {",
                "      throw new ArachneAPIError(",
                "        await this.errorMessage(response),",
                "        response.status,",
                "        headersToRecord(response.headers),",
                "      );",
                "    }",
                "    if (response.status === 204) {",
                "      return null as T;",
                "    }",
                "    const text = await response.text();",
                '    if (text === "") {',
                "      return null as T;",
                "    }",
                '    const contentType = response.headers.get("content-type") ?? "";',
                '    if (contentType.includes("json")) {',
                "      const payload = JSON.parse(text) as unknown;",
                "      if (!page) {",
                "        return payload as T;",
                "      }",
                "      return {",
                "        items: payload,",
                '        next_cursor: response.headers.get("x-next-cursor"),',
                '        prev_cursor: response.headers.get("x-prev-cursor"),',
                '        has_more: response.headers.get("x-has-more") === "true",',
                '        limit: parseIntOrNull(response.headers.get("x-limit")),',
                "      } as unknown as T;",
                "    }",
                "    return text as T;",
                "  }",
                "",
                "  private async errorMessage(response: Response): Promise<string> {",
                "    let payload: unknown = null;",
                "    try {",
                "      payload = await response.json();",
                "    } catch {",
                "      payload = null;",
                "    }",
                '    if (payload !== null && typeof payload === "object") {',
                "      const record = payload as Record<string, unknown>;",
                '      const error = record["error"];',
                '      if (error !== null && typeof error === "object") {',
                '        const message = (error as Record<string, unknown>)["message"];',
                '        if (typeof message === "string" && message !== "") {',
                "          return message;",
                "        }",
                "      }",
                '      const detail = record["detail"];',
                '      if (typeof detail === "string" && detail !== "") {',
                "        return detail;",
                "      }",
                "    }",
                "    return `HTTP ${response.status}`;",
                "  }",
            ]
        )
    )
    # The generated operations are members of the class, so they go before its brace.
    for operation in operations:
        lines.append("")
        lines.append(_ts_method(operation))
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append(
        "\n".join(
            [
                "/** The `Retry-After` header in seconds; an HTTP-date (or garbage) is null. */",
                "function parseRetryAfter(value: string | null): number | null {",
                '  if (value === null || value.trim() === "") {',
                "    return null;",
                "  }",
                "  const parsed = Number(value.trim());",
                "  return Number.isFinite(parsed) ? parsed : null;",
                "}",
                "",
                "/** A numeric response header, or null when it is absent or unparseable. */",
                "function parseIntOrNull(value: string | null): number | null {",
                '  if (value === null || value.trim() === "") {',
                "    return null;",
                "  }",
                "  const parsed = Number.parseInt(value.trim(), 10);",
                "  return Number.isNaN(parsed) ? null : parsed;",
                "}",
                "",
                "/** The response headers as a plain object, for an error a caller can inspect. */",
                "function headersToRecord(headers: Headers): Record<string, string> {",
                "  const record: Record<string, string> = {};",
                "  headers.forEach((value, name) => {",
                "    record[name] = value;",
                "  });",
                "  return record;",
                "}",
            ]
        )
    )
    return "\n".join(lines) + "\n"


def _render_all() -> dict[str, str]:
    """Every generated file, keyed by its path relative to the clients root."""
    spec = load_spec()
    models = _models(spec)
    operations = _operations(spec, frozenset(model.name for model in models))
    return {
        "python/arachne_client/__init__.py": render_python_init(models),
        "python/arachne_client/client.py": render_python_client(models, operations),
        "typescript/src/client.ts": render_typescript_client(models, operations),
        "typescript/src/types.ts": render_typescript_types(models),
    }


# --------------------------------------------------------------------------- entry points
def clients_root() -> Path:
    """The repository's ``code/clients`` directory — where the committed clients live."""
    return Path(__file__).resolve().parents[3] / "clients"


def generate(root: Path | None = None) -> list[Path]:
    """Write every generated file under ``root`` (default :func:`clients_root`)."""
    target_root = clients_root() if root is None else root
    written: list[Path] = []
    rendered = _render_all()
    for relative in GENERATED_FILES:
        target = target_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered[relative], encoding="utf-8")
        written.append(target)
    return written


def check(root: Path | None = None) -> list[Path]:
    """Regenerate into memory and return the owned files that differ from the tree."""
    target_root = clients_root() if root is None else root
    rendered = _render_all()
    drift: list[Path] = []
    for relative in GENERATED_FILES:
        target = target_root / relative
        if not target.is_file() or target.read_text(encoding="utf-8") != rendered[relative]:
            drift.append(target)
    return drift


def main(argv: list[str] | None = None) -> int:
    """Write the clients, or (``--check``) verify the committed ones are up to date."""
    parser = argparse.ArgumentParser(
        prog="python -m arachne.tools.sdkgen",
        description="Generate the Python and TypeScript API clients from the live OpenAPI schema.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="write below this directory (default: the repository's clients/ tree)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in memory and fail when a committed client has drifted",
    )
    args = parser.parse_args(argv)
    out: str | None = args.out
    root = Path(out) if out is not None else clients_root()
    if args.check:
        drift = check(root)
        if drift:
            for path in drift:
                sys.stderr.write(f"sdkgen: out of date: {path}\n")
            sys.stderr.write("sdkgen: run `python -m arachne.tools.sdkgen` and commit the result\n")
            return 1
        sys.stdout.write(f"sdkgen: {len(GENERATED_FILES)} generated files are up to date\n")
        return 0
    for path in generate(root):
        sys.stdout.write(f"sdkgen: wrote {path}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
