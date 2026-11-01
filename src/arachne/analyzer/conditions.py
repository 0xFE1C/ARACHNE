"""The restricted condition language the rule engine evaluates (F-08-06).

Rule bodies are *data*: an operator edits a YAML file, not the scanner. That makes rule
evaluation a security boundary — the expression text is parsed here and interpreted by a
hand-written evaluator, and **``eval``/``exec`` never appear** (F-08-06;
``tests/unit/test_no_eval_exec.py`` keeps the whole tree free of them). The grammar is
deliberately tiny:

.. code-block:: text

    expression := or
    or         := and ("or" and)*
    and        := not ("and" not)*
    not        := "not" not | comparison
    comparison := operand ( op operand )?
    operand    := path | literal | "(" expression ")"
    op         := == != >= <= > < in "not in" matches contains startswith endswith
    literal    := number | "string" | 'string' | true | false | null | [literal, ...]

Paths address the *fact space* (:func:`build_facts`): ``evidence.http_response.body``,
``check.module``, ``analysis.verification_count``, ``asset.kind``. A path that resolves to
several values (three ``artifact`` evidence rows, say) compares with **any** semantics, and a
path that resolves to nothing makes every comparison false, so a rule can never fire on a
fact the candidate does not have. A few bare names are aliases, so a rule can read like
 (``http_status == 200``).

Rule-local condition names (``conditions:`` in the YAML) resolve first, which is what lets
one named condition be reused by both ``severity_if`` and ``confidence``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = [
    "ConditionError",
    "FactSpace",
    "ParsedExpression",
    "build_facts",
    "evaluate",
    "parse_expression",
]

#: Maximum length of a regex a rule may use. A pattern longer than this is a mistake, not a
#: technique, and the bound keeps a malicious or careless corpus entry cheap to reject.
MAX_PATTERN_LENGTH: Final = 500


class ConditionError(ConfigurationError):
    """A condition expression could not be parsed or evaluated."""


class _Missing:
    """Sentinel for "this fact is absent" (distinct from ``None``, which is a real value)."""

    _instance: _Missing | None = None

    def __new__(cls) -> _Missing:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING: Final = _Missing()

# --------------------------------------------------------------------------- AST


@dataclass(frozen=True, slots=True)
class Path:
    """A fact reference, e.g. ``evidence.http_response.body``."""

    text: str
    segments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Literal:
    value: Any


@dataclass(frozen=True, slots=True)
class Compare:
    op: str
    left: Path | Literal
    right: Path | Literal


@dataclass(frozen=True, slots=True)
class Truthy:
    """A bare operand used as a boolean (``matched_patterns``, ``reproducible``)."""

    operand: Path | Literal


@dataclass(frozen=True, slots=True)
class NotOp:
    operand: Node


@dataclass(frozen=True, slots=True)
class BoolOp:
    op: str  # "and" | "or"
    items: tuple[Node, ...]


Node = Path | Literal | Compare | Truthy | NotOp | BoolOp

_OPERATORS: Final = (
    "==",
    "!=",
    ">=",
    "<=",
    ">",
    "<",
)
_WORD_OPERATORS: Final = ("matches", "contains", "startswith", "endswith", "in")
#: Postfix presence operators: ``path present``, ``path missing``.
_PRESENCE_OPERATORS: Final = ("present", "missing")
_KEYWORDS: Final = frozenset({"and", "or", "not", "in", "true", "false", "null"})

_TOKEN = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<op>==|!=|>=|<=|>|<)
  | (?P<punct>[\[\](),])
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<word>[A-Za-z_$][A-Za-z0-9_$-]*(?:\.[A-Za-z0-9_$-]+)*)
    """,
    re.VERBOSE,
)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    text: str
    pos: int


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(text):
        match = _TOKEN.match(text, position)
        if match is None:
            raise ConditionError(
                f"invalid condition {text!r}: unexpected character {text[position]!r} "
                f"at offset {position}"
            )
        position = match.end()
        kind = match.lastgroup or ""
        if kind == "space":
            continue
        tokens.append(_Token(kind=kind, text=match.group(0), pos=match.start()))
    return tokens


class _Parser:
    """Recursive-descent parser for the grammar in the module docstring."""

    def __init__(self, text: str, tokens: Sequence[_Token]) -> None:
        self.text = text
        self.tokens = tokens
        self.index = 0

    # ------------------------------------------------------------------ helpers
    def _peek(self) -> _Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _next(self) -> _Token:
        token = self._peek()
        if token is None:
            raise ConditionError(f"invalid condition {self.text!r}: unexpected end of input")
        self.index += 1
        return token

    def _accept_word(self, *words: str) -> str | None:
        token = self._peek()
        if token is not None and token.kind == "word" and token.text.lower() in words:
            self.index += 1
            return token.text.lower()
        return None

    def _accept_op(self, *ops: str) -> str | None:
        token = self._peek()
        if token is not None and token.kind == "op" and token.text in ops:
            self.index += 1
            return token.text
        return None

    def _expect_punct(self, punct: str) -> None:
        token = self._peek()
        if token is None or token.kind != "punct" or token.text != punct:
            found = "end of input" if token is None else repr(token.text)
            raise ConditionError(
                f"invalid condition {self.text!r}: expected {punct!r}, found {found}"
            )
        self.index += 1

    # ------------------------------------------------------------------ grammar
    def parse(self) -> Node:
        node = self.parse_or()
        if self._peek() is not None:
            remaining = self._peek()
            assert remaining is not None
            raise ConditionError(
                f"invalid condition {self.text!r}: unexpected trailing token "
                f"{remaining.text!r} at offset {remaining.pos}"
            )
        return node

    def parse_or(self) -> Node:
        items = [self.parse_and()]
        while self._accept_word("or") is not None:
            items.append(self.parse_and())
        return items[0] if len(items) == 1 else BoolOp(op="or", items=tuple(items))

    def parse_and(self) -> Node:
        items = [self.parse_not()]
        while self._accept_word("and") is not None:
            items.append(self.parse_not())
        return items[0] if len(items) == 1 else BoolOp(op="and", items=tuple(items))

    def parse_not(self) -> Node:
        if self._accept_word("not") is not None:
            return NotOp(operand=self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> Node:
        left = self.parse_operand()
        op = self._accept_op(*_OPERATORS)
        if op is None:
            # ``not in`` is one operator written as two words, so it is recognised before the
            # single-word operators.
            if self._accept_word("not") is not None:
                if self._accept_word("in") is None:
                    raise ConditionError(
                        f"invalid condition {self.text!r}: 'not' before an operator is only "
                        "valid as 'not in'"
                    )
                op = "not in"
            else:
                word_op = self._accept_word(*_WORD_OPERATORS)
                if word_op is None:
                    # ``path present`` / ``path missing``: the presence tests. They are the
                    # only way to ask about a fact a check did *not* capture, which is what
                    # header, WAF and placeholder rules need.
                    presence = self._accept_word(*_PRESENCE_OPERATORS)
                    if presence is not None:
                        return Compare(op=presence, left=left, right=Literal(value=None))
                    return Truthy(operand=left)
                op = word_op
        right = self.parse_operand()
        return Compare(op=op, left=left, right=right)

    def parse_operand(self) -> Path | Literal:
        token = self._peek()
        if token is None:
            raise ConditionError(f"invalid condition {self.text!r}: unexpected end of input")
        if token.kind == "punct" and token.text == "(":
            self.index += 1
            node = self.parse_or()
            self._expect_punct(")")
            return Literal(value=node)  # nested expression, evaluated as a boolean
        if token.kind == "punct" and token.text == "[":
            return Literal(value=self.parse_list())
        if token.kind == "number":
            self.index += 1
            return Literal(value=_number(token.text))
        if token.kind == "string":
            self.index += 1
            return Literal(value=_unquote(token.text))
        if token.kind == "word":
            lowered = token.text.lower()
            if lowered == "true":
                self.index += 1
                return Literal(value=True)
            if lowered == "false":
                self.index += 1
                return Literal(value=False)
            if lowered == "null":
                self.index += 1
                return Literal(value=None)
            if lowered == "not":
                raise ConditionError(
                    f"invalid condition {self.text!r}: 'not' cannot start an operand; write "
                    "'not (expression)' or use the 'not in' operator"
                )
            self.index += 1
            return Path(text=token.text, segments=tuple(token.text.split(".")))
        raise ConditionError(
            f"invalid condition {self.text!r}: unexpected token {token.text!r} at offset "
            f"{token.pos}"
        )

    def parse_list(self) -> list[Any]:
        self._expect_punct("[")
        items: list[Any] = []
        if self._is_punct("]"):
            self.index += 1
            return items
        while True:
            operand = self.parse_operand()
            if isinstance(operand, Path):
                raise ConditionError(
                    f"invalid condition {self.text!r}: a list literal cannot contain the path "
                    f"{operand.text!r}"
                )
            items.append(operand.value)
            if self._is_punct(","):
                self.index += 1
                continue
            break
        self._expect_punct("]")
        return items

    def _is_punct(self, punct: str) -> bool:
        """True when the next token is ``punct`` (a small reader for the list grammar)."""
        token = self._peek()
        return token is not None and token.kind == "punct" and token.text == punct


def _number(text: str) -> float | int:
    if "." in text:
        return float(text)
    return int(text)


def _unquote(text: str) -> str:
    quote = text[0]
    body = text[1:-1]
    # Only the escapes a rule author needs; the input is trusted rule data, not target data.
    return body.replace(f"\\{quote}", quote).replace("\\\\", "\\")


@dataclass(frozen=True, slots=True)
class ParsedExpression:
    """A parsed condition plus the original text (kept for the rule trace)."""

    node: Node
    text: str

    def evaluate(self, facts: FactSpace, conditions: Mapping[str, bool] | None = None) -> bool:
        return evaluate(self.node, facts, conditions)

    def describe(self) -> str:
        return self.text


def parse_expression(text: str) -> ParsedExpression:
    """Parse one condition expression; raises :class:`ConditionError` on bad syntax."""
    if not isinstance(text, str) or not text.strip():
        msg = f"condition expression must be a non-empty string, got {text!r}"
        raise ConditionError(msg)
    parser = _Parser(text, _tokenize(text))
    return ParsedExpression(node=parser.parse(), text=text.strip())


# --------------------------------------------------------------------------- fact space

#: Bare names the examples use, mapped onto the fact they mean.
ALIASES: Final[dict[str, str]] = {
    "http_status": "evidence.http_response.status_code",
    "http_body": "evidence.http_response.body",
    "verification_count": "analysis.verification_count",
    "reproducible": "analysis.reproducible",
    "verifiable": "analysis.verifiable",
    "asset_kind": "asset.kind",
    "asset_value": "asset.value",
    "asset_host": "asset.host",
    "asset_criticality": "asset.criticality",
    "check": "check.id",
    "check_id": "check.id",
    "module": "check.module",
    "research_ref": "check.research_ref",
    "cwe": "check.cwe",
    "cve": "check.cve",
    "title": "finding.title",
    "status": "finding.status",
    "confidence": "finding.confidence",
    "severity_hint": "check.severity_hint",
    "evidence_count": "analysis.evidence_count",
    "evidence_kinds": "analysis.evidence_kinds",
    # The check writes ``evidence.http_status`` and
    # ``evidence.verification_count``; both are facts under an evidence-ish spelling, so a
    # corpus can keep the spec's wording.
    "evidence.http_status": "evidence.http_response.status_code",
    "evidence.http_body": "evidence.http_response.body",
    "evidence.verification_count": "analysis.verification_count",
    "evidence.reproducible": "analysis.reproducible",
    "evidence.verified_reproducible": "analysis.reproducible",
}


class FactSpace:
    """Resolves dotted fact paths against the nested mapping :func:`build_facts` produced.

    Resolution is *permissive downward*: when an intermediate value is a list (several
    evidence rows of one kind), the remaining path is resolved against every element and the
    results are collected — which is what gives comparisons their any-semantics. A missing
    key returns :data:`MISSING` rather than raising, so one rule referencing a fact a given
    check never produces cannot break the scan.
    """

    def __init__(self, facts: Mapping[str, Any]) -> None:
        self._facts: dict[str, Any] = dict(facts)

    def __contains__(self, path: str) -> bool:
        return self.get(path) is not MISSING

    def get(self, path: str) -> Any:
        """The first value at ``path``, or :data:`MISSING`."""
        values = self.values(path)
        if not values:
            return MISSING
        return values[0]

    def values(self, path: str) -> list[Any]:
        """Every value at ``path`` (empty when absent)."""
        resolved = ALIASES.get(path, path)
        segments = tuple(resolved.split("."))
        return _walk(self._facts, segments)

    def as_mapping(self) -> dict[str, Any]:
        """A shallow copy of the raw tree (the correlation engine extends it with its facts)."""
        return dict(self._facts)

    def leaves(self) -> dict[str, Any]:
        """Flattened scalar view, for narratives and debugging."""
        flat: dict[str, Any] = {}
        _flatten(self._facts, "", flat)
        return flat


def _walk(node: Any, segments: tuple[str, ...]) -> list[Any]:
    if not segments:
        if isinstance(node, list):
            return list(node)
        return [node]
    head, rest = segments[0], segments[1:]
    if isinstance(node, Mapping):
        if head in node:
            return _walk(node[head], rest)
        # A payload key may itself contain dots (``evidence.artifact.api.version``); prefer
        # the longest matching key so such a fact stays addressable.
        for size in range(len(segments), 0, -1):
            joined = ".".join(segments[:size])
            if joined in node:
                return _walk(node[joined], segments[size:])
        return []
    if isinstance(node, list):
        found: list[Any] = []
        for item in node:
            found.extend(_walk(item, segments))
        return found
    return []


def _flatten(node: Any, prefix: str, out: dict[str, Any]) -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            _flatten(value, f"{prefix}.{key}" if prefix else str(key), out)
        return
    if isinstance(node, list):
        for index, value in enumerate(node):
            _flatten(value, f"{prefix}[{index}]", out)
        return
    out[prefix] = node


# --------------------------------------------------------------------------- evaluation


def evaluate(node: Node, facts: FactSpace, conditions: Mapping[str, bool] | None = None) -> bool:
    """Evaluate a parsed node against a fact space and the rule's resolved conditions."""
    if isinstance(node, BoolOp):
        return _evaluate_bool(node, facts, conditions)
    return bool(_value_of(node, facts, conditions))


def _evaluate_bool(node: BoolOp, facts: FactSpace, conditions: Mapping[str, bool] | None) -> bool:
    if node.op == "and":
        return all(evaluate(item, facts, conditions) for item in node.items)
    return any(evaluate(item, facts, conditions) for item in node.items)


def _value_of(node: Node, facts: FactSpace, conditions: Mapping[str, bool] | None) -> Any:
    """The first value of an operand-position node (used for traces and prose)."""
    if isinstance(node, Literal):
        if isinstance(node.value, (Path, Compare, Truthy, NotOp, BoolOp)):
            return evaluate(node.value, facts, conditions)  # a parenthesised sub-expression
        return node.value
    if isinstance(node, Path):
        values = _operand_values(node, facts, conditions)
        if not values:
            return MISSING
        return values[0] if len(values) == 1 else values
    if isinstance(node, Compare):
        return _compare_node(node, facts, conditions)
    if isinstance(node, Truthy):
        return _truthy(node.operand, facts, conditions)
    if isinstance(node, NotOp):
        return not evaluate(node.operand, facts, conditions)
    return evaluate(node, facts, conditions)


def _operand_values(
    node: Path | Literal | Compare | Truthy | NotOp | BoolOp,
    facts: FactSpace,
    conditions: Mapping[str, bool] | None,
) -> list[Any]:
    """Every value an operand contributes, which is what gives comparisons any-semantics."""
    if isinstance(node, Path):
        if conditions and node.text in conditions:
            return [conditions[node.text]]
        return facts.values(node.text)
    if isinstance(node, Literal):
        if isinstance(node.value, (Path, Compare, Truthy, NotOp, BoolOp)):
            return [evaluate(node.value, facts, conditions)]
        if isinstance(node.value, (list, tuple)):
            return list(node.value)
        return [node.value]
    return [_value_of(node, facts, conditions)]


def _truthy(
    node: Path | Literal | Compare | Truthy | NotOp | BoolOp,
    facts: FactSpace,
    conditions: Mapping[str, bool] | None,
) -> bool:
    """True when at least one of the operand's values is truthy."""
    return any(
        bool(value) for value in _operand_values(node, facts, conditions) if value is not MISSING
    )


def _compare_node(node: Compare, facts: FactSpace, conditions: Mapping[str, bool] | None) -> bool:
    if node.op in _PRESENCE_OPERATORS:
        present = _truthy(node.left, facts, conditions)
        return present if node.op == "present" else not present
    left = _operand_values(node.left, facts, conditions)
    right = _operand_values(node.right, facts, conditions)
    if not left:
        # A fact the candidate does not have satisfies nothing (see the module docstring);
        # a rule negates with ``not (...)`` — or asks directly with ``path missing``.
        return False
    return any(_compare_scalar(node.op, lvalue, right) for lvalue in left)


def _compare_scalar(op: str, left: Any, right: Sequence[Any]) -> bool:
    if left is MISSING:
        return False
    if op == "==":
        return any(left == item for item in right)
    if op == "!=":
        return all(left != item for item in right)
    if op in {">", ">=", "<", "<="}:
        return any(_numeric_compare(op, left, item) for item in right)
    if op == "in":
        return any(_member(left, item) for item in right)
    if op == "not in":
        return not any(_member(left, item) for item in right)
    if op in {"matches", "contains", "startswith", "endswith"}:
        return any(_string_op(op, left, item) for item in right)
    raise ConditionError(f"unsupported operator {op!r}")


def _numeric_compare(op: str, left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return False
    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
        return False
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    return left <= right


def _member(value: Any, container: Any) -> bool:
    if isinstance(container, (list, tuple, set, frozenset)):
        return any(value == item for item in container)
    if isinstance(container, str) and isinstance(value, str):
        return value in container
    return bool(value == container)


def _string_op(op: str, left: Any, right: Any) -> bool:
    text = left if isinstance(left, str) else _stringify(left)
    pattern = right if isinstance(right, str) else _stringify(right)
    if op == "matches":
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise ConditionError(
                f"regex pattern is {len(pattern)} characters long; the limit is "
                f"{MAX_PATTERN_LENGTH}"
            )
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ConditionError(f"invalid regex {pattern!r}: {exc}") from exc
        return compiled.search(text) is not None
    if op == "contains":
        if isinstance(left, (list, tuple, set, frozenset)):
            return any(_stringify(item) == pattern for item in left)
        return pattern in text
    if op == "startswith":
        return text.startswith(pattern)
    return text.endswith(pattern)


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


# --------------------------------------------------------------------------- fact builder

#: Evidence kinds whose presence counts as "we captured a request/response pair".
_REQUEST_KIND: Final = "http_request"
_RESPONSE_KIND: Final = "http_response"


def build_facts(
    candidate: Any,
    *,
    criticality: str = "normal",
    verification: Any = None,
    signatures: Iterable[str] = (),
    extra: Mapping[str, Any] | None = None,
) -> FactSpace:
    """Build the fact space one candidate is evaluated against.

    ``candidate`` is an :class:`~arachne.analyzer.model.Candidate`; the parameters are the
    analysis-level inputs the engine already computed (asset criticality, the verification
    outcome, matched signature ids). Everything here is derived from the candidate's own
    evidence, so two runs over the same candidate produce the same facts — which is what
    makes the whole engine deterministic .
    """
    from arachne.analyzer.model import Candidate, VerificationOutcome

    assert isinstance(candidate, Candidate)  # documented contract; keeps mypy precise
    outcome = (
        verification if isinstance(verification, VerificationOutcome) else VerificationOutcome()
    )

    evidence: dict[str, Any] = {}
    counts: dict[str, int] = {}
    for item in candidate.evidence:
        counts[item.kind] = counts.get(item.kind, 0) + 1
        payload = dict(item.payload)
        existing = evidence.get(item.kind)
        if existing is None:
            evidence[item.kind] = payload
        elif isinstance(existing, list):
            existing.append(payload)
        else:
            evidence[item.kind] = [existing, payload]
    evidence["count"] = counts

    response_body = _first_string(evidence.get(_RESPONSE_KIND), "body")
    facts: dict[str, Any] = {
        "check": {
            "id": candidate.check_id,
            "name": candidate.check_name,
            "module": candidate.check_module,
            "version": candidate.check_version,
            "research_ref": candidate.research_ref,
            "cwe": candidate.cwe,
            "cve": candidate.cve,
            "severity_hint": candidate.severity_hint,
            "verifiable": candidate.verifiable,
        },
        "asset": {
            "kind": candidate.asset_kind,
            "value": candidate.asset_value,
            "host": _host_of(candidate.asset_value)
            if candidate.asset_kind == "url"
            else candidate.asset_value,
            "criticality": criticality,
        },
        "finding": {
            "title": candidate.title,
            "status": candidate.status,
            "confidence": candidate.check_confidence,
            "finding_id": candidate.finding_id,
        },
        "analysis": {
            "verification_count": outcome.count,
            "verified": outcome.attempted,
            "reproducible": outcome.reproducible,
            "contradicted": outcome.contradicted,
            "verifiable": candidate.verifiable,
            "evidence_count": len(candidate.evidence),
            "evidence_kinds": sorted(counts),
            "has_request": _REQUEST_KIND in counts,
            "has_response": _RESPONSE_KIND in counts,
            "body_bytes": len(response_body or ""),
            "signature_ids": sorted(signatures),
        },
        "evidence": evidence,
        "signature": {
            "matched": sorted(signatures),
            "count": len(list(signatures)),
        },
        "derived": {
            # Facts a rule author can rely on without knowing which check produced the
            # candidate; genuinely check-specific signals stay in the rule's own conditions.
            "http_status": _first_int(evidence.get(_RESPONSE_KIND), "status_code"),
            "body_bytes": len(response_body or ""),
            "has_http": _RESPONSE_KIND in counts,
            "request_response_pair": _REQUEST_KIND in counts and _RESPONSE_KIND in counts,
            "asset_is_url": candidate.asset_kind == "url",
            "asset_criticality": criticality,
        },
    }
    if extra:
        facts["context"] = dict(extra)
    return FactSpace(facts)


def _first_string(payload: Any, key: str) -> str | None:
    if isinstance(payload, Mapping):
        value = payload.get(key)
        return value if isinstance(value, str) else None
    if isinstance(payload, list):
        for item in payload:
            found = _first_string(item, key)
            if found is not None:
                return found
    return None


def _first_int(payload: Any, key: str) -> int | None:
    if isinstance(payload, Mapping):
        value = payload.get(key)
        if isinstance(value, bool):
            return None
        return value if isinstance(value, int) else None
    if isinstance(payload, list):
        for item in payload:
            found = _first_int(item, key)
            if found is not None:
                return found
    return None


def _host_of(value: str | None) -> str | None:
    if not value:
        return None
    from urllib.parse import urlsplit

    return urlsplit(value).hostname or value
