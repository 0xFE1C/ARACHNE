"""The template-string audit: no user-visible literal, no missing key (REQ-UIX-008).

REQ-UIX-008 has two acceptance criteria that a reviewer cannot check by reading, so both are
machine-checked here.

**"No user-visible string literal remains in a template."** Every word a screen can show has to
come from the catalogue. This tool reads each template in ``templates/web/`` as *source* (not as
rendered output) and fails on:

``T1``
    a bare text node that contains a letter;
``T2``
    a name-bearing attribute (``aria-label``, ``aria-description``, ``title``, ``alt``,
    ``placeholder``) whose value is a literal;
``T3``
    a string literal inside a Jinja expression that reads as prose and is not an argument of the
    catalogue lookup ``t`` / ``tp``;
``T4``
    a literal in a ``{{ … }}`` output whose text is *already* a catalogue value — the
    translation exists, so the literal is a second, untranslatable copy of it.

**"A missing translation … fails the build."**

``K1``
    every literal key the templates name exists in every shipped locale;
``K2``
    English and French carry the same key set;
``K3``
    every ``ui.*`` key is named by a template or by the code that renders one, so the catalogue
    cannot accumulate translations for strings nobody shows;
``V1``
    a *dynamic* key prefix (``t('ui.status.' ~ status)``) covers every value of the closed
    vocabulary it is built from — the half a static scan of the templates cannot see.

The exemptions are deliberate and few: :data:`ALLOWED_LITERALS` names a technical string that
must not be translated (a shell command, a format name) **with its reason**, and
:data:`ALLOWED_ATTRIBUTES` does the same for a machine example. ``A1`` fails an exemption that
is no longer used, and ``--self-test`` drives every rule over a deliberately offending template
and reports the ones that stayed silent — a rule that cannot fail is not a gate.

Usage::

    python -m arachne.i18n.audit              # audit the shipped templates
    python -m arachne.i18n.audit --self-test  # prove every rule fires (exit 1 if one does not)
    python -m arachne.i18n.audit --list       # print the referenced keys
"""

from __future__ import annotations

import argparse
import ast
import html
import re
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Final, get_args

from arachne.i18n.catalog import DEFAULT_LOCALE, load_catalog

__all__ = [
    "ALLOWED_ATTRIBUTES",
    "ALLOWED_LITERALS",
    "Finding",
    "audit",
    "code_keys",
    "main",
    "referenced_keys",
    "scan_template",
    "template_sources",
]

#: Attributes that carry an accessible name or a hint. A literal here is a string a screen
#: reader (or a user) reads, so it is the catalogue's or it is not allowed.
NAME_ATTRIBUTES: Final[tuple[str, ...]] = (
    "alt",
    "aria-description",
    "aria-label",
    "aria-placeholder",
    "placeholder",
    "title",
)

#: The catalogue lookup the templates call. ``t`` reads a key, ``tp`` its plural form.
_LOOKUPS: Final[tuple[str, ...]] = ("t", "tp")

#: A string literal that must stay as it is, with the reason. Every entry has to be *used*
#: (``A1``), so an exemption cannot linger after the string it excused is gone. The list holds
#: only what is not a *label* but an artefact: a shell command, which stops working the moment
#: somebody translates it. Everything else a screen can show is in the catalogue.
ALLOWED_LITERALS: Final[dict[str, str]] = {
    "arachne feeds import <file>": "a shell command shown in <code>; it must stay runnable",
}

#: An attribute value that is a machine example rather than prose (see ``T2``).
ALLOWED_ATTRIBUTES: Final[dict[str, str]] = {
    '{"name": "lab", "targets": [{"kind": "url", "value": "https://example.com/"}], '
    '"attestation": {"attested_by": "you", "attested_at": "2026-10-01T00:00:00Z", '
    '"allowed_targets": ["example.com"]}}': (
        "the JSON target-definition example: a data shape, and its key names are the schema's"
    ),
}

#: ``t("key")`` — a literal dotted key, or a fragment ending in ``.`` (the static half of a
#: dynamic key such as ``t('ui.status.' ~ status)``).
_KEY: Final = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+\.?$")

#: A quoted string literal inside a Jinja expression. A backslash-escaped quote would be a
#: payload rather than a label, and no template carries one.
_STRING: Final = re.compile(r"'([^'\\]*)'|\"([^\"\\]*)\"")

#: A run of lowercase letters — what a sentence is made of and a path or an acronym is not.
_LOWER_WORD: Final = re.compile(r"[a-z]{3}")

#: Everything that is a path, a URL or a scheme (``/ui/findings?q=1``, ``https://x/y``).
_TECHNICAL: Final = re.compile(r"\S*://\S*|/\S*")

_TAG: Final = re.compile(r"<[^>]*>")
_JINJA_COMMENT: Final = re.compile(r"\{#.*?#\}", re.DOTALL)
_JINJA: Final = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)


@dataclass(frozen=True, slots=True)
class Finding:
    """One violation, with enough context to act on it without opening the file."""

    path: str
    line: int
    rule: str
    message: str

    def __str__(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{self.rule} {where}: {self.message}"


# --------------------------------------------------------------------------- template sources
def template_sources(root: Path | None = None) -> list[Path]:
    """Every hand-written UI template (the report templates are the report renderer's)."""
    base = root or Path(str(files("arachne.templates").joinpath("web")))
    return sorted(base.glob("*.html"))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _gaps(text: str, spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """The spans of ``text`` no span in ``spans`` covers (the text nodes)."""
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in sorted(spans):
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < len(text):
        gaps.append((cursor, len(text)))
    return gaps


def _lookup_spans(text: str) -> list[tuple[int, int]]:
    """The spans covered by a ``t(...)`` / ``tp(...)`` call, so their arguments are exempt."""
    spans: list[tuple[int, int]] = []
    for name in _LOOKUPS:
        for match in re.finditer(rf"(?<![\w.]){name}\(", text):
            depth = 0
            for index in range(match.end() - 1, len(text)):
                if text[index] == "(":
                    depth += 1
                elif text[index] == ")":
                    depth -= 1
                    if depth == 0:
                        spans.append((match.start(), index))
                        break
    return spans


def _inside(spans: Iterable[tuple[int, int]], offset: int) -> bool:
    return any(start <= offset <= end for start, end in spans)


def _looks_like_prose(text: str) -> bool:
    """True when a literal reads as a phrase rather than as an identifier (see ``T3``).

    Two conditions, both needed: whitespace (a sentence has separate words; ``"open"`` and
    ``"selected"`` are vocabulary) and a lowercase word of three letters or more once URLs and
    paths are removed (``"GET /api/v1/scans"`` is an endpoint, not a sentence).
    """
    if not re.search(r"\s", text.strip()):
        return False
    return bool(_LOWER_WORD.search(_TECHNICAL.sub(" ", text)))


def _normalise(value: str) -> str:
    return html.unescape(value).strip()


def scan_template(
    path: Path, text: str, *, catalog_values: frozenset[str] = frozenset()
) -> tuple[list[Finding], set[str], set[str]]:
    """One template's violations, the keys it names, and the dynamic prefixes it builds.

    ``text`` is the *source*: Jinja blocks are analysed as expressions, and everything outside
    a tag is a text node the browser will paint. Comments are blanked first, so a ``>`` or a
    ``"`` inside one cannot confuse the markup scan.
    """
    relative = path.name
    masked = _JINJA_COMMENT.sub(lambda match: " " * len(match.group(0)), text)
    blocks = list(_JINJA.finditer(masked))
    comments = [match.span() for match in _JINJA_COMMENT.finditer(text)]
    tags = [(match.start(), match.end()) for match in _TAG.finditer(masked)]
    lookups = _lookup_spans(masked)
    findings: list[Finding] = []
    keys: set[str] = set()
    prefixes: set[str] = set()

    # ---- T2: a name-bearing attribute carrying a literal --------------------------------
    for match in _TAG.finditer(masked):
        tag = match.group(0)
        for attribute in NAME_ATTRIBUTES:
            found = re.search(rf"\b{attribute}\s*=\s*", tag, re.IGNORECASE)
            if found is None:
                continue
            quote_at = match.start() + found.end()
            quote = masked[quote_at : quote_at + 1]
            if quote not in ("'", '"'):
                continue
            close = masked.find(quote, quote_at + 1)
            value = masked[quote_at + 1 : close]
            if value.startswith("{{"):
                continue  # a rendered expression: the catalogue is behind it
            if not re.search(r"[A-Za-z]", html.unescape(value)):
                continue  # digits, punctuation, an em dash — nothing to translate
            if attribute == "placeholder" and not re.search(r"\s", value.strip()):
                continue  # a single-token example ("m3", "CWE-200", "example.com")
            if value.strip() in ALLOWED_ATTRIBUTES:
                continue
            findings.append(
                Finding(
                    relative,
                    _line_of(text, quote_at),
                    "T2",
                    f"<{attribute}> carries the literal {value.strip()!r}; pass t('ui....')",
                )
            )

    # ---- T1: a bare text node -----------------------------------------------------------
    for start, end in _gaps(text, [b.span() for b in blocks] + tags + comments):
        node = text[start:end]
        readable = html.unescape(node).strip()
        if not readable or not re.search(r"[A-Za-z]", readable):
            continue
        if readable in ALLOWED_LITERALS:
            continue
        findings.append(
            Finding(
                relative,
                _line_of(text, start),
                "T1",
                f"bare text {readable[:60]!r} does not come from the catalogue",
            )
        )

    # ---- T3 / T4 / K1: Jinja expressions ------------------------------------------------
    for block in blocks:
        body = block.group(0)
        for match in _STRING.finditer(body):
            literal = match.group(1) if match.group(1) is not None else match.group(2)
            if not literal.strip():
                continue
            offset = block.start() + match.start()
            if _inside(lookups, offset) or (literal.endswith(".") and _KEY.match(literal)):
                # An argument of `t`/`tp`, or the static half of a dynamic key.
                if _KEY.match(literal):
                    (prefixes if literal.endswith(".") else keys).add(literal)
                continue
            if _looks_like_prose(literal):
                findings.append(
                    Finding(
                        relative,
                        _line_of(text, offset),
                        "T3",
                        f"literal {literal!r} is prose inside a Jinja expression; use t('ui....')",
                    )
                )
            elif (
                body.startswith("{{")
                and not _inside(tags, offset)
                and _normalise(literal) in catalog_values
            ):
                findings.append(
                    Finding(
                        relative,
                        _line_of(text, offset),
                        "T4",
                        f"literal {literal!r} is rendered and is already a catalogue value; "
                        "use its key",
                    )
                )
    return findings, keys, prefixes


# --------------------------------------------------------------------------- catalogue keys
def referenced_keys(root: Path | None = None) -> tuple[set[str], set[str]]:
    """The keys the templates name, and the dynamic key prefixes they build."""
    keys: set[str] = set()
    prefixes: set[str] = set()
    for path in template_sources(root):
        _, found, built = scan_template(path, path.read_text(encoding="utf-8"))
        keys |= found
        prefixes |= built
    return keys, prefixes


def code_keys(root: Path | None = None) -> tuple[set[str], set[str]]:
    """The ``ui.*`` keys the rendering code names — a route builds a notice's text too."""
    base = root or Path(str(files("arachne")))
    keys: set[str] = set()
    prefixes: set[str] = set()
    for path in sorted(base.rglob("*.py")):
        if path.name == "audit.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover - another gate's finding
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in ("translate", "pluralize") or not node.args:
                continue
            for head, dynamic in _arguments(node.args[0]):
                if not head.startswith("ui."):
                    continue
                (prefixes if dynamic else keys).add(head if dynamic else head.rstrip("."))
    return keys, prefixes


def _arguments(node: ast.expr) -> list[tuple[str, bool]]:
    """``(head, is_dynamic)`` for each literal a ``translate``/``pluralize`` call may use.

    A key can be a constant, an f-string (whose first part is the prefix of a built key), or
    either branch of a conditional — ``translate("a" if stale else "b")`` names two keys.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [(node.value, False)]
    if isinstance(node, ast.JoinedStr) and node.values:
        start = node.values[0]
        if isinstance(start, ast.Constant) and isinstance(start.value, str):
            return [(start.value, True)]
        return []
    if isinstance(node, ast.IfExp):
        return _arguments(node.body) + _arguments(node.orelse)
    return []


def _vocabulary_prefixes() -> dict[str, tuple[str, ...]]:
    """The dynamic key prefixes, and the closed vocabulary each one is built from.

    A prefix the templates use but that is absent here is itself a ``V1`` finding: a
    dynamically built key is exactly where a missing translation hides.
    """
    from arachne.api.workspace import SHORTCUTS, WorkspaceAction
    from arachne.core.config import SEVERITY_LEVELS
    from arachne.core.lifecycle import ScanStatus, StepStatus
    from arachne.data.api_store import FINDING_STATUSES
    from arachne.quality.suppressions import SuppressionKind

    return {
        "ui.severity.": (*SEVERITY_LEVELS, "unanalysed"),
        "ui.status.": (
            *[str(item) for item in ScanStatus],
            *[str(item) for item in StepStatus],
            *sorted(FINDING_STATUSES),
        ),
        "ui.quality.kind.": tuple(str(item) for item in get_args(SuppressionKind)),
        "ui.quality.kind_short.": tuple(str(item) for item in get_args(SuppressionKind)),
        "ui.workspace.shortcut.": tuple(item.action for item in SHORTCUTS),
        "ui.workspace.notice.": tuple(str(item) for item in get_args(WorkspaceAction)),
    }


def _has_key(catalog: dict[str, str], key: str) -> bool:
    """``key``, or its plural forms — a dynamic prefix may build either."""
    return any(candidate in catalog for candidate in (key, f"{key}.one", f"{key}.other"))


def _is_used(key: str, named: set[str], prefixes: set[str]) -> bool:
    if key in named or key.rsplit(".", 1)[0] in named:
        return True
    return any(key.startswith(prefix) for prefix in prefixes)


# --------------------------------------------------------------------------- the audit
def audit(
    root: Path | None = None, *, catalogs: dict[str, dict[str, str]] | None = None
) -> list[Finding]:
    """Every violation in the shipped templates and catalogues (empty means clean)."""
    multilingual = catalogs or {locale: load_catalog(locale) for locale in (DEFAULT_LOCALE, "fr")}
    english = multilingual[DEFAULT_LOCALE]
    findings: list[Finding] = []
    template_keys: set[str] = set()
    template_prefixes: set[str] = set()
    for path in template_sources(root):
        scanned, found, built = scan_template(
            path, path.read_text(encoding="utf-8"), catalog_values=frozenset(english.values())
        )
        findings.extend(scanned)
        template_keys |= found
        template_prefixes |= built
    code_key_set, code_prefixes = code_keys()
    named = template_keys | code_key_set
    prefixes = template_prefixes | code_prefixes

    # K2: the locales carry the same keys.
    for locale, catalog in multilingual.items():
        missing = sorted(set(english) - set(catalog))
        extra = sorted(set(catalog) - set(english))
        if missing:
            findings.append(Finding(f"i18n/{locale}.yaml", 0, "K2", f"missing keys: {missing[:6]}"))
        if extra:
            findings.append(
                Finding(f"i18n/{locale}.yaml", 0, "K2", f"keys English does not have: {extra[:6]}")
            )

    # K1: every key a template names exists everywhere.
    for key in sorted(template_keys):
        for locale, catalog in multilingual.items():
            if not _has_key(catalog, key):
                findings.append(Finding("templates/web", 0, "K1", f"{locale} has no key {key!r}"))

    # K3: no translation for a string nobody shows.
    for key in sorted(english):
        if key.startswith("ui.") and not _is_used(key, named, prefixes):
            findings.append(Finding("i18n/en.yaml", 0, "K3", f"{key!r} is not referenced anywhere"))

    # V1: a dynamically built key covers its whole closed vocabulary.
    vocabularies = _vocabulary_prefixes()
    for prefix in sorted(prefixes):
        values = vocabularies.get(prefix)
        if values is None:
            findings.append(
                Finding(
                    "templates/web",
                    0,
                    "V1",
                    f"dynamic key prefix {prefix!r} has no declared vocabulary to check",
                )
            )
            continue
        for value in values:
            for locale, catalog in multilingual.items():
                if not _has_key(catalog, f"{prefix}{value}"):
                    findings.append(
                        Finding("templates/web", 0, "V1", f"{locale} has no key {prefix}{value!r}")
                    )

    # A1: an exemption that is no longer needed.
    corpus = html.unescape(
        "\n".join(path.read_text(encoding="utf-8") for path in template_sources(root))
    )
    for literal, reason in ALLOWED_LITERALS.items():
        if literal not in corpus:
            findings.append(
                Finding("i18n/audit.py", 0, "A1", f"exemption {literal!r} ({reason}) is not used")
            )
    for value, reason in ALLOWED_ATTRIBUTES.items():
        if value not in corpus:
            findings.append(Finding("i18n/audit.py", 0, "A1", f"exemption {reason!r} is not used"))
    return findings


# --------------------------------------------------------------------------- self-test
#: A template that breaks every rule at once. `--self-test` scans it and reports the rules that
#: stayed silent, so a rule that has quietly stopped matching is a failure rather than a pass.
_OFFENDING: Final = """\
{% set severity = "high" %}
{% set status = "open" %}
<h1>Sign in</h1>
<p aria-label="Display controls">{{ t('ui.login.heading') }}</p>
<input placeholder="m3 example">
<label>{{ t('ui.login.api_key_label') }} <input name="key"></label>
<p>{{ "Sign in without a catalogue key" }}</p>
<p>{{ "fp" }}</p>
<p title="{{ t('ui.display.aria') }}">{{ t('ui.login.submit') }}</p>
<p>{{ t('ui.status.' ~ status, locale='en') }}</p>
"""

_SELF_TEST_CATALOG: Final[dict[str, str]] = {
    "ui.title.login": "Login",
    "ui.login.heading": "Sign in",
    "ui.login.api_key_label": "API key",
    "ui.login.submit": "Submit",
    "ui.display.aria": "Display",
    "ui.status.fp": "fp",
    "ui.unused.extra": "never shown",
}


def self_test() -> list[str]:
    """The rules that did *not* fire on :data:`_OFFENDING` (empty means the audit works)."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "offending.html").write_text(_OFFENDING, encoding="utf-8")
        catalogs = {"en": dict(_SELF_TEST_CATALOG), "fr": {"ui.title.login": "Connexion"}}
        fired = {item.rule for item in audit(root, catalogs=catalogs)}
    return [
        rule for rule in ("T1", "T2", "T3", "T4", "K1", "K2", "K3", "V1", "A1") if rule not in fired
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m arachne.i18n.audit")
    parser.add_argument("--self-test", action="store_true", help="prove every rule fires")
    parser.add_argument("--list", action="store_true", help="print the referenced keys")
    parser.add_argument("root", nargs="?", default=None, help="a template directory (tests)")
    args = parser.parse_args(argv)

    if args.self_test:
        problems = self_test()
        if problems:
            print(f"FAIL the audit is blind to: {', '.join(problems)}")  # noqa: T201
            return 1
        print("self-test: all nine rules fired on the offending template")  # noqa: T201
        return 0

    root = Path(args.root) if args.root else None
    if args.list:
        keys, prefixes = referenced_keys(root)
        for key in sorted(keys):
            print(key)  # noqa: T201
        for prefix in sorted(prefixes):
            print(f"{prefix}*")  # noqa: T201
        return 0

    findings = audit(root)
    for item in findings:
        print(f"FAIL {item}")  # noqa: T201
    print(f"{len(template_sources(root))} template(s) scanned, {len(findings)} violation(s)")  # noqa: T201
    return 1 if findings else 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
