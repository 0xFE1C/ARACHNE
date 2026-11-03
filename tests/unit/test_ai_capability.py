"""No process, socket or filesystem-write primitive in the AI package (REQ-AGENT-011, G5 cl. 5).

``ai.tools`` says which tools the AI layer may call. This module asserts the property that makes
that enumeration meaningful: there is no *second door* to the primitives the tool surface omits.
It is a source-level check over every module of ``arachne.ai`` — not only the ones a test happens
to import — and it is deliberately conservative: it reports a call it cannot prove is plain data
rather than assuming the best.

The modules are enumerated **through the import system** (``pkgutil`` over the package's own
path, source read by ``inspect``), so this module assembles no filesystem path of its own: the
scope of the audit is the package Python resolves, which is the same package ``ai.tools`` belongs
to.

The self-test comes first, because a checker that cannot fail on the case it exists for is worse
than no checker. It is **data-driven**: every entry in the checker's own tables is turned into a
synthetic module and must be reported, which is how a rule added to a table gets a test without
anyone remembering to write one — and the case the clause names (an added ``subprocess`` import)
is written out by hand as well, so the promise is checked independently of the table. The tests
after it feed the checker the shapes that must stay *allowed* (a read, a string ``replace``, a
helper's ``run`` with a data argument), and one documents the checker's known blind spot honestly
rather than pretending it does not exist.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any

import pytest

from arachne.ai.capability import (
    FORBIDDEN_ATTRIBUTES,
    FORBIDDEN_CALLS,
    FORBIDDEN_MODULES,
    ForbiddenPrimitive,
    scan_modules,
    scan_source,
)

#: The package under audit.
PACKAGE = "arachne.ai"

#: Shapes that must stay allowed: reads, string methods, and helpers taking plain data.
ALLOWED_SNIPPETS: tuple[str, ...] = (
    "def f(target):\n    return target.read_text()\n",
    "def f(target):\n    return open(target, 'rb')\n",
    "def f(target):\n    return target.exists()\n",
    "def f(text):\n    return text.replace('a', 'b')\n",
    "def f(runner):\n    return runner.run('triage')\n",
    "def f(loop):\n    return loop.run(['a', 'b'])\n",
    "import json\nimport hashlib\nimport ast\n",
    "import pathlib\n",
)


def _module_sources() -> dict[str, str]:
    """Every module of ``arachne.ai``, keyed by its dotted name, read via ``inspect``."""
    package: Any = importlib.import_module(PACKAGE)
    sources: dict[str, str] = {PACKAGE: inspect.getsource(package)}
    for info in pkgutil.walk_packages(package.__path__, prefix=f"{PACKAGE}."):
        module = importlib.import_module(info.name)
        sources[info.name] = inspect.getsource(module)
    return sources


# ------------------------------------------------------------------ the self-test


def test_the_checker_reports_an_added_subprocess_import() -> None:
    """The clause's own example, written by hand: the promise cannot rest on the table alone."""
    findings = scan_source("import subprocess\n", module="synthetic.py")
    assert findings, "an added subprocess import must be reported"
    assert findings[0].kind == "process"
    assert "subprocess" in str(findings[0])


@pytest.mark.parametrize("module", sorted(FORBIDDEN_MODULES))
def test_every_module_in_the_table_is_reported(module: str) -> None:
    findings = scan_source(f"import {module}\n", module="synthetic.py")
    assert findings, f"importing {module} was not reported"
    assert findings[0].kind == FORBIDDEN_MODULES[module]


@pytest.mark.parametrize(("owner", "attribute"), sorted(FORBIDDEN_CALLS), ids=str)
def test_every_call_in_the_table_is_reported(owner: str, attribute: str) -> None:
    source = f"import {owner}\ndef f():\n    {owner}.{attribute}()\n"
    findings = scan_source(source, module="synthetic.py")
    assert findings, f"calling {owner}.{attribute}() was not reported"
    assert findings[0].kind == FORBIDDEN_CALLS[(owner, attribute)]


@pytest.mark.parametrize("attribute", sorted(FORBIDDEN_ATTRIBUTES))
def test_every_attribute_in_the_table_is_reported(attribute: str) -> None:
    findings = scan_source(f"def f(target):\n    target.{attribute}()\n", module="synthetic.py")
    assert findings, f"calling .{attribute}() was not reported"
    assert findings[0].kind == FORBIDDEN_ATTRIBUTES[attribute]


def test_a_write_mode_open_is_reported() -> None:
    """The one call rule that needs its argument read: a literal write mode is a write."""
    findings = scan_source(
        "def f(target):\n    open(target, OPEN_FOR_WRITING)\n".replace(
            "OPEN_FOR_WRITING", repr("w")
        ),
        module="synthetic.py",
    )
    assert findings
    assert findings[0].kind == "filesystem-write"


def test_the_table_covers_the_primitives_the_clause_names() -> None:
    """The three families the requirement names, present by name in the closed tables."""
    assert {"subprocess", "socket", "shutil"} <= set(FORBIDDEN_MODULES)
    assert {"write_text", "unlink"} <= set(FORBIDDEN_ATTRIBUTES)
    assert any(owner == "os" for owner, _attribute in FORBIDDEN_CALLS)
    assert {"process", "socket", "filesystem-write"} == {
        *FORBIDDEN_MODULES.values(),
        *FORBIDDEN_CALLS.values(),
        *FORBIDDEN_ATTRIBUTES.values(),
    }


@pytest.mark.parametrize("snippet", ALLOWED_SNIPPETS, ids=lambda item: str(item)[:40])
def test_the_checker_allows_reads_and_plain_data(snippet: str) -> None:
    assert scan_source(snippet, module="synthetic.py") == (), snippet


def test_a_write_through_a_variable_mode_is_a_known_gap() -> None:
    """Stated rather than hidden: the checker reads a literal mode, not a computed one.

    A module that called ``open(target, mode)`` with ``mode`` assembled at run time would not be
    caught by this rule. That is a real limit of a source-level check, and the reason the *tool
    registry* is the first line of defence and this sweep is the second: the AI package's own
    imports are what the tests above pin, and a computed write mode is a shape nothing in the
    current package uses.
    """
    source = "def f(target, mode):\n    open(target, mode)\n"
    assert scan_source(source, module="synthetic.py") == ()


def test_an_added_subprocess_import_fails_the_sweep() -> None:
    """The same clause, as it would actually be tripped: a module added to the *package*."""
    sources = _module_sources()
    sources["arachne.ai.new_stage"] = "import subprocess\n\ndef run():\n    return 1\n"
    findings = scan_modules(sources)
    assert findings, "an added subprocess import must fail this test"
    assert any(finding.kind == "process" for finding in findings)


def test_a_finding_names_where_it_is() -> None:
    finding = scan_source("import socket\n", module="arachne.ai.transport")[0]
    assert isinstance(finding, ForbiddenPrimitive)
    assert finding.module == "arachne.ai.transport"
    assert finding.line == 1
    assert "socket" in str(finding)


# ------------------------------------------------------------------ the real package


def test_no_ai_module_imports_a_process_socket_or_filesystem_write_primitive() -> None:
    findings = scan_modules(_module_sources())
    assert findings == (), (
        "the AI package must not import a process, socket or filesystem-write primitive "
        "(REQ-AGENT-011):\n" + "\n".join(f"  {finding}" for finding in findings)
    )


def test_the_sweep_covers_the_whole_package() -> None:
    """A sweep over three files would pass for the wrong reason; this is the whole package."""
    sources = _module_sources()
    assert len(sources) >= 15, sorted(sources)
    for expected in (
        "arachne.ai.engine",
        "arachne.ai.runner",
        "arachne.ai.stages",
        "arachne.ai.tools",
        "arachne.ai.providers.registry",
    ):
        assert expected in sources, sorted(sources)


def test_the_cache_delegates_its_write() -> None:
    """The one place a write was *needed*: documented, and delegated to ``core``.

    ``ai.cache`` mirrors the request cache to a JSON file when a deployment configures a cache
    directory. That write is real and useful, so instead of carving an exception into the rule
    above, the store moved to :class:`arachne.core.jsonstore.JsonFileStore`: the AI package keeps
    the policy and the write, and imports no write primitive.
    """
    cache = _module_sources()["arachne.ai.cache"]
    assert "JsonFileStore" in cache
    assert "write_text" not in cache
