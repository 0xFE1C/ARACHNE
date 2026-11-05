"""Enforces the architectural invariant behind ADR-05: one HTTP egress path.

A "single scoped client" is only a real guarantee if nothing else can open a socket.
These are source-level checks (cheap, deterministic, and they fail the moment someone
adds ``import requests`` to a module), not runtime checks.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "arachne"

#: Modules allowed to import a raw HTTP library. Everything else must use the client.
HTTP_CLIENT_MODULE = "core/http.py"

#: The only modules allowed to start a process (ADR-180, ADR-190.4). Each call shape is
#: asserted: ``test_pdf_backend_process_call_is_fixed_argv_with_timeout``,
#: ``test_plugin_installer_process_call_is_fixed_argv_with_timeout``,
#: ``test_documentation_tools_call_fixed_argv_with_a_timeout``,
#: ``test_the_handoff_tool_calls_fixed_argv_with_a_timeout``,
#: ``test_the_mutation_runner_calls_fixed_argv_with_a_timeout``, and for the S27 fix
#: engine ``test_fix_safety.py::test_every_process_call_is_a_sequence_with_no_shell_and_a_timeout``
#: (which additionally asserts that every argv[0] is a literal from the runner allowlist).
SHELL_EXEMPT_MODULES = frozenset(
    {
        "report/pdf_backend.py",
        "plugins/installer.py",
        "fix/gitops.py",
        # The documentation gate asks the checkout's own git whether a cited commit exists,
        # and the count generator asks pytest what it collects. Both are read-only questions
        # about this repository, asked with a fixed argv.
        "tools/doccheck.py",
        "tools/counts.py",
        # The handoff gate reads commits, diffs and exit codes with `git` and runs the quality
        # gates (`ruff`, `mypy`, `pytest`) in a fresh process. Every program name is a literal
        # (REQ-QUAL-013).
        "tools/wp_check.py",
        # The mutation gate runs the covering test suite once per mutant, with the interpreter
        # by name and a fixed list of literals. The mutant's identity and its test scope travel
        # in the environment, so nothing is spliced into an argv — and the gate refuses to
        # start when that interpreter cannot import this project (REQ-QUAL-008).
        "fuzz/mutate.py",
        # The quickstart runner executes the commands `docs/getting-started.md` declares, in a
        # shell, because "the page runs verbatim" *is* REQ-DOC-005 — the guide's own first block
        # sources a virtualenv, which is a shell builtin no argv can express. The script it runs
        # is assembled from committed prose in this repository and never from a scan, a target or
        # any other external input; the call shape is asserted by
        # ``test_the_quickstart_runner_calls_a_shell_only_with_the_guide_as_its_script``.
        "tools/quickstart.py",
    }
)

#: Libraries that would bypass the scoped client.
BANNED_HTTP_MODULES = ("requests", "urllib.request", "urllib3", "aiohttp", "http.client")


def python_files() -> list[Path]:
    files = sorted(path for path in SRC.rglob("*.py") if path.name != "__init__.py")
    assert files, "no source files found — is the layout still src/arachne?"
    return files


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
            modules.update(f"{node.module}.{alias.name}" for alias in node.names)
    return modules


@pytest.mark.parametrize("path", python_files(), ids=lambda path: str(path.name))
def test_no_module_bypasses_the_shared_http_client(path: Path) -> None:
    relative = path.relative_to(SRC).as_posix()
    modules = imported_modules(path)

    for banned in BANNED_HTTP_MODULES:
        assert not any(module == banned or module.startswith(f"{banned}.") for module in modules), (
            f"{relative} imports {banned!r}; all HTTP must go through core/http.py (ADR-05)"
        )

    if relative != HTTP_CLIENT_MODULE:
        assert "httpx" not in modules, (
            f"{relative} imports httpx directly; use arachne.core.http.ScopedHttpClient (ADR-05)"
        )


def test_production_code_has_no_debug_breakpoints() -> None:
    for path in python_files():
        source = path.read_text(encoding="utf-8")
        assert "breakpoint(" not in source, f"{path.name} contains a debug breakpoint"


def test_no_shell_execution_helpers() -> None:
    """Target-derived data must never reach a shell (F-08-03).

    Starting a process is not banned outright: the PDF path legitimately drives an external
    headless engine. The ban is on *shells* and on target data reaching an argv, so the one
    module allowed to call ``subprocess`` is named here and its call shape is asserted below
    (fixed argv from a literal template, no ``shell``, always a timeout).
    """
    offenders = []
    for path in python_files():
        relative = path.relative_to(SRC).as_posix()
        modules = imported_modules(path)
        if "os.system" in modules:
            offenders.append(f"{relative} imports os.system")
        source = path.read_text(encoding="utf-8")
        if "os.popen" in source:
            offenders.append(f"{relative} uses os.popen")
        if "subprocess" in modules and relative not in SHELL_EXEMPT_MODULES:
            offenders.append(f"{relative} imports subprocess")
    assert not offenders, f"shell execution helpers found in: {offenders}"


def test_pdf_backend_process_call_is_fixed_argv_with_timeout() -> None:
    """The one ``subprocess`` exemption, asserted rather than commented (ADR-180).

    Four properties make the call safe, and each one is checked from the AST so that a new
    backend cannot quietly widen it:

    1. every ``subprocess.run`` gets a sequence, never a command string;
    2. ``shell`` is never passed (so it defaults to ``False``);
    3. ``timeout`` is always set;
    4. the argv templates are module-level literals, and the executable is resolved with
       ``shutil.which`` — no value from scanned content can name a program.
    """
    path = SRC / "report/pdf_backend.py"
    assert path.is_file(), "report/pdf_backend.py is missing; update ADR-180"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]
    assert run_calls, "the exempt module no longer calls subprocess.run; drop the exemption"

    for call in run_calls:
        assert call.args, "subprocess.run must be given an argv"
        argv = call.args[0]
        assert not isinstance(argv, ast.Constant), (
            "subprocess.run must never receive a command string (shell-style invocation)"
        )
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert "shell" not in keywords, "subprocess.run must not pass shell= at all"
        assert "timeout" in keywords, "subprocess.run must always set a timeout"

    # The argv templates are literal data, not assembled from report/target content.
    specs = [
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign | ast.Assign)
        and isinstance(getattr(node, "target", None), ast.Name)
        and node.target.id == "EXTERNAL_BACKEND_SPECS"
    ]
    assert specs, "EXTERNAL_BACKEND_SPECS is the fixed argv table; it must stay module-level"
    value = specs[0].value
    assert isinstance(value, ast.Dict), "EXTERNAL_BACKEND_SPECS must be a literal dict"
    for entry in value.values:
        assert isinstance(entry, ast.List), "each backend's argv must be a literal list"
        for part in entry.elts:
            assert isinstance(part, ast.Constant) and isinstance(part.value, str), (
                "argv elements must be string literals"
            )

    # The executable is looked up on PATH, never taken from input.
    source = path.read_text(encoding="utf-8")
    assert "shutil.which(" in source, "backend resolution must go through shutil.which"


def test_the_mutation_runner_calls_fixed_argv_with_a_timeout() -> None:
    """The mutation gate's process calls, asserted rather than trusted (REQ-QUAL-008).

    It runs pytest once per mutant, so it needs the exemption — and it earns it the same way
    the other exempt modules do. Four properties, each read from the AST:

    1. every ``subprocess.run`` receives a sequence literal, never a command string;
    2. ``shell`` is either absent or the literal ``False`` (never ``True``, never a variable);
    3. ``timeout`` is always set, with a non-literal value from the config;
    4. every argv element is a string literal — the mutant's identity and its test scope
       travel in the environment, so nothing derived from a file can name a program.
    """
    path = SRC / "fuzz/mutate.py"
    assert path.is_file(), "fuzz/mutate.py is missing; drop the exemption"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]
    assert run_calls, "the exempt module no longer calls subprocess.run; drop the exemption"

    for call in run_calls:
        assert call.args, "subprocess.run must be given an argv"
        argv = call.args[0]
        assert not isinstance(argv, ast.Constant), (
            "subprocess.run must never receive a command string (shell-style invocation)"
        )
        assert isinstance(argv, ast.List), "the argv must be written out as a list literal"
        for element in argv.elts:
            assert isinstance(element, ast.Constant) and isinstance(element.value, str), (
                f"argv elements must be string literals, found {type(element).__name__}"
            )
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        if "shell" in keywords:
            shell = keywords["shell"]
            assert isinstance(shell, ast.Constant) and shell.value is False, (
                "subprocess.run must never enable a shell"
            )
        assert "timeout" in keywords, "subprocess.run must always set a timeout"

    # The mutant and its scope travel in the environment, never in the argv.
    source = path.read_text(encoding="utf-8")
    for variable in ("MODULE_ENV", "SOURCE_ENV", "TESTS_ENV", "STATUS_ENV"):
        assert f"environment[{variable}]" in source, (
            f"{variable} must be set on the environment, not spliced into the argv"
        )


def test_the_quickstart_runner_calls_a_shell_only_with_the_guide_as_its_script() -> None:
    """The quickstart runner's process call, asserted rather than trusted (REQ-DOC-005).

    Unlike every other exemption, this one *must* use a shell: the guide's first block sources a
    virtualenv, which is a shell builtin. So the shape assertions are about what the shell is
    given, not about avoiding the shell:

    1. every ``subprocess.run`` receives a list literal whose first two elements are the
       literals ``"bash"`` and ``"-c"`` — the only shell this module may start;
    2. ``shell`` is never passed (so it defaults to ``False``: the argv is a list, not a string);
    3. ``timeout`` is always set, so a documented command that hangs fails the job;
    4. ``cwd`` is always the repository the caller named, so no command runs in a target's
       directory;
    5. ``subprocess.Popen`` appears nowhere: a service is backgrounded *inside* the shell, with
       an EXIT trap that kills it, rather than held as a Python process handle.
    """
    path = SRC / "tools/quickstart.py"
    assert path.is_file(), "tools/quickstart.py is missing; drop the exemption"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]
    assert len(run_calls) == 2, (
        "the runner has exactly two process calls (the corridor segment and `arachne --version`); "
        "a new one needs its own assertion"
    )

    for call in run_calls:
        assert call.args, "subprocess.run must be given an argv"
        argv = call.args[0]
        assert isinstance(argv, ast.List), "the argv must be a list literal, never a string"
        assert [part.value for part in argv.elts[:2] if isinstance(part, ast.Constant)] == [
            "bash",
            "-c",
        ], "the only program this module may start is bash with -c"
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert "shell" not in keywords, "shell= must not be passed (the argv is already a list)"
        assert "timeout" in keywords, "a documented command that hangs must fail the job"
        cwd = keywords.get("cwd")
        assert isinstance(cwd, ast.Name), "cwd must be the repository the caller named"
        assert cwd.id == "repo"

    assert "Popen" not in source, (
        "the quickstart runner must not hold a process handle: a service is backgrounded in the "
        "shell and stopped by its EXIT trap"
    )
    # And the script is built from the guide's own blocks, never from a command string the
    # caller supplied: `_segment_script` takes parsed `Block`s and is the only assembler.
    assert "def _segment_script(segment: list[Block]" in source
    assert "parse_blocks(" in source


def test_plugin_installer_process_call_is_fixed_argv_with_timeout() -> None:
    """The second ``subprocess`` exemption, asserted (ADR-190.4).

    An install legitimately drives ``pip``, but the call must stay data-only:

    1. the executable is ``sys.executable`` — never a program named by input;
    2. the command is an argv sequence, not a shell string;
    3. ``shell`` is never passed;
    4. a ``timeout`` is always set.
    """
    path = SRC / "plugins" / "installer.py"
    assert path.is_file(), "plugins/installer.py is missing; update ADR-190"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]
    assert run_calls, "the installer no longer calls subprocess.run; drop the exemption"

    for call in run_calls:
        assert call.args, "subprocess.run must be given an argv"
        assert not isinstance(call.args[0], ast.Constant), (
            "subprocess.run must never receive a command string"
        )
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert "shell" not in keywords, "subprocess.run must not pass shell= at all"
        assert "timeout" in keywords, "subprocess.run must always set a timeout"

    source = path.read_text(encoding="utf-8")
    assert "sys.executable" in source, "the installer must invoke the current interpreter"
    for literal in ('"-m"', '"pip"', '"install"'):
        assert literal in source, f"the pip argv must stay literal: {literal} is missing"


def test_documentation_tools_call_fixed_argv_with_a_timeout() -> None:
    """The two documentation tools' ``subprocess`` exemptions, asserted (REQ-DOC-001/002).

    Both ask a read-only question about this checkout — "does this commit exist?"
    (``git cat-file -t``) and "what does pytest collect?" — and both must stay data-only:

    1. ``argv[0]`` is a string literal: a program named in the source, never by input;
    2. the command is an argv sequence, not a shell string, and carries fixed flag literals;
    3. ``shell`` is never passed;
    4. a ``timeout`` is always set.

    The commit sha and the repository path are *data* passed as arguments; nothing derived
    from scanned content can reach an argv position that names a program.
    """
    for relative in ("tools/doccheck.py", "tools/counts.py"):
        path = SRC / relative
        assert path.is_file(), f"{relative} is missing; drop its exemption"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        run_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ]
        assert run_calls, f"{relative} no longer calls subprocess.run; drop its exemption"
        for call in run_calls:
            assert call.args, "subprocess.run must be given an argv"
            argv = call.args[0]
            assert isinstance(argv, ast.List), "argv must be a literal sequence, not a string"
            head = argv.elts[0]
            assert isinstance(head, ast.Constant) and isinstance(head.value, str), (
                f"{relative}: argv[0] must be a literal program name"
            )
            literals = [element for element in argv.elts if isinstance(element, ast.Constant)]
            assert len(literals) >= 3, f"{relative}: the argv must be a fixed template"
            keywords = {keyword.arg: keyword.value for keyword in call.keywords}
            assert "shell" not in keywords, "subprocess.run must not pass shell= at all"
            assert "timeout" in keywords, "subprocess.run must always set a timeout"


def test_the_handoff_tool_calls_fixed_argv_with_a_timeout() -> None:
    """The handoff gate's ``subprocess`` exemption, asserted (REQ-QUAL-013).

    ``wp_check`` reads commits, diffs and exit codes and runs the quality gates. The safety
    property is the same as the documentation tools': every call is a literal argv whose
    ``argv[0]`` is a literal program name — ``git``, ``ruff``, ``mypy``, ``python`` — so no
    value from the repository under inspection can name a program. The repository path and a
    commit sha enter only as data arguments, ``shell`` is never passed and a timeout is set.
    """
    relative = "tools/wp_check.py"
    path = SRC / relative
    assert path.is_file(), f"{relative} is missing; drop its exemption"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
    ]
    assert run_calls, f"{relative} no longer calls subprocess.run; drop its exemption"
    for call in run_calls:
        assert call.args, "subprocess.run must be given an argv"
        argv = call.args[0]
        assert isinstance(argv, ast.List), "argv must be a literal sequence, not a string"
        head = argv.elts[0]
        assert isinstance(head, ast.Constant) and isinstance(head.value, str), (
            f"{relative}: argv[0] must be a literal program name"
        )
        literals = [element for element in argv.elts if isinstance(element, ast.Constant)]
        assert len(literals) >= 3, f"{relative}: the argv must be a fixed template"
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert "shell" not in keywords, "subprocess.run must not pass shell= at all"
        assert "timeout" in keywords, "subprocess.run must always set a timeout"


#: Call sites allowed to turn redaction off or raise the body cap for one client instance.
#: Each one is a documented exemption (ADR-220.3, ADR-230.3) and each is asserted here so a
#: third cannot appear quietly: a client that reads a response *verbatim* is a client whose
#: output must be accounted for by hand.
VERBATIM_READ_EXEMPTIONS = frozenset({"api/oidc.py", "intel/sync.py"})

#: Call sites allowed to use ``request_bytes`` — the byte-exact read path (ADR-250.4). Two
#: modules: the evidence backend, whose objects are already redacted captures addressed by
#: their content digest, and the native image scanner (WP-12), whose payload is a compressed
#: layer addressed by *its* content digest before anything is unpacked. A text decode plus a
#: redaction pass would corrupt both and change the digest the row verifies. Every other read
#: keeps the redacting ``HttpExchange`` shape.
BYTE_READ_EXEMPTIONS = frozenset({"data/evidence_backend.py", "modules/m5/image.py"})


def test_only_the_documented_call_sites_read_a_response_verbatim() -> None:
    """``redaction_enabled=False``/``max_body_bytes=`` are two call sites, not a habit.

    Redaction is the scanner's safety net; a client that disables it must justify itself in
    an ADR. The OIDC token exchange needs the credential back to work; the feed sync needs the
    exact bytes because a feed is integrity-verified *before* import (a redaction pass would
    edit the payload and the digest would no longer match). Both never log or persist the
    response through an evidence path — and this test is what keeps the list at two.
    """
    offenders: dict[str, list[str]] = {}
    for path in python_files():
        relative = path.relative_to(SRC).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg in {"redaction_enabled", "max_body_bytes"} and (
                    isinstance(keyword.value, ast.Constant)
                ):
                    value = keyword.value.value
                    if keyword.arg == "redaction_enabled" and value is not False:
                        continue
                    offenders.setdefault(relative, []).append(f"{keyword.arg}={value!r}")
    assert set(offenders) == VERBATIM_READ_EXEMPTIONS, offenders
    # And the exemptions are the *instance* knobs, never the deployment-wide setting.
    for path in python_files():
        source = path.read_text(encoding="utf-8")
        assert "safety.redaction_enabled = False" not in source


def test_only_the_documented_call_sites_read_a_body_as_bytes() -> None:
    """``request_bytes`` is the byte-exact read path, and it has two callers.

    It exists because some bodies are not text: an evidence object and a container layer are
    both compressed, content-addressed containers whose digest is recorded with the finding.
    Returning one through the ordinary ``HttpExchange`` (a redacted, decoded string) would
    corrupt it. Naming the exceptions here is what stops it becoming the habit of "just fetch
    the bytes" everywhere else.
    """
    offenders: dict[str, list[str]] = {}
    for path in python_files():
        relative = path.relative_to(SRC).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "request_bytes"
            ):
                offenders.setdefault(relative, []).append(f"line {node.lineno}")
    assert set(offenders) == BYTE_READ_EXEMPTIONS, offenders
