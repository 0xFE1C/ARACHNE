"""External headless PDF engines — the single, bounded ``subprocess`` call site.

The built-in renderer in :mod:`arachne.report.pdf` needs no external process at all, so a
scan, a report and the whole CI suite work on a host with no browser installed. A deployment
that wants CSS-exact output can opt in to a real engine (``ARACHNE_PDF_BACKEND=auto``); this
module is the *only* place in the package that is allowed to start a process, and it exists so
that permission is one file wide and mechanically asserted.

The invariant behind F-08-03 ("target-derived data must never reach a shell") is kept by
construction, not by review:

* the executable and every argument come from :data:`EXTERNAL_BACKEND_SPECS`, a module-level
  literal mapping — a fixed argv template, never a string assembled from scanned content;
* the report HTML reaches the engine through a temporary *file* (``{src}``), so document bytes
  are never an argument and never parsed by a shell;
* ``shell`` is never passed (and therefore defaults to ``False``), and every call sets
  ``timeout``;
* the backend name is resolved with :func:`shutil.which` against ``PATH`` — a caller can only
  name one of the four known engines, it cannot supply an arbitrary command.

``tests/unit/test_http_hygiene.py`` asserts all four points from the AST, so adding a fifth
engine or a new call site without honouring them fails the suite.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from arachne.core.errors import ReportError

__all__ = [
    "BACKENDS",
    "EXTERNAL_BACKEND_SPECS",
    "available_backends",
    "render_external",
    "select_backend",
    "weasyprint_available",
]

#: The external backends, in preference order, with the fixed argv each one needs.
#: ``{src}`` and ``{dst}`` are the only substitutions; both are temp-file paths this module
#: created, never report content.
EXTERNAL_BACKEND_SPECS: Final[dict[str, list[str]]] = {
    "chromium": [
        "chromium",
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--print-to-pdf-no-header",
        "--print-to-pdf={dst}",
        "{src}",
    ],
    "google-chrome": [
        "google-chrome",
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--no-pdf-header-footer",
        "--print-to-pdf={dst}",
        "{src}",
    ],
    "firefox": ["firefox", "--headless", "--print-to-pdf={dst}", "{src}"],
    "wkhtmltopdf": ["wkhtmltopdf", "--quiet", "{src}", "{dst}"],
}

#: Every backend this build knows how to drive, built-in one included.
BACKENDS: Final[tuple[str, ...]] = ("builtin", "weasyprint", *EXTERNAL_BACKEND_SPECS)

#: The environment variable the CLI and the API both honour.
BACKEND_ENV: Final = "ARACHNE_PDF_BACKEND"

#: Upper bound for one external render. A report is a deliverable, not a job: a hung browser
#: must fail the command, not wedge the process.
COMMAND_TIMEOUT: Final = 300


def weasyprint_available() -> bool:
    """Whether WeasyPrint can actually be imported on this host (it needs system libraries)."""
    if importlib.util.find_spec("weasyprint") is None:
        return False
    try:
        import weasyprint  # noqa: F401
    except Exception:  # a missing system library is "not available", not a crash
        return False
    return True


def available_backends() -> tuple[str, ...]:
    """Which backends this host can actually use (``builtin`` is always first)."""
    found = ["builtin"]
    if weasyprint_available():
        found.append("weasyprint")
    for name, argv in EXTERNAL_BACKEND_SPECS.items():
        if shutil.which(argv[0]):
            found.append(name)
    return tuple(found)


def select_backend(name: str | None = None) -> tuple[str, str | None]:
    """Resolve the configured backend to ``(backend_name, fallback_reason)``.

    ``auto`` (and an unset value) prefers an external headless engine and falls back to the
    built-in renderer, reporting why. An explicitly requested backend that is unavailable is
    a hard error, because a deployment that asked for WeasyPrint should not silently get a
    different artifact.
    """
    requested = (name or os.environ.get(BACKEND_ENV) or "builtin").strip().lower()
    if requested in {"", "builtin"}:
        return "builtin", None
    if requested == "auto":
        for candidate in available_backends():
            if candidate != "builtin":
                return candidate, None
        return "builtin", "no external headless renderer is installed"
    if requested not in BACKENDS:
        raise ReportError(
            f"unknown PDF backend {requested!r}; choose one of {', '.join(BACKENDS)} or 'auto'"
        )
    if requested == "weasyprint":
        if not weasyprint_available():
            raise ReportError(
                f"{BACKEND_ENV}=weasyprint but weasyprint is not installed "
                "(pip install 'arachne[pdf]')"
            )
        return "weasyprint", None
    argv = EXTERNAL_BACKEND_SPECS.get(requested)
    if argv is None or not shutil.which(argv[0]):
        raise ReportError(f"{BACKEND_ENV}={requested} but {requested} is not on PATH")
    return requested, None


def _run_command(name: str, argv: Sequence[str]) -> None:
    """Run one fixed argv, with no shell and a timeout (F-08-03)."""
    try:
        subprocess.run(  # noqa: S603 - argv comes from EXTERNAL_BACKEND_SPECS, never from a target
            list(argv),
            check=True,
            capture_output=True,
            timeout=COMMAND_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReportError(f"{name} PDF backend failed: {exc}") from exc


def _command_backend(name: str, document: str) -> bytes:
    argv_template = EXTERNAL_BACKEND_SPECS[name]
    with tempfile.TemporaryDirectory(prefix="arachne-pdf-") as directory:
        source = Path(directory) / "report.html"
        target = Path(directory) / "report.pdf"
        source.write_text(document, encoding="utf-8")
        argv = [
            part.replace("{src}", str(source)).replace("{dst}", str(target))
            for part in argv_template
        ]
        _run_command(name, argv)
        if not target.is_file():
            raise ReportError(f"{name} PDF backend produced no output")
        return target.read_bytes()


def _weasyprint_backend(document: str) -> bytes:
    import weasyprint

    return bytes(weasyprint.HTML(string=document).write_pdf())


def render_external(name: str, document: str) -> bytes:
    """Render ``document`` (HTML) with the named external backend."""
    if name == "weasyprint":
        return _weasyprint_backend(document)
    if name not in EXTERNAL_BACKEND_SPECS:
        raise ReportError(f"unknown external PDF backend {name!r}")
    return _command_backend(name, document)
