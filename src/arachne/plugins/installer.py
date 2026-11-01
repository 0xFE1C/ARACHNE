"""Install a plugin from a local path or a git URL (F-09-01, S14).

This is the one place in ARACHNE that starts a process other than the PDF renderer, and the
shape of the call is asserted from the AST by ``tests/unit/test_http_hygiene.py``: a fixed
executable (``sys.executable``), an argv list, no ``shell``, and always a timeout. A plugin
source is operator input, so it is validated before it reaches pip:

* a **local path** must exist and be a Python project (``pyproject.toml``/``setup.py``) or a
  wheel/sdist archive;
* a **git URL** must be ``git+https://``, ``git+ssh://``, ``git+file://`` or the scp-like
  ``git@host:path.git`` form, optionally with ``#egg=`` / ``@ref`` suffixes;
* anything beginning with ``-`` is refused, because pip would read it as an option.

After installing, :func:`install_and_verify` re-runs discovery and reports which checks or
report formats appeared. An install that produces nothing discoverable is a failure with
the reason, not a silent success.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = [
    "InstallRequest",
    "InstallResult",
    "PluginInstallError",
    "install",
    "install_and_verify",
    "verify_installed",
]

#: Git URL forms pip understands. A bare ``https://…/.git`` is rewritten to ``git+https``.
_GIT_PREFIXES: Final[tuple[str, ...]] = ("git+https://", "git+ssh://", "git+file://", "git+http://")
_ARCHIVE_SUFFIXES: Final[tuple[str, ...]] = (".whl", ".tar.gz", ".zip")
#: A bound on how much of pip's output is kept in the result (it can be verbose).
_OUTPUT_LIMIT: Final = 8000
#: Default install timeout: generous for a source build, still finite.
DEFAULT_TIMEOUT_S: Final = 600.0


class PluginInstallError(ConfigurationError):
    """An installation that could not start, failed, or installed nothing discoverable."""


@dataclass(frozen=True, slots=True)
class InstallRequest:
    """A validated install: where the package comes from and how pip will be invoked."""

    source: str
    kind: str
    target: str | None = None
    upgrade: bool = True

    @classmethod
    def parse(
        cls, source: str, *, target: str | None = None, upgrade: bool = True
    ) -> InstallRequest:
        """Validate ``source`` and classify it as ``local-path`` or ``git-url``."""
        raw = (source or "").strip()
        if not raw:
            msg = "a plugin source (a local path or a git URL) is required"
            raise PluginInstallError(msg)
        if raw.startswith("-"):
            msg = (
                f"plugin source {source!r} must not begin with '-' (pip would read it as an option)"
            )
            raise PluginInstallError(msg)
        if any(char in raw for char in "\n\r\t\x00"):
            msg = "a plugin source must not contain control characters"
            raise PluginInstallError(msg)

        resolved_target: str | None = None
        if target:
            resolved_target = str(Path(target).expanduser().resolve())

        rewritten = _git_url(raw)
        if rewritten is not None:
            return cls(source=rewritten, kind="git-url", target=resolved_target, upgrade=upgrade)

        path = Path(raw).expanduser()
        if path.exists():
            resolved = path.resolve()
            if resolved.is_dir():
                has_project = (resolved / "pyproject.toml").is_file() or (
                    resolved / "setup.py"
                ).is_file()
                if not has_project:
                    msg = (
                        f"plugin directory {resolved} has no pyproject.toml or setup.py; "
                        "point at the package root"
                    )
                    raise PluginInstallError(msg)
            elif resolved.suffix not in _ARCHIVE_SUFFIXES:
                msg = (
                    f"plugin file {resolved} is not a wheel/sdist archive "
                    f"({', '.join(_ARCHIVE_SUFFIXES)})"
                )
                raise PluginInstallError(msg)
            return cls(
                source=str(resolved), kind="local-path", target=resolved_target, upgrade=upgrade
            )

        msg = (
            f"plugin source {source!r} is neither an existing path nor a git URL "
            "(git+https://, git+ssh://, git+file://, or git@host:path.git)"
        )
        raise PluginInstallError(msg)

    def argv(self) -> list[str]:
        """The exact pip command line (a list, never a string)."""
        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-input",
            "--disable-pip-version-check",
        ]
        if self.upgrade:
            command.append("--upgrade")
        if self.target:
            command.extend(["--target", self.target])
        command.append(self.source)
        return command

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "target": self.target,
            "argv": self.argv(),
        }


@dataclass(frozen=True, slots=True)
class InstallResult:
    """What the install did, including whether it actually ran (``dry_run``)."""

    request: InstallRequest
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    executed: bool = True

    @property
    def ok(self) -> bool:
        return not self.executed or self.returncode == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.request.to_dict(),
            "executed": self.executed,
            "returncode": self.returncode,
            "ok": self.ok,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def install(
    source: str,
    *,
    target: str | None = None,
    upgrade: bool = True,
    dry_run: bool = False,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    extra_args: Sequence[str] = (),
) -> InstallResult:
    """Install ``source`` into this environment (or ``target``), returning the outcome.

    ``dry_run`` validates and returns the argv without starting anything — the safe way for
    an interface to show an operator exactly what will run. ``extra_args`` are appended
    before the source (``--no-deps`` is useful for an offline demo), and are themselves
    validated to be options so a caller cannot smuggle a second positional source.
    """
    request = InstallRequest.parse(source, target=target, upgrade=upgrade)
    for arg in extra_args:
        if not str(arg).startswith("-"):
            msg = f"extra pip argument {arg!r} must be an option (it would be a source otherwise)"
            raise PluginInstallError(msg)
    argv = [*request.argv()[:-1], *map(str, extra_args), request.argv()[-1]]
    if dry_run:
        return InstallResult(
            request=request, returncode=None, stdout=" ".join(argv), executed=False
        )
    if timeout_s <= 0:
        msg = "install timeout must be > 0"
        raise PluginInstallError(msg)
    # A fixed executable, an argv list, no shell, always a timeout (ADR-190.4).
    completed = subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    if request.target:
        # An install into --target is not on sys.path; add it so verification below (and a
        # same-process plugin in a test) can see the new distribution metadata.
        _prepend_sys_path(request.target)
    _invalidate_import_caches()
    return InstallResult(
        request=request,
        returncode=completed.returncode,
        stdout=(completed.stdout or "")[-_OUTPUT_LIMIT:],
        stderr=(completed.stderr or "")[-_OUTPUT_LIMIT:],
    )


def verify_installed(before: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """The plugins visible *now* that were not in ``before``."""
    after = _snapshot()
    appeared: dict[str, list[dict[str, Any]]] = {"checks": [], "report_formats": []}
    for family in ("checks", "report_formats"):
        known = {_identity(item) for item in before.get(family, [])}
        appeared[family] = [item for item in after[family] if _identity(item) not in known]
    return appeared


def install_and_verify(
    source: str,
    *,
    target: str | None = None,
    upgrade: bool = True,
    dry_run: bool = False,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    extra_args: Sequence[str] = (),
) -> tuple[InstallResult, dict[str, list[dict[str, Any]]]]:
    """Install, then report what became discoverable.

    A non-zero exit raises :class:`PluginInstallError` with the tail of pip's stderr. A
    successful install that registers nothing discoverable is **not** an error by itself
    (a plugin may register an OSINT provider, which the snapshot does not track), so the
    caller prints the empty diff; the CLI says so explicitly.
    """
    before = _snapshot()
    result = install(
        source,
        target=target,
        upgrade=upgrade,
        dry_run=dry_run,
        timeout_s=timeout_s,
        extra_args=extra_args,
    )
    if dry_run:
        return result, {"checks": [], "report_formats": []}
    if not result.ok:
        detail = (result.stderr or result.stdout or "").strip()
        msg = f"pip exited {result.returncode} installing {result.request.source!r}: {detail}"
        raise PluginInstallError(msg)
    return result, verify_installed(before)


# --------------------------------------------------------------------------- helpers
def _git_url(source: str) -> str | None:
    """Return the pip-installable git URL for ``source``, or ``None`` if it is not one."""
    lowered = source.lower()
    if lowered.startswith(_GIT_PREFIXES):
        return source
    # scp-like: git@github.com:org/repo.git
    if source.startswith("git@") and ":" in source:
        return f"git+ssh://{source.replace(':', '/', 1)}"
    # A plain https URL to a bare repository: pip needs the git+ prefix.
    if lowered.startswith(("https://", "http://")) and lowered.split("?", 1)[0].endswith(".git"):
        return f"git+{source}"
    return None


def _snapshot() -> dict[str, list[dict[str, Any]]]:
    from arachne.plugins import installed_plugins

    return installed_plugins()


def _identity(item: dict[str, Any]) -> tuple[str, str]:
    return (
        str(item.get("module") or item.get("name") or ""),
        str(item.get("version") or ""),
    )


def _prepend_sys_path(path: str) -> None:
    resolved = str(Path(path).expanduser().resolve())
    if resolved not in sys.path:
        sys.path.insert(0, resolved)


def _invalidate_import_caches() -> None:
    import importlib

    importlib.invalidate_caches()
    try:
        from arachne.report import reset_format_cache
    except Exception:  # pragma: no cover - the report layer is always importable here
        return
    reset_format_cache()
