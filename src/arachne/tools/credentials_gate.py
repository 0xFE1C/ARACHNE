"""The no-default-credentials gate: a repository grep that fails CI (REQ-OPS-006).

The requirement is blunt — *no default credentials ship anywhere* — and the failure mode it
guards against is quiet: a `${VAR:-change-me}` default, a demo API key in a README, a
"temporary" password in the secrets example. None of those break a test, and all of them
become a customer's deployed credential. So the check is a grep, it runs in CI as its own
step, and it has no "warn" mode: a finding exits non-zero.

Design rules, because a gate that is wrong gets deleted:

* **Placeholders are the only allowed value.** Every credential-named assignment in a shipped
  configuration file must be empty, a variable reference, or an obvious placeholder
  (``<random value>``, ``REPLACE_ME``, ``...``, ``change-me``, ``goes-here``). Deciding by
  *shape* rather than by a deny-list is what makes it catch the next invented demo key.
* **Exemptions are verified, not trusted.** The vulnerable-by-design lab fixtures in
  ``docker/docker-compose.yml`` (DVWA's MySQL root password, an empty VNC password, Redis with
  protection off) are intentional and loopback-only. They are exempted **per service**, and the
  gate re-reads the compose file to prove every exempted service is in the ``lab`` profile —
  so an exemption can never cover a service the demo stack starts.
* **Shipped files only.** ``tests/`` fixtures, extracted archives, and the CI workflow are not
  artifacts an operator deploys; the scan covers the deployment surface (``docker/``,
  ``.env.example``, the READMEs).
* **It bites.** ``tests/test_no_default_credentials.py`` runs this gate against a temporary
  tree containing the exact patterns it exists to catch, so a gate that silently stopped
  matching fails the suite rather than passing everything.

Usage::

    python -m arachne.tools.credentials_gate [repo-root]

Exit code is 0 when nothing is found, 1 when it is.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml

__all__ = [
    "CI_FILES",
    "LAB_EXEMPT_SERVICES",
    "Finding",
    "main",
    "scan_paths",
]

#: Files (relative to ``code/``) that an operator deploys or reads: the gate's whole surface.
SHIPPED_FILES: Final[tuple[str, ...]] = (
    "docker/docker-compose.yml",
    "docker/docker-compose.prod.yml",
    "docker/Dockerfile",
    "docker/README.md",
    ".env.example",
    "README.md",
)

#: Directories scanned file-by-file (every ``.example`` and every ``.yml``/``.yaml``).
#: ``deploy/helm`` is the Kubernetes surface (S22): the chart's values and templates
#: are shipped configuration an operator deploys, exactly like the compose files.
SHIPPED_DIRS: Final[tuple[str, ...]] = ("docker/secrets", "docker/demo", "deploy/helm")

#: Compose services whose credentials are *deliberately* broken, because the service is a
#: vulnerable-by-design lab fixture published on loopback only (``profiles: ["lab"]``). The
#: gate proves that is what they are before honouring the exemption.
LAB_EXEMPT_SERVICES: Final[frozenset[str]] = frozenset(
    {"dvwa", "juice-shop", "lab-nginx", "lab-tls", "lab-mysql", "lab-redis", "lab-vnc"}
)

#: CI workflow files: not shipped to operators. The workflows generate throwaway
#: values (the release render-smoke, the compose validation), and this list is
#: documented here rather than implied by a path glob.
CI_FILES: Final[frozenset[str]] = frozenset(
    {".github/workflows/ci.yml", ".github/workflows/release.yml"}
)

#: The words that make a setting a credential *value*. ``key`` alone is included: an
#: ``ARACHNE_VAULT_KEY=shortkey`` is a credential, and the reference-suffix rule is what
#: keeps pointers (``..._KEY_FILE``) and bounds (``..._KEY_LENGTH``) out of the way.
_CREDENTIAL_NAME: Final = r"(?:password|passwd|pwd|secret|token|key|apikey)"
#: ``password: value`` / ``ARACHNE_API_KEYS=value`` in yaml, dotenv or a shell snippet.
#:
#: The two anchors matter more than the name pattern. The name must start at the beginning
#: of a line or after whitespace, ``#``, ``-``, a quote, ``(`` or ``,`` — i.e. where a
#: *setting* is written — which is what stops a value like
#: ``acme-admin:admin:replace-with-a-random-secret`` from being read as a setting named
#: ``...-secret``. And a name that ends in one of :data:`REFERENCE_SUFFIXES` is a pointer to
#: a secret (``POSTGRES_PASSWORD_FILE``), not a secret.
_ASSIGNMENT_RE: Final = re.compile(
    rf"(?<![^\s#'\"(,])"
    rf"(?P<name>[A-Za-z0-9_.\-]*{_CREDENTIAL_NAME}[A-Za-z0-9_.\-]*)"
    rf"\s*[:=]\s*(?P<value>[^\s#].*)",
    re.IGNORECASE,
)

#: Name suffixes that make a credential-named setting a *reference* or a *bound*, not a value.
REFERENCE_SUFFIXES: Final[tuple[str, ...]] = (
    "_file",
    "_path",
    "_dir",
    "_env",
    "_var",
    "_url",
    "_uri",
    "_max",
    "_min",
    "_ttl",
    "_days",
    "_count",
    "_bytes",
    "_seconds",
    "_ms",
    "_name",
    "_user",
    "_id",
    "_mode",
    "_type",
    "_scope",
    "_hosts",
    "_domains",
    "_ports",
    "_labels",
    "_patterns",
    "_algorithms",
    "_claim",
    "_header",
    "_length",
    "_limit",
    "_manifest",
    "_public_key",
    "_tls_key",
    "_cert",
    "_certificate",
)

#: Exact (lower-cased) setting names that, on the Kubernetes deployment surface
#: (``deploy/``), are *pointers* to where a secret lives rather than a secret: a
#: ``secretKeyRef``'s ``key``, a ``secretName``, an ``existingSecret`` reference, an
#: affinity ``topologyKey``. The same shape rule as ``_FILE``-suffixed environment
#: variables — the pointer idiom just spelled in camelCase.
_KUBERNETES_REFERENCE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "key",
        "secretkey",
        "secretname",
        "existingsecret",
        "topologykey",
        "imagepullsecrets",
    }
)

#: Values that are settings rather than secrets.
_BOOLEAN_VALUES: Final[frozenset[str]] = frozenset(
    {"true", "false", "yes", "no", "on", "off", "null", "none"}
)
#: A value that names a file is a *reference* to secret material the operator manages
#: (``/etc/arachne/tls/key.pem``), not a credential shipped in the repository.
_PATH_LIKE_RE: Final = re.compile(r"^(?:[~.]?/|[A-Za-z]:\\|\./)")
#: Compose's ``${VAR:-default}`` — the exact shape of "it works out of the box, and the box is
#: public". ``${VAR:?message}`` (required) is the correct form and is not matched.
_COMPOSE_DEFAULT_RE: Final = re.compile(
    rf"\$\{{[A-Z0-9_]*{_CREDENTIAL_NAME.upper()}[A-Z0-9_]*:-(?P<default>[^}}]*)\}}",
    re.IGNORECASE,
)
#: ``label:role:secret`` — an ARACHNE API key, wherever it is written down.
_API_KEY_TRIPLE_RE: Final = re.compile(
    r"(?<![\w:-])(?P<label>[a-z0-9][a-z0-9_.\-]{1,32}):(?P<role>admin|scanner|viewer):"
    r"(?P<secret>[A-Za-z0-9._\-+/=]{6,})"
)

#: Substrings that make a value an obvious placeholder rather than a working credential.
_PLACEHOLDERS: Final[tuple[str, ...]] = (
    "replace",
    "change-me",
    "changeme",
    "change_me",
    "placeholder",
    "goes-here",
    "goes_here",
    "example",
    "your-",
    "your_",
    "todo",
    "redacted",
    "not-a-secret",
    "not_a_secret",
    "xxx",
    "****",
    "...",
    "\u2026",
    "<",
    "dummy",
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One suspected default credential."""

    path: str
    line: int
    rule: str
    detail: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.detail}"


def _is_placeholder(value: str) -> bool:
    """True when ``value`` cannot be used as a credential as-is."""
    stripped = value.strip().strip("\"'").strip()
    if not stripped:
        return True
    if stripped.startswith(("$", "!", "?")):  # an indirection, or compose's required syntax
        return True
    if stripped.startswith("{{"):  # a helm template reference: resolved at deploy time
        return True
    if "$(" in stripped or "${" in stripped:  # a command substitution or an expansion
        return True
    if re.fullmatch(r"\d+", stripped):  # a bare number is a count, never a secret
        return True
    if stripped in ("{}", "[]"):  # an empty mapping/sequence carries no credential
        return True
    lowered = stripped.lower()
    if lowered in _BOOLEAN_VALUES or _PATH_LIKE_RE.match(stripped):
        return True
    return any(marker in lowered for marker in _PLACEHOLDERS)


def _is_reference(name: str, *, kubernetes: bool = False) -> bool:
    """True when a credential-named setting points at a secret rather than holding one."""
    lowered = name.lower()
    if lowered.endswith(REFERENCE_SUFFIXES):
        return True
    return kubernetes and lowered in _KUBERNETES_REFERENCE_NAMES


def _scan_line(path: str, number: int, line: str, *, in_exempt_service: bool) -> list[Finding]:
    findings: list[Finding] = []
    if in_exempt_service:
        return findings
    # ``deploy/`` is the Kubernetes surface (S22): its ``secretKeyRef``/``secretName``
    # vocabulary names where a secret lives, which is a pointer, not a value.
    kubernetes = path.startswith("deploy/")
    for match in _ASSIGNMENT_RE.finditer(line):
        name, value = match.group("name"), match.group("value")
        if _is_reference(name, kubernetes=kubernetes) or _is_placeholder(value):
            continue
        findings.append(
            Finding(
                path,
                number,
                "credential-default",
                f"{name} has the literal value {value.strip()[:60]!r}",
            )
        )
    for match in _COMPOSE_DEFAULT_RE.finditer(line):
        if _is_placeholder(match.group("default")):
            continue
        findings.append(
            Finding(
                path,
                number,
                "compose-default",
                f"${{...:-{match.group('default')}}} provides a fallback credential",
            )
        )
    for match in _API_KEY_TRIPLE_RE.finditer(line):
        if _is_placeholder(match.group("secret")):
            continue
        findings.append(
            Finding(
                path,
                number,
                "api-key",
                f"an API key for role {match.group('role')!r} is written down",
            )
        )
    return findings


def _lab_services(compose_path: Path) -> frozenset[str]:
    """The services the gate may exempt, *proved* to be lab-profile fixtures."""
    try:
        document = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return frozenset()
    services = document.get("services") or {}
    if not isinstance(services, dict):
        return frozenset()
    return frozenset(
        str(name)
        for name, service in services.items()
        if isinstance(service, dict) and "lab" in (service.get("profiles") or [])
    )


def _service_line_map(compose_path: Path) -> dict[int, str]:
    """Line number → the compose service it belongs to (top-level ``services:`` children)."""
    owners: dict[int, str] = {}
    current: str | None = None
    for number, line in enumerate(compose_path.read_text(encoding="utf-8").splitlines(), start=1):
        if re.match(r"^  [A-Za-z0-9_.\-]+:\s*$", line):
            current = line.strip().rstrip(":")
        if current is not None:
            owners[number] = current
    return owners


def _scan_compose(path: Path, relative: str) -> list[Finding]:
    """Scan a YAML file, skipping the services proved to be lab fixtures.

    ``relative`` (the checkout-relative path) is what the Kubernetes-surface rule
    reads: the pointer idiom applies to ``deploy/`` wherever the checkout lives.
    """
    lab = LAB_EXEMPT_SERVICES & _lab_services(path)
    owners = _service_line_map(path)
    findings: list[Finding] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        owner = owners.get(number)
        findings.extend(
            _scan_line(relative, number, line, in_exempt_service=bool(owner and owner in lab))
        )
    return findings


def shipped_files(root: Path) -> list[Path]:
    """Every file the gate reads, in a deterministic order."""
    files: list[Path] = [root / name for name in SHIPPED_FILES]
    for directory in SHIPPED_DIRS:
        base = root / directory
        if base.is_dir():
            files.extend(sorted(path for path in base.rglob("*") if path.is_file()))
    return [path for path in files if path.is_file()]


def scan_paths(root: Path | str) -> tuple[Finding, ...]:
    """Every suspected default credential under ``root`` (a ``code/`` checkout)."""
    base = Path(root)
    findings: list[Finding] = []
    for path in shipped_files(base):
        relative = path.relative_to(base).as_posix()
        if relative in CI_FILES:
            continue
        if path.suffix in {".yml", ".yaml"}:
            findings.extend(_scan_compose(path, relative))
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            findings.extend(_scan_line(relative, number, line, in_exempt_service=False))
    return tuple(findings)


def main(argv: list[str] | None = None) -> int:
    """Run the gate; return the process exit code (0 clean, 1 findings)."""
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0]) if args else Path(__file__).resolve().parents[3]
    findings = scan_paths(root)
    if not findings:
        sys.stdout.write(f"no default credentials found under {root} (REQ-OPS-006: gate green)\n")
        return 0
    sys.stderr.write("default credentials found (REQ-OPS-006: gate FAILED)\n")
    for finding in findings:
        sys.stderr.write(f"  {finding.render()}\n")
    return 1


if __name__ == "__main__":  # pragma: no cover - exercised as a CI step
    raise SystemExit(main())
