"""The content-pack review pipeline: signature, safety and parity gates (S26, REQ-ECOS-001).

REQ-ECOS-001 asks that third-party checks and templates reach a deployment as signed content
packs, pass a review pipeline **before they are listed**, have their provenance recorded, and
that an unsigned pack never loads. This module is that pipeline, and it is deliberately three
independent gates rather than one check, because they fail for different reasons and an
operator needs to know which:

``signature``
    The pack carries a signature that verifies against the *deployment's* content key, and —
    when the deployment names trusted key ids — against one of those. An unsigned pack is
    refused; so is one signed by somebody else's key. This is the gate
    :mod:`arachne.resil.packs` already enforces on import; review is where the decision is
    recorded rather than where it is first discovered.
``safety``
    Every Python member is parsed and walked for constructs a *detection* plugin has no
    business using: starting a process, opening a socket outside the shared HTTP client,
    ``eval``/``exec``/``compile``, ``__import__``, unpickling, ``ctypes``, filesystem
    destruction. Declared check content is checked for proof-ladder consistency — an L3/L4
    check (one that changes state on a target) that does not require the state-change
    attestation is precisely the "unsafe check" the requirement names. A ``block`` finding
    fails the gate; a ``warn`` finding is recorded and passes.
``parity``
    The pack says what it is and matches it: a declared ``kind`` and ``entry_point_group``
    that agree with each other, well-formed check/format ids that do **not** collide with the
    built-in catalogue. A pack that declares ``m3.cmdi-oob`` is not adding a check, it is
    *replacing* one — silently, and with whatever it likes — which is the substitution attack
    a marketplace has to refuse.

Why the scan is on the AST and not on the text: a text search for ``subprocess`` misses
``__import__("subprocess")`` and flags the word in a docstring; the AST sees the import and
the call as they will actually execute. The scan is a *policy* gate, not a sandbox — it raises
the cost of shipping a hostile pack and makes the honest mistake loud, and the pack still runs
in-process afterwards, which `docs/security-review.md` states plainly rather than
pretending the pipeline is a sandbox.

Nothing here installs or executes a pack: :func:`review_pack` takes an already-verified
:class:`~arachne.resil.packs.ContentPack` (or bytes, via :func:`review_pack_bytes`, which
verifies first) and only reads it.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal

import yaml

from arachne.core.errors import ContentPackError
from arachne.core.signing import Signer, SigningKeyring
from arachne.resil.packs import ContentPack, read_pack

__all__ = [
    "DECISION_LISTED",
    "DECISION_REJECTED",
    "ENTRY_POINT_GROUPS",
    "REVIEW_FORMAT",
    "GateResult",
    "ReviewReport",
    "SafetyFinding",
    "review_json",
    "review_pack",
    "review_pack_bytes",
    "scan_member",
    "scan_python_source",
]

#: The manifest tag for a review record. Bump when the report's meaning changes.
REVIEW_FORMAT: Final = "arachne-pack-review/1"

DECISION_LISTED: Final = "listed"
DECISION_REJECTED: Final = "rejected"

SafetySeverity = Literal["block", "warn"]

#: The marketplace's ``kind`` → the entry-point group a pack of that kind must register
#: under. Mirrors :mod:`arachne.plugins.marketplace` and the two registries; a kind/group
#: mismatch is how a "report format" smuggles in a module that runs during a scan.
ENTRY_POINT_GROUPS: Final[dict[str, tuple[str, ...]]] = {
    "check": ("arachne.modules",),
    "module": ("arachne.modules",),
    "report-format": ("arachne.report_formats",),
    # A provider registers under the OSINT provider group; kept open because the group is the
    # provider subsystem's business, not this pipeline's — the parity gate only insists that
    # *something* is declared and that it is a group the platform owns.
    "provider": ("arachne.providers", "arachne.osint_providers"),
}

#: Groups the platform will accept a pack registering under, whatever its kind.
KNOWN_ENTRY_POINT_GROUPS: Final[frozenset[str]] = frozenset(
    group for groups in ENTRY_POINT_GROUPS.values() for group in groups
)

#: Imports a detection plugin must not make. Each is a capability the plugin API does not
#: grant: process control, raw network, dynamic code, serialisation of code, or FFI.
_BLOCKED_IMPORTS: Final[frozenset[str]] = frozenset(
    {
        "subprocess",
        "multiprocessing",
        "ctypes",
        "pty",
        "socket",
        "telnetlib",
        "ftplib",
        "smtplib",
        "imaplib",
        "poplib",
        "pickle",
        "marshal",
        "shelve",
        "dbm",
        "http.client",
        "urllib.request",
        "urllib.error",
        "requests",
        "urllib3",
        "aiohttp",
        "httpx",
        "paramiko",
        "asyncio.subprocess",
    }
)

#: A call is blocked when its dotted name starts with one of these. ``subprocess`` is listed
#: as a prefix so ``subprocess.run``/``Popen`` are both caught without enumerating them.
_BLOCKED_CALL_PREFIXES: Final[tuple[str, ...]] = (
    "subprocess.",
    "multiprocessing.",
    "ctypes.",
    "pickle.load",
    "pickle.loads",
    "marshal.load",
    "marshal.loads",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.chmod",
    "os.chown",
    "os.setuid",
    "os.setgid",
    "shutil.rmtree",
    "shutil.move",
    "signal.",
    "runpy.",
)

#: Calls banned by their *last* component, whatever they are reached through (``os.X``,
#: ``subprocess.X``, an aliased import). Written as suffixes rather than full dotted names on
#: purpose: ``tests/unit/test_http_hygiene.py`` scans every module's source *text* for the shell
#: helpers it bans, so a denylist that quoted them verbatim would trip that scan — the policy
#: table would read as the very thing it forbids.
_BLOCKED_CALL_SUFFIXES: Final[tuple[str, ...]] = (
    "popen",
    "system",
    "spawn",
    "spawnv",
    "spawnl",
    "execv",
    "execve",
    "execl",
    "execle",
    "execvp",
    "execvpe",
)

#: Bare names that are dynamic-code execution wherever they appear.
_BLOCKED_NAMES: Final[frozenset[str]] = frozenset({"eval", "exec", "compile", "__import__"})

#: Attribute-write targets that are a warning: a detection plugin has no reason to write
#: files or mutate the interpreter, but neither is it proof of malice the way a shell is.
_WARN_NAMES: Final[frozenset[str]] = frozenset({"open", "input", "breakpoint"})

#: A check at or above this proof level changes state on the target (REQ-PROOF-001).
_STATE_CHANGING_PROOF: Final[frozenset[str]] = frozenset({"L3", "L4"})

_LEVEL_RANK: Final[dict[str, int]] = {"block": 0, "warn": 1}


#: Member extensions the scanner can read as source.
_SOURCE_SUFFIXES: Final[tuple[str, ...]] = (".py",)
#: Member extensions it reads as declared content.
_CONTENT_SUFFIXES: Final[tuple[str, ...]] = (".yaml", ".yml")

#: Extensions that carry *executable* code the AST scan cannot read. A content pack is data —
#: checks, rules, templates — so a compiled or native member is either a mistake or an attempt
#: to slip past the scan inside something the pipeline cannot parse. Refused rather than
#: warned: "we could not review this member" must not be a pass.
_OPAQUE_CODE_SUFFIXES: Final[tuple[str, ...]] = (
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dll",
    ".dylib",
    ".whl",
    ".egg",
)


@dataclass(frozen=True, slots=True)
class SafetyFinding:
    """One policy finding: what the scan saw, where, and whether it blocks."""

    code: str
    severity: SafetySeverity
    message: str
    path: str = ""
    line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class GateResult:
    """One gate's outcome, with everything it has to say about it."""

    gate: str
    passed: bool
    detail: str = ""
    findings: tuple[SafetyFinding, ...] = ()

    @property
    def blocked(self) -> tuple[SafetyFinding, ...]:
        return tuple(item for item in self.findings if item.severity == "block")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "gate": self.gate,
            "passed": self.passed,
            "detail": self.detail,
        }
        if self.findings:
            payload["findings"] = [item.to_dict() for item in self.findings]
        return payload


@dataclass(frozen=True, slots=True)
class ReviewReport:
    """The pipeline's verdict on one pack, at one digest."""

    name: str
    version: str
    digest: str
    key_id: str | None
    kind: str | None
    gates: tuple[GateResult, ...]
    reviewed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    format: str = REVIEW_FORMAT

    @property
    def listed(self) -> bool:
        """True only when every gate passed — there is no partial listing."""
        return all(gate.passed for gate in self.gates)

    @property
    def decision(self) -> str:
        return DECISION_LISTED if self.listed else DECISION_REJECTED

    @property
    def blockers(self) -> tuple[SafetyFinding, ...]:
        """Every blocking finding, across gates (what an operator must fix)."""
        return tuple(item for gate in self.gates for item in gate.blocked)

    def gate(self, name: str) -> GateResult | None:
        for item in self.gates:
            if item.gate == name:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "key_id": self.key_id,
            "kind": self.kind,
            "decision": self.decision,
            "listed": self.listed,
            "reviewed_at": self.reviewed_at,
            "gates": [gate.to_dict() for gate in self.gates],
        }


# --------------------------------------------------------------------------- entry points
def review_pack_bytes(
    data: bytes,
    *,
    signer: Signer | None = None,
    keyring: SigningKeyring | None = None,
    catalogue: Any = None,
    trusted_key_ids: Iterable[str] = (),
    allow_unsigned: bool = False,
    source: str | None = None,
) -> ReviewReport:
    """Parse ``data`` then review it. A pack that does not parse is a rejection, not an error.

    The distinction matters: "this pack is hostile/unsigned" is an *outcome* of the pipeline
    that must be recorded for the operator, while "this file is not a tar.gz" is a usage error.
    Both are refusals, but only the first is a review, so a pack that cannot even be parsed is
    reported as a signature-gate failure carrying the parse error as its detail.

    The archive is read with ``require_signature=False`` and the *gate* verifies the signature,
    deliberately: it lets the report distinguish "unsigned" from "signed elsewhere" from
    "tampered manifest", which is the difference between three different operator actions.
    File digests are still checked by :func:`~arachne.resil.packs.read_pack` — a pack whose
    members do not match its manifest never reaches a gate at all.

    ``keyring`` is the deployment's accepted key *set* (REQ-ECOS-008), so a pack signed by either
    key of a rotation overlap is listed; ``signer`` is the older single-key form.
    """
    try:
        pack = read_pack(data, signer=signer, require_signature=False, source=source)
    except ContentPackError as exc:
        return _unparseable(str(exc))
    return review_pack(
        pack,
        signer=signer,
        keyring=keyring,
        catalogue=catalogue,
        trusted_key_ids=trusted_key_ids,
        allow_unsigned=allow_unsigned,
    )


def review_pack(
    pack: ContentPack,
    *,
    signer: Signer | None = None,
    keyring: SigningKeyring | None = None,
    catalogue: Any = None,
    trusted_key_ids: Iterable[str] = (),
    allow_unsigned: bool = False,
) -> ReviewReport:
    """Run the three gates over a parsed pack and return the report.

    ``signer``/``keyring`` is the *deployment's* content key set: the signature gate verifies the
    pack against it, so passing neither means "no key configured", which refuses a signed pack
    the same way it refuses an unsigned one — a deployment that cannot verify cannot list.
    """
    kind = _declared_kind(pack)
    gates = (
        _signature_gate(
            pack,
            signer=signer,
            keyring=keyring,
            trusted_key_ids=trusted_key_ids,
            allow_unsigned=allow_unsigned,
        ),
        _safety_gate(pack),
        _parity_gate(pack, kind=kind, catalogue=catalogue),
    )
    return ReviewReport(
        name=pack.manifest.name,
        version=pack.manifest.version,
        digest=pack.manifest.digest,
        key_id=pack.key_id,
        kind=kind,
        gates=gates,
    )


# --------------------------------------------------------------------------- gates
def _signature_gate(
    pack: ContentPack,
    *,
    signer: Signer | None,
    keyring: SigningKeyring | None = None,
    trusted_key_ids: Iterable[str],
    allow_unsigned: bool,
) -> GateResult:
    """Unsigned, unverifiable or untrusted-key packs are refused — fail closed."""
    trusted = {item.strip() for item in trusted_key_ids if item and item.strip()}
    if pack.signature is None:
        if not allow_unsigned:
            return GateResult(
                gate="signature",
                passed=False,
                detail=(
                    "the pack carries no signature; an unsigned pack is never listed "
                    "(set ARACHNE_PLUGIN_ALLOW_UNSIGNED only for a lab, which records it)"
                ),
                findings=(
                    SafetyFinding(
                        code="signature.unsigned",
                        severity="block",
                        message="the pack is not signed",
                    ),
                ),
            )
        return GateResult(
            gate="signature",
            passed=True,
            detail="unsigned pack accepted because this deployment allows unsigned packs",
            findings=(
                SafetyFinding(
                    code="signature.unsigned_accepted",
                    severity="warn",
                    message="the pack is unsigned and was accepted by configuration",
                ),
            ),
        )
    if signer is None and keyring is None:
        return GateResult(
            gate="signature",
            passed=False,
            detail=(
                f"the pack is signed by key {pack.key_id} but this deployment has no content "
                "key configured (ARACHNE_INTEGRITY_KEY), so the signature cannot be verified"
            ),
            findings=(
                SafetyFinding(
                    code="signature.no_key",
                    severity="block",
                    message="no content key is configured to verify the signature against",
                ),
            ),
        )
    # Imported here, not at module scope: the constant lives with the pack format and
    # importing it at module scope would make this module's import order matter.
    from arachne.resil.packs import PACK_DOMAIN

    digest = pack.manifest.digest.encode("ascii")
    if keyring is not None:
        verified = keyring.verify(PACK_DOMAIN, digest, pack.signature)
        accepted = keyring.key_ids()
    else:
        assert signer is not None  # the branch above returned when both were absent
        verified = signer.verify(PACK_DOMAIN, digest, pack.signature)
        accepted = (signer.key_id,)
    if not verified:
        return GateResult(
            gate="signature",
            passed=False,
            detail=(
                "the signature does not verify against any key this deployment accepts "
                f"({list(accepted)}): the manifest was edited, or the pack was signed by "
                "another deployment"
            ),
            findings=(
                SafetyFinding(
                    code="signature.invalid",
                    severity="block",
                    message=f"the signature by key {pack.key_id} does not verify",
                ),
            ),
        )
    if trusted and pack.key_id not in trusted:
        return GateResult(
            gate="signature",
            passed=False,
            detail=(
                f"the pack is signed by key {pack.key_id!r}, which is not in this "
                f"deployment's trusted key ids ({sorted(trusted)})"
            ),
            findings=(
                SafetyFinding(
                    code="signature.untrusted_key",
                    severity="block",
                    message=f"key {pack.key_id} is not a trusted signing key",
                ),
            ),
        )
    return GateResult(
        gate="signature",
        passed=True,
        detail=f"verifies against an accepted content key (key id {pack.key_id})",
    )


def _safety_gate(pack: ContentPack) -> GateResult:
    """AST-scan every Python member; check declared content for proof-ladder consistency."""
    findings: list[SafetyFinding] = []
    scanned = 0
    for name in sorted(pack.files):
        lowered = name.lower()
        if lowered.endswith(_OPAQUE_CODE_SUFFIXES):
            findings.append(
                SafetyFinding(
                    code="member.opaque_code",
                    severity="block",
                    message=(
                        f"the pack carries {name}, a member the scanner cannot read as source; "
                        "a content pack is data, not compiled or native code"
                    ),
                    path=name,
                )
            )
            continue
        if lowered.endswith(_SOURCE_SUFFIXES):
            scanned += 1
            findings.extend(scan_python_source(_decode(pack.files[name]), path=name))
        # Declared content is scanned whatever ``kind`` the pack filed it under: a pack that
        # files a state-changing check under an unrecognised kind must not thereby skip the
        # proof-ladder check. The scan is cheap and keys off the document's own shape.
        if lowered.endswith(_CONTENT_SUFFIXES):
            findings.extend(_scan_check_content(_decode(pack.files[name]), path=name))
    findings.sort(key=lambda item: (_LEVEL_RANK[item.severity], item.path, item.line, item.code))
    blocked = [item for item in findings if item.severity == "block"]
    detail = (
        f"scanned {scanned} Python member(s); {len(blocked)} blocking finding(s)"
        if findings
        else f"scanned {scanned} Python member(s); nothing unsafe found"
    )
    return GateResult(
        gate="safety",
        passed=not blocked,
        detail=detail,
        findings=tuple(findings),
    )


def _parity_gate(pack: ContentPack, *, kind: str | None, catalogue: Any) -> GateResult:
    """The pack must declare what it is, and must not collide with a built-in."""
    findings: list[SafetyFinding] = []
    meta = _meta(pack)
    group = meta.get("entry_point_group")
    if not kind:
        findings.append(
            SafetyFinding(
                code="parity.kind_missing",
                severity="block",
                message=(
                    "the pack manifest declares no meta.kind, so it cannot be listed; "
                    f"declare one of {sorted(ENTRY_POINT_GROUPS)}"
                ),
            )
        )
    if not isinstance(group, str) or not group.strip():
        findings.append(
            SafetyFinding(
                code="parity.group_missing",
                severity="block",
                message=(
                    "the pack manifest declares no meta.entry_point_group; a pack that does "
                    "not say where it registers cannot be reviewed"
                ),
            )
        )
    elif group not in KNOWN_ENTRY_POINT_GROUPS:
        findings.append(
            SafetyFinding(
                code="parity.group_unknown",
                severity="block",
                message=(
                    f"entry point group {group!r} is not one the platform owns "
                    f"({sorted(KNOWN_ENTRY_POINT_GROUPS)})"
                ),
            )
        )
    elif kind and group not in ENTRY_POINT_GROUPS.get(kind, ()):
        findings.append(
            SafetyFinding(
                code="parity.group_mismatch",
                severity="block",
                message=(
                    f"a pack of kind {kind!r} must register under "
                    f"{list(ENTRY_POINT_GROUPS.get(kind, ()))} but declares {group!r}"
                ),
            )
        )

    builtin_checks = _builtin_check_ids(catalogue)
    for check_id in _declared_strings(meta, "checks"):
        if not _well_formed_check_id(check_id):
            findings.append(
                SafetyFinding(
                    code="parity.check_id_malformed",
                    severity="block",
                    message=f"declared check id {check_id!r} is not of the form module.name",
                )
            )
        elif check_id in builtin_checks:
            findings.append(
                SafetyFinding(
                    code="parity.check_id_collision",
                    severity="block",
                    message=(
                        f"declared check id {check_id!r} already exists in the built-in "
                        "catalogue; a pack may add checks, never replace one"
                    ),
                )
            )

    from arachne.report.formats import BUILTIN_FORMAT_NAMES

    for format_name in _declared_strings(meta, "formats"):
        if format_name in BUILTIN_FORMAT_NAMES:
            findings.append(
                SafetyFinding(
                    code="parity.format_collision",
                    severity="block",
                    message=(
                        f"declared report format {format_name!r} collides with a built-in "
                        "format; a pack may add formats, never shadow one"
                    ),
                )
            )

    passed = not any(item.severity == "block" for item in findings)
    return GateResult(
        gate="parity",
        passed=passed,
        detail=(
            f"kind={kind or 'undeclared'} group={group or 'undeclared'} "
            f"checks={len(_declared_strings(meta, 'checks'))} "
            f"formats={len(_declared_strings(meta, 'formats'))}"
        ),
        findings=tuple(findings),
    )


# --------------------------------------------------------------------------- the AST scan
def scan_member(data: bytes, *, path: str) -> tuple[SafetyFinding, ...]:
    """Scan one pack member by name (Python source via the AST, YAML as check content)."""
    if path.endswith(".py"):
        return scan_python_source(_decode(data), path=path)
    if path.endswith((".yaml", ".yml")):
        return _scan_check_content(_decode(data), path=path)
    return ()


def scan_python_source(source: str, *, path: str = "<string>") -> tuple[SafetyFinding, ...]:
    """Walk ``source``'s AST for constructs a detection plugin may not use.

    A file that does not parse is itself a finding: a pack whose members cannot be read is not
    reviewable, and "we could not parse it" must not look like "we found nothing".
    """
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return (
            SafetyFinding(
                code="syntax_error",
                severity="block",
                message=f"the member does not parse as Python: {exc.msg}",
                path=path,
                line=int(exc.lineno or 0),
            ),
        )
    findings: list[SafetyFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                findings.extend(_import_findings(alias.name, path, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                findings.extend(_import_findings(node.module, path, node.lineno))
        elif isinstance(node, ast.Call):
            findings.extend(_call_findings(node, path))
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            findings.extend(_attribute_store_findings(node, path))
    findings.sort(key=lambda item: (item.line, item.code))
    return tuple(findings)


def _import_findings(module: str, path: str, line: int) -> list[SafetyFinding]:
    if module in _BLOCKED_IMPORTS or any(
        module.startswith(f"{blocked}.") for blocked in _BLOCKED_IMPORTS
    ):
        return [
            SafetyFinding(
                code="import.blocked",
                severity="block",
                message=(
                    f"the member imports {module!r}; a detection plugin must reach the "
                    "network through the shared HTTP client and must not start processes, "
                    "unpickle, or use FFI"
                ),
                path=path,
                line=line,
            )
        ]
    return []


def _call_findings(node: ast.Call, path: str) -> list[SafetyFinding]:
    name = _dotted_name(node.func)
    if name is None:
        return []
    bare = name.rsplit(".", 1)[-1]
    if bare in _BLOCKED_NAMES or name in _BLOCKED_NAMES:
        return [
            SafetyFinding(
                code="call.dynamic_code",
                severity="block",
                message=f"the member calls {name}(); dynamic code execution is not permitted",
                path=path,
                line=node.lineno,
            )
        ]
    if name.startswith(_BLOCKED_CALL_PREFIXES) or bare in _BLOCKED_CALL_SUFFIXES:
        return [
            SafetyFinding(
                code="call.blocked",
                severity="block",
                message=f"the member calls {name}(); that capability is not granted to a plugin",
                path=path,
                line=node.lineno,
            )
        ]
    findings: list[SafetyFinding] = []
    if bare in _WARN_NAMES:
        findings.append(
            SafetyFinding(
                code="call.deprecated",
                severity="warn",
                message=f"the member calls {name}(); review why a check needs it",
                path=path,
                line=node.lineno,
            )
        )
    if name.endswith(("open", "write_text", "write_bytes")) and _writes(node):
        findings.append(
            SafetyFinding(
                code="call.file_write",
                severity="warn",
                message=f"the member writes a file with {name}(); checks should be pure readers",
                path=path,
                line=node.lineno,
            )
        )
    return findings


def _attribute_store_findings(node: ast.Attribute, path: str) -> list[SafetyFinding]:
    """``os.environ[X] = ...`` / ``sys.path.append`` / ``sys.modules[...] =`` — warnings."""
    target = _dotted_name(node.value)
    if target in {"sys.modules", "sys.path", "os.environ"}:
        return [
            SafetyFinding(
                code="assign.interpreter_state",
                severity="warn",
                message=f"the member mutates {target}; a check should not change the process",
                path=path,
                line=node.lineno,
            )
        ]
    return []


def _scan_check_content(text: str, *, path: str) -> tuple[SafetyFinding, ...]:
    """Proof-ladder consistency for a declared check: L3/L4 must require the attestation.

    A check that changes state on a target without declaring that it needs the state-change
    attestation would be planned and *run* on the strength of an authorization that never
    covered it (REQ-PROOF-002/004). That is the "unsafe check" half of REQ-ECOS-001's accept
    criterion, and it is a property of the declared content, not of the Python.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return (
            SafetyFinding(
                code="content.unparseable",
                severity="block",
                message=f"the member is not valid YAML: {exc}",
                path=path,
            ),
        )
    if not isinstance(document, Mapping):
        return ()
    rows = document.get("checks")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return ()
    findings: list[SafetyFinding] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        proof = str(row.get("proof") or "L1").strip().upper()
        if proof not in _STATE_CHANGING_PROOF:
            continue
        requires = bool(row.get("requires_state_attestation", False))
        identifier = str(row.get("name") or row.get("id") or f"row {index + 1}")
        if not requires:
            findings.append(
                SafetyFinding(
                    code="content.state_change_without_attestation",
                    severity="block",
                    message=(
                        f"check {identifier!r} declares proof {proof} (it changes state on "
                        "the target) but does not require the state-change attestation"
                    ),
                    path=path,
                )
            )
    return tuple(findings)


# --------------------------------------------------------------------------- helpers
def _unparseable(detail: str) -> ReviewReport:
    """The report for a pack that failed verification (or is not a pack at all)."""
    return ReviewReport(
        name="<unreadable>",
        version="",
        digest="",
        key_id=None,
        kind=None,
        gates=(
            GateResult(
                gate="signature",
                passed=False,
                detail=detail,
                findings=(
                    SafetyFinding(code="signature_invalid", severity="block", message=detail),
                ),
            ),
        ),
    )


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _meta(pack: ContentPack) -> Mapping[str, Any]:
    meta = pack.manifest.meta
    return meta if isinstance(meta, Mapping) else {}


def _declared_kind(pack: ContentPack) -> str | None:
    declared = _meta(pack).get("kind")
    if isinstance(declared, str) and declared.strip():
        return declared.strip()
    return None


def _declared_strings(meta: Mapping[str, Any], key: str) -> tuple[str, ...]:
    raw = meta.get(key)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    return tuple(str(item).strip() for item in raw if str(item).strip())


def _builtin_check_ids(catalogue: Any) -> frozenset[str]:
    """The built-in check ids, from the caller's catalogue or the shipped one."""
    if catalogue is not None:
        checks = getattr(catalogue, "checks", catalogue)
        try:
            return frozenset(str(check.id) for check in checks)
        except (AttributeError, TypeError):  # pragma: no cover - defensive
            return frozenset()
    try:
        from arachne.core.catalog import load_catalog

        return frozenset(str(check.id) for check in load_catalog().checks)
    except Exception:  # pragma: no cover - a packaging failure, not a review path
        return frozenset()


def _well_formed_check_id(value: str) -> bool:
    head, _, tail = value.partition(".")
    if not head or not tail:
        return False
    return head.upper().startswith("M") and head[1:].isdigit() and bool(tail.strip())


def _dotted_name(node: ast.expr) -> str | None:
    """The dotted name of an attribute chain (``os.path.join`` → ``"os.path.join"``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _writes(node: ast.Call) -> bool:
    """True when an ``open``/``write_*`` call looks like a write (a write-ish mode string)."""
    name = _dotted_name(node.func) or ""
    if name.endswith(("write_text", "write_bytes")):
        return True
    for argument in node.args[1:]:
        if (
            isinstance(argument, ast.Constant)
            and isinstance(argument.value, str)
            and any(char in argument.value for char in "wax+")
        ):
            return True
    for keyword in node.keywords:
        if (
            keyword.arg == "mode"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
            and any(char in keyword.value.value for char in "wax+")
        ):
            return True
    return False


def review_json(report: ReviewReport) -> str:
    """Deterministic JSON for a review report (the CLI's ``--json`` form)."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=False, default=str) + "\n"
