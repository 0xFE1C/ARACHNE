"""Offline mobile-artifact analysis (research ch01#26, REQ-DEPTH-005).

A mobile app is a client the operator ships but does not control: whatever it hardcodes is on
every device that installed it, and whatever endpoints it names are part of the attack surface
nobody inventoried. This check reads an APK or IPA **from the local filesystem** and reports
two things:

* **secrets** — reported exactly as ``m1.js-asset-scan`` reports them: as the *detector names*
  that fired, with the value replaced by a masked fingerprint (F-08-04). A hardcoded key in a
  shipped binary is the same finding as one in a bundle, and it is handled the same way.
* **endpoints** — hostnames and URLs the artifact references, recorded as assets so M1 and M3
  pick them up as targets on the next scan (``REQ-DEPTH-005``: "feeding M1/M3 targets").

**Zero network, and it is structural, not a promise.** The check declares
:data:`~arachne.core.proof.ProofLevel.L0` — it never contacts a target — and it reaches the
filesystem only through :func:`read_artifact`, which imports nothing that can open a socket.
``tests/test_depth_safety.py`` proves it the way the platform proves zero-network simulation
(REQ-SIM-003): an armed-socket fixture fails the test if any entry point is touched while the
check runs, and the same test asserts the check actually read the artifact (so it cannot pass
by doing nothing).

**Opt-in twice over.** Reading a local file is not something a scan should do because a path
appeared somewhere: the check is outside the default set, and the path must be a declared
``artifact`` target covered by the attestation — a deny-by-default scope dimension of its own
(``Scope.allowed_artifacts``). An artifact that is missing, is a directory, or exceeds
``max_bytes`` is refused with a reason rather than read.

Nothing is executed, decompiled or unpacked into a temporary directory: the APK/IPA zip is
read as a container of bytes, its entries are decoded as text where they decode, and the
analysis runs over that text.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

from arachne.core.errors import SafetyError
from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.extract import detect_secrets, extract_emails, extract_endpoints, extract_urls

__all__ = ["MobileArtifactScan", "read_artifact"]

#: The artifact is read up to this size. A shipped app is tens of megabytes; the cap keeps one
#: check from turning into a disk-reading job, and it is a *refusal* rather than a truncation,
#: so an analysis never claims to have covered a file it only partly read.
MAX_ARTIFACT_BYTES = 96 * 1024 * 1024

#: Zip entries worth reading: the executable code and the manifest-ish metadata. Everything
#: else (resources, images) is skipped, which keeps the analysis proportional to the code.
_CODE_SUFFIXES: tuple[str, ...] = (
    "classes.dex",
    "classes2.dex",
    "classes3.dex",
    ".dex",
    "androidmanifest.xml",
    "resources.arsc",
    ".plist",
    ".json",
    ".js",
    ".properties",
    ".strings",
    "plugin",
    ".so",
)

#: How many entries one artifact may contribute to the text scan.
MAX_ENTRIES_SCANNED = 40
#: Bytes read from each entry.
MAX_ENTRY_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArtifactContents:
    """What was read out of one artifact: its entries as decoded text, plus the facts."""

    path: str
    size: int
    entries: tuple[tuple[str, str], ...] = ()
    skipped_entries: int = 0

    @property
    def scanned(self) -> int:
        return len(self.entries)


def read_artifact(path: str, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> ArtifactContents:
    """Read an APK/IPA as text. Pure filesystem access — no socket is imported or reachable.

    A zip is the container for both formats, so one reader covers APK and IPA. Entries whose
    names suggest code or manifest metadata are decoded as ``latin-1`` (a binary that is *not*
    text still contains printable strings, and a mis-decoded byte must not raise); everything
    else is counted and skipped.
    """
    artifact = Path(path)
    if not artifact.is_absolute():
        raise SafetyError(f"refusing a relative artifact path {path!r}")
    if not artifact.is_file():
        raise SafetyError(f"artifact {path!r} is not a readable file")
    size = artifact.stat().st_size
    if size > max_bytes:
        raise SafetyError(
            f"artifact {path!r} is {size} bytes, above the {max_bytes}-byte analysis cap"
        )
    entries: list[tuple[str, str]] = []
    skipped = 0
    data = artifact.open("rb").read(max_bytes)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SafetyError(f"artifact {path!r} is not a zip container: {exc}") from exc
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if len(entries) >= MAX_ENTRIES_SCANNED:
                skipped += 1
                continue
            lowered = info.filename.lower()
            if not any(lowered.endswith(suffix) for suffix in _CODE_SUFFIXES):
                skipped += 1
                continue
            try:
                raw = archive.read(info)[:MAX_ENTRY_BYTES]
            except (zipfile.BadZipFile, RuntimeError, OSError):
                skipped += 1
                continue
            entries.append((info.filename, raw.decode("latin-1", "replace")))
    return ArtifactContents(path=path, size=size, entries=tuple(entries), skipped_entries=skipped)


@dataclass(frozen=True, slots=True)
class _ArtifactSignals:
    """Everything the static pass found across an artifact's entries."""

    secrets: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    sources: dict[str, tuple[str, ...]] = field(default_factory=dict)


def _scan_contents(contents: ArtifactContents) -> _ArtifactSignals:
    """Run the shared extractors over every decoded entry.

    The extractors are the ones M1 already uses (``modules/extract``), so "what a secret looks
    like" and "what an endpoint looks like" have one definition in the codebase and the mobile
    half cannot drift from the web half.
    """
    secrets: dict[str, None] = {}
    endpoints: dict[str, None] = {}
    urls: dict[str, None] = {}
    emails: dict[str, None] = {}
    sources: dict[str, list[str]] = {}
    for name, text in contents.entries:
        for match in detect_secrets(text, limit=40):
            secrets.setdefault(match.kind, None)
            sources.setdefault("secret", []).append(name)
        for endpoint in extract_endpoints(text, limit=200):
            endpoints.setdefault(endpoint, None)
            sources.setdefault("endpoint", []).append(name)
        for url in extract_urls(text, limit=200):
            urls.setdefault(url, None)
            sources.setdefault("url", []).append(name)
        for address in extract_emails(text, limit=50):
            emails.setdefault(address, None)
    return _ArtifactSignals(
        secrets=tuple(secrets),
        endpoints=tuple(endpoints),
        urls=tuple(urls),
        emails=tuple(emails),
        sources={key: tuple(dict.fromkeys(value)) for key, value in sources.items()},
    )


class MobileArtifactScan(Module):
    """``m1.mobile-artifact`` — offline APK/IPA secret and endpoint analysis (ch01#26)."""

    metadata = CheckMetadata(
        id="m1.mobile-artifact",
        module="M1",
        name="mobile-artifact",
        version="1.0",
        title="Offline mobile artifact analysis",
        description=(
            "Reads a declared APK/IPA locally and reports the credential patterns its code "
            "contains (as detector names, values masked) and the endpoints and hosts it "
            "references, which are recorded as assets for M1 and M3. Offline: the check makes "
            "no network request at all, and nothing is executed, decompiled or unpacked."
        ),
        research_ref="ch01#26",
        framework=("WSTG-INFO-05", "CWE-798"),
        cwe="CWE-798",
        target_kinds=(TargetKind.ARTIFACT,),
        severity_hint="medium",
        type="passive",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        proof=ProofLevel.L0,
        estimated_requests=0,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        path = ctx.asset.value
        try:
            contents = read_artifact(path)
        except SafetyError as exc:
            yield ctx.skipped(f"artifact not analyzed: {exc}")
            return
        if not contents.entries:
            yield ctx.clean(
                f"no code or manifest entry found in {Path(path).name}",
                detail=(
                    f"the container holds {contents.skipped_entries} entry/entries, none of "
                    "them a code or manifest file this analysis reads"
                ),
                confidence=0.6,
            )
            return

        signals = _scan_contents(contents)
        recorded = 0
        for url in signals.urls[: ctx.config.max_assets]:
            # Only same-origin-free absolute URLs are recorded as assets; the scope gate
            # decides whether they are in scope at all (F-01-02).
            if await ctx.record_asset(
                "url", url, meta={"discovered_by": "mobile-artifact"}, source="mobile-artifact"
            ):
                recorded += 1

        evidence = [
            ctx.evidence(
                "artifact",
                {
                    "path": path,
                    "bytes": contents.size,
                    "entries_scanned": [name for name, _ in contents.entries],
                    "entries_skipped": contents.skipped_entries,
                    "matched_patterns": list(signals.secrets),
                    "endpoints": list(signals.endpoints)[:100],
                    "urls": list(signals.urls)[:100],
                    "emails": list(signals.emails)[:20],
                    "urls_recorded_as_assets": recorded,
                    "network_requests": 0,
                    "executed": False,
                },
                source=path,
            )
        ]

        yield ctx.info(
            f"mobile artifact analyzed: {contents.scanned} entr(y/ies) of {Path(path).name}",
            detail=(
                f"{len(signals.endpoints)} endpoint(s), {len(signals.urls)} URL(s), "
                f"{len(signals.secrets)} credential pattern(s); {recorded} URL(s) recorded as "
                "assets for M1/M3. Analysis was offline: no network request was made."
            ),
            evidence=evidence,
            confidence=0.8,
        )

        if signals.secrets:
            yield ctx.candidate(
                f"{len(signals.secrets)} credential pattern(s) hardcoded in {Path(path).name}",
                detail=(
                    "a shipped mobile binary is on every device that installed it, so a "
                    "credential compiled into it is public. Values are masked at extraction "
                    "(F-08-04) and reported as detector names: "
                    + ", ".join(sorted(signals.secrets))
                    + ". Rotate the credential and move it server-side; a mobile client can "
                    "never keep a secret (research ch01#26)."
                ),
                cwe="CWE-798",
                evidence=evidence,
                confidence=0.6,
            )
