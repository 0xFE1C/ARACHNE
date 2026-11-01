"""TLS deep scan: protocols, cipher suites, certificate and trust posture (ch02#14).

The stdlib pass, which is the default and the offline path (docs/spec/07- §9.1):

1. **Negotiate once** to learn what the endpoint offers by default and to collect the
   certificate DER (``certificate_der``).
2. **Verify separately**, with a real trust store, to learn whether the chain *validates* —
   the only way to report "untrusted" without losing the certificate.
3. **Probe each protocol version** (SSLv3 → TLS 1.3) with the version pinned, which is how
   a scanner finds the TLS 1.0 an operator thought they had disabled.
4. **Probe a curated cipher list** one suite at a time, weakest first, so "this server still
   accepts RC4/3DES/anonymous suites" is an observation rather than an inference.
5. **Read the certificate** with :mod:`arachne.modules.m2.x509` and turn the facts into
   findings: expired, not-yet-valid, self-signed, hostname mismatch, weak key, weak signature.

Each step is bounded (a fixed version list, a curated cipher list, one handshake each) and
every handshake goes through :class:`~arachne.core.net.ScopedNetClient`, so the scope guard,
the per-host rate limiter and the audit trail apply exactly as they do to a port probe.

For operators who want the full matrix, ``ARACHNE_NET_TLS_TOOL`` runs an external
``testssl.sh``/``sslscan`` in addition (see :mod:`arachne.modules.m2.external`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from arachne.core.net import (
    LEGACY_TLS_VERSIONS,
    PINNABLE_TLS_VERSIONS,
    TLS_VERSION_ORDER,
    WEAK_CIPHER_CANDIDATES,
    ScopedNetClient,
    TlsProfile,
    TlsVersionProbe,
    legacy_version_cap_options,
)
from arachne.modules.m2.x509 import CertificateInfo, parse_certificate

__all__ = [
    "CERTIFICATE_ISSUES",
    "TlsAssessment",
    "TlsIssue",
    "classify_certificate",
    "classify_cipher",
    "classify_version",
    "profile_tls",
]

#: The client cipher/security string used for the *version* probes: ``ALL`` at security
#: level 0, so a server that only still offers a legacy suite is still probed for the protocol
#: version it runs it over. Without this, "TLS 1.0 is disabled" would be reported for every
#: endpoint on any modern OpenSSL build (which refuses legacy suites by default).
LEGACY_PROBE_CIPHERS = "ALL:@SECLEVEL=0"

#: Protocol versions that are no longer acceptable on a 2026 estate (RFC 8996).
WEAK_PROTOCOLS: dict[str, tuple[str, str]] = {
    "SSLv3": ("CWE-327", "high"),
    "TLSv1.0": ("CWE-327", "medium"),
    "TLSv1.1": ("CWE-327", "medium"),
}

#: Cipher-name fragments that make a suite unacceptable, with the weakness they imply.
WEAK_CIPHER_FRAGMENTS: tuple[tuple[str, str, str], ...] = (
    ("NULL", "CWE-327", "no encryption"),
    ("EXPORT", "CWE-327", "export-grade (deliberately weakened) cipher"),
    ("RC4", "CWE-327", "RC4 is broken (RFC 7465)"),
    ("3DES", "CWE-327", "64-bit block cipher (SWEET32, CVE-2016-2183)"),
    ("DES-CBC", "CWE-327", "single DES"),
    ("_DES_", "CWE-327", "DES-based suite"),
    ("ADH", "CWE-295", "anonymous key exchange (no authentication)"),
    ("AECDH", "CWE-295", "anonymous elliptic-curve key exchange"),
    ("anon", "CWE-295", "anonymous key exchange"),
    ("MD5", "CWE-327", "MD5-based integrity/PRF"),
)

#: Legacy signature algorithms on the certificate itself.
WEAK_SIGNATURES = ("md5", "sha1")

#: Certificate findings, keyed by kind (used by tests and the report layer).
CERTIFICATE_ISSUES: tuple[str, ...] = (
    "expired",
    "not-yet-valid",
    "self-signed",
    "untrusted",
    "hostname-mismatch",
    "weak-key",
    "weak-signature",
    "expiring-soon",
    "no-subject-alternative-name",
)


@dataclass(frozen=True, slots=True)
class TlsIssue:
    """One TLS posture problem, with the evidence needed to explain it."""

    kind: str
    summary: str
    detail: str
    cwe: str | None = None
    severity_hint: str = "low"
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "summary": self.summary,
            "detail": self.detail,
            "cwe": self.cwe,
            "severity_hint": self.severity_hint,
        }


@dataclass(frozen=True, slots=True)
class TlsAssessment:
    """The full result of profiling one TLS endpoint."""

    profile: TlsProfile
    certificate: CertificateInfo | None = None
    issues: tuple[TlsIssue, ...] = ()
    #: Which probes ran, for evidence and probe accounting.
    probes: tuple[str, ...] = ()

    @property
    def supported_versions(self) -> tuple[str, ...]:
        return self.profile.supported_versions

    @property
    def weak_versions(self) -> tuple[str, ...]:
        return tuple(
            item.version
            for item in self.profile.versions
            if item.supported and item.version in WEAK_PROTOCOLS
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.profile.host,
            "port": self.profile.port,
            "supported_versions": list(self.supported_versions),
            "weak_versions": list(self.weak_versions),
            "ciphers": list(self.profile.ciphers),
            "trust_error": self.profile.trust_error,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "issues": [item.to_dict() for item in self.issues],
            "probes": list(self.probes),
            "error": self.profile.error,
        }


def _moment(value: Any) -> str:
    """ISO form of a datetime, or a readable placeholder (evidence must stay JSON-safe)."""
    return value.isoformat() if value is not None else "an unknown date"


def classify_version(version: str) -> TlsIssue | None:
    """A weak protocol version as an issue (``None`` for TLS 1.2+)."""
    if version not in WEAK_PROTOCOLS:
        return None
    cwe, severity = WEAK_PROTOCOLS[version]
    return TlsIssue(
        kind=f"protocol-{version.lower()}",
        summary=f"{version} is enabled",
        detail=(
            f"The endpoint completed a handshake negotiating {version}. RFC 8996 deprecates it; "
            "a client that can be downgraded to it can be attacked with the protocol's known "
            "weaknesses (POODLE for SSLv3, BEAST/weak MACs for TLS 1.0/1.1)."
        ),
        cwe=cwe,
        severity_hint=severity,
        evidence={"version": version},
    )


def classify_cipher(cipher: str) -> TlsIssue | None:
    """A weak cipher suite as an issue (``None`` for an acceptable suite)."""
    upper = cipher.upper()
    for fragment, cwe, reason in WEAK_CIPHER_FRAGMENTS:
        if fragment.upper() in upper:
            return TlsIssue(
                kind=f"cipher-{fragment.lower().strip('_')}",
                summary=f"weak cipher suite accepted: {cipher}",
                detail=f"The endpoint negotiated {cipher}: {reason}.",
                cwe=cwe,
                severity_hint="high" if fragment in {"NULL", "EXPORT", "RC4"} else "medium",
                evidence={"cipher": cipher, "reason": reason},
            )
    return None


def classify_certificate(
    certificate: CertificateInfo,
    *,
    host: str,
    trust_error: str | None,
    now: Any = None,
) -> tuple[TlsIssue, ...]:
    """Turn certificate facts into issues (each independently checkable)."""
    issues: list[TlsIssue] = []
    if certificate.expired(now=now):
        issues.append(
            TlsIssue(
                kind="expired",
                summary=f"certificate for {host} is expired",
                detail=(
                    f"The presented certificate expired on {_moment(certificate.not_after)} "
                    f"(CN={certificate.common_name or 'n/a'}). Clients will warn or refuse."
                ),
                cwe="CWE-298",
                severity_hint="high",
                evidence={
                    "not_after": certificate.not_after.isoformat()
                    if certificate.not_after
                    else None
                },
            )
        )
    elif certificate.not_yet_valid(now=now):
        issues.append(
            TlsIssue(
                kind="not-yet-valid",
                summary=f"certificate for {host} is not valid yet",
                detail="The presented certificate's notBefore is in the future.",
                cwe="CWE-298",
                severity_hint="medium",
                evidence={
                    "not_before": certificate.not_before.isoformat()
                    if certificate.not_before
                    else None
                },
            )
        )
    else:
        days = certificate.days_until_expiry(now=now)
        if days is not None and days <= 30:
            issues.append(
                TlsIssue(
                    kind="expiring-soon",
                    summary=f"certificate for {host} expires in {days} day(s)",
                    detail=(
                        "Renewal is imminent; an expired certificate causes hard client failures."
                    ),
                    cwe="CWE-298",
                    severity_hint="low",
                    evidence={"days_until_expiry": days},
                )
            )
    if certificate.is_self_signed:
        issues.append(
            TlsIssue(
                kind="self-signed",
                summary=f"certificate for {host} is self-signed",
                detail=(
                    f"Issuer and subject are identical (CN={certificate.common_name or 'n/a'}), "
                    "so no trusted CA vouches for the key."
                ),
                cwe="CWE-295",
                severity_hint="medium",
                evidence={"subject": certificate.subject, "issuer": certificate.issuer},
            )
        )
    if trust_error:
        issues.append(
            TlsIssue(
                kind="untrusted",
                summary=f"certificate chain for {host} does not validate",
                detail=f"A verifying handshake failed: {trust_error}",
                cwe="CWE-295",
                severity_hint="medium",
                evidence={"verify_error": trust_error},
            )
        )
    if certificate.hostname_mismatch(host):
        issues.append(
            TlsIssue(
                kind="hostname-mismatch",
                summary=f"certificate does not name {host}",
                detail=(
                    "Neither the common name nor any subjectAltName matches the host that was "
                    f"contacted (CN={certificate.common_name or 'n/a'}, "
                    f"SAN={', '.join(certificate.subject_alt_names[:5]) or 'none'})."
                ),
                cwe="CWE-297",
                severity_hint="medium",
                evidence={"subject_alt_names": list(certificate.subject_alt_names[:10])},
            )
        )
    if certificate.public_key_bits is not None and certificate.public_key_bits < 2048:
        issues.append(
            TlsIssue(
                kind="weak-key",
                summary=f"certificate public key is {certificate.public_key_bits} bits",
                detail="Keys below 2048 bits (RSA) are considered weak by current guidance.",
                cwe="CWE-326",
                severity_hint="medium",
                evidence={"public_key_bits": certificate.public_key_bits},
            )
        )
    signature = (certificate.signature_algorithm or "").lower()
    if any(item in signature for item in WEAK_SIGNATURES):
        issues.append(
            TlsIssue(
                kind="weak-signature",
                summary=f"certificate signed with {certificate.signature_algorithm}",
                detail="MD5/SHA-1 signature algorithms are collision-prone and deprecated.",
                cwe="CWE-327",
                severity_hint="medium",
                evidence={"signature_algorithm": certificate.signature_algorithm},
            )
        )
    if certificate.subject_alt_names == () and not certificate.is_ca:
        issues.append(
            TlsIssue(
                kind="no-subject-alternative-name",
                summary="certificate carries no subjectAltName",
                detail=(
                    "Browsers ignore the common name entirely; a certificate without a SAN is "
                    "rejected by modern clients."
                ),
                cwe="CWE-295",
                severity_hint="medium",
                evidence={"common_name": certificate.common_name},
            )
        )
    return tuple(issues)


async def _probe_versions(
    client: ScopedNetClient,
    *,
    host: str,
    port: int,
    server_name: str | None,
    probes: list[str],
) -> list[TlsVersionProbe]:
    """Which protocol versions the endpoint negotiates, oldest first.

    Two mechanisms, because one is not enough:

    * **TLS 1.2/1.3** are pinned directly (``min = max = version``); the ``ssl`` module
      supports those members without complaint, and a pinned handshake that succeeds is proof
      the version is offered.
    * **TLS 1.0/1.1** are observed through a *cap*: the client stops offering TLS 1.2+, and
      whichever legacy version the server then negotiates is read back from the connection. A
      version below the negotiated one stays **undetermined** (``supported=None``) — a server
      that negotiates TLS 1.1 need not also accept TLS 1.0, and claiming either way would be a
      guess. On interpreters that treat the relevant deprecation warnings as errors (Python
      3.14 under ``PYTHONWARNINGS=error``, which this project's own test suite arranges), the
      cap probe cannot run at all: the check then reports the legacy versions as undetermined
      and says why, instead of inventing a result. Establishing them definitively needs a
      stack that still speaks them — ``ARACHNE_NET_TLS_TOOL`` (testssl.sh/sslscan).
    """
    results: dict[str, bool | None] = dict.fromkeys(TLS_VERSION_ORDER, False)
    for name in PINNABLE_TLS_VERSIONS:
        probe = await client.tls(
            host,
            port,
            min_version=name,
            max_version=name,
            # A modern client refuses legacy cipher suites at its default security level, so a
            # probe that did not lower the level would report "not supported" for a server
            # that only still offers a legacy suite over TLS 1.2.
            ciphers=LEGACY_PROBE_CIPHERS,
            server_hostname=server_name,
        )
        probes.append(name)
        results[name] = probe.ok
    probes.append("legacy-cap")
    try:
        legacy = await client.tls(
            host,
            port,
            ciphers=LEGACY_PROBE_CIPHERS,
            options=legacy_version_cap_options(),
            server_hostname=server_name,
        )
    except DeprecationWarning:
        # The interpreter refuses to cap the protocol version below TLS 1.2 (see the docstring).
        # Reporting "unsupported" here would be a fabricated fact, so every legacy version is
        # left undetermined.
        return [
            TlsVersionProbe(
                version=name,
                supported=results[name] if name not in LEGACY_TLS_VERSIONS else None,
            )
            for name in TLS_VERSION_ORDER
        ]
    negotiated_legacy = legacy.version if legacy.ok else None
    if negotiated_legacy in LEGACY_TLS_VERSIONS:
        results[negotiated_legacy] = True
        for name in LEGACY_TLS_VERSIONS:
            if name != negotiated_legacy:
                results[name] = None  # undetermined, not "unsupported"
    else:
        for name in LEGACY_TLS_VERSIONS:
            results[name] = False
    return [TlsVersionProbe(version=name, supported=results[name]) for name in TLS_VERSION_ORDER]


async def profile_tls(
    client: ScopedNetClient,
    *,
    host: str,
    port: int,
    server_name: str | None = None,
    probe_versions: bool = True,
    probe_ciphers: bool = True,
    cipher_candidates: Sequence[str] | None = None,
    now: Any = None,
) -> TlsAssessment:
    """Profile the TLS endpoint at ``host:port`` (see the module docstring for the steps)."""
    probes: list[str] = []
    negotiated = await client.tls(host, port, server_hostname=server_name)
    probes.append("negotiate")
    if not negotiated.ok:
        # No handshake means no TLS profile: the endpoint either is not TLS or requires a
        # negotiation this client cannot offer. Reporting "no weakness found" here would be a
        # clean bill of health for a port we never spoke to.
        return TlsAssessment(
            profile=TlsProfile(
                host=host,
                port=port,
                error=negotiated.error or "the server refused the TLS handshake",
            ),
            probes=tuple(probes),
        )

    trust_error: str | None = None
    verified = await client.tls(host, port, server_hostname=server_name, verify=True)
    probes.append("verify")
    if not verified.ok:
        trust_error = verified.verify_error or verified.error

    certificate = (
        parse_certificate(negotiated.certificate_der) if negotiated.certificate_der else None
    )

    versions: list[TlsVersionProbe] = []
    if probe_versions:
        versions.extend(
            await _probe_versions(
                client,
                host=host,
                port=port,
                server_name=server_name,
                probes=probes,
            )
        )
    elif negotiated.version:
        versions.append(TlsVersionProbe(version=negotiated.version, supported=True))

    ciphers: list[str] = []
    if probe_ciphers:
        candidates = WEAK_CIPHER_CANDIDATES if cipher_candidates is None else cipher_candidates
        for candidate in candidates:
            if candidate.upper().startswith("TLS_"):
                # TLS 1.3 suites cannot be pinned with set_ciphers; their support is already
                # visible in the TLSv1.3 version probe.
                continue
            probe = await client.tls(host, port, ciphers=candidate, server_hostname=server_name)
            probes.append(f"cipher:{candidate}")
            if probe.ok and probe.cipher:
                ciphers.append(probe.cipher)

    profile = TlsProfile(
        host=host,
        port=port,
        versions=tuple(versions),
        ciphers=tuple(dict.fromkeys(ciphers)),
        trust_error=trust_error,
        negotiated=negotiated,
        error=None,
    )

    issues: list[TlsIssue] = []
    for item in versions:
        if item.supported:
            issue = classify_version(item.version)
            if issue is not None:
                issues.append(issue)
    for cipher in profile.ciphers:
        issue = classify_cipher(cipher)
        if issue is not None:
            issues.append(issue)
    if certificate is not None:
        issues.extend(
            classify_certificate(
                certificate, host=server_name or host, trust_error=trust_error, now=now
            )
        )
    return TlsAssessment(
        profile=profile,
        certificate=certificate,
        issues=tuple(issues),
        probes=tuple(probes),
    )
