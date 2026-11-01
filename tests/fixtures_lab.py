"""Access to the certificate fixtures the M2 tests validate against.

``tests/fixtures/lab/expired.crt`` is a self-signed certificate generated with OpenSSL whose
validity window is in the past (2020-01-01 → 2021-01-01). It is committed rather than
generated at test time so the TLS assertions are stable and no test depends on an OpenSSL CLI
being present or on its version's ability to backdate a certificate.
"""

from __future__ import annotations

import base64
from pathlib import Path

__all__ = ["CERT_DIR", "expired_certificate_der", "pem_to_der", "valid_certificate_der"]

CERT_DIR = Path(__file__).resolve().parent / "fixtures" / "lab"


def pem_to_der(pem: str) -> bytes:
    """Decode a PEM certificate (or key) body into DER."""
    body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


def expired_certificate_der() -> bytes:
    """The DER of the expired self-signed certificate (CN=weak-lab.local)."""
    return pem_to_der((CERT_DIR / "expired.crt").read_text(encoding="utf-8"))


def valid_certificate_der() -> bytes:
    """The DER of a currently valid, self-signed certificate (CN=strong-lab.local)."""
    return pem_to_der((CERT_DIR / "valid.crt").read_text(encoding="utf-8"))
