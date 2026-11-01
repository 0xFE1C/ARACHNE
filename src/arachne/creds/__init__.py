"""Credentialed scanning: the broker, the login/session flow, and nothing else (S19, CREDS).

``core.vault`` holds the encrypted store and the opaque handle; this package is the only
code that reads a handle's material. A check asks :class:`~arachne.creds.broker.CredentialBroker`
for an outcome (an authenticated :class:`~arachne.creds.session.WebSession`, or a
:class:`~arachne.creds.broker.ProtocolAuthResult`) and never receives a value.
"""

from __future__ import annotations

from arachne.creds.broker import (
    PROTOCOL_KINDS,
    Authenticator,
    CredentialBroker,
    ProtocolAuthResult,
)
from arachne.creds.session import LoginSpec, LogoutOutcome, WebAuthOutcome, WebSession

__all__ = [
    "PROTOCOL_KINDS",
    "Authenticator",
    "CredentialBroker",
    "LoginSpec",
    "LogoutOutcome",
    "ProtocolAuthResult",
    "WebAuthOutcome",
    "WebSession",
]
