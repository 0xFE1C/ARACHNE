"""A fixture mobile artifact, built at test time (S29, REQ-DEPTH-005).

An APK is a zip; an IPA is a zip. Building the fixture in the test rather than committing a
binary keeps the repo free of opaque blobs *and* keeps the planted secret visible in the test
that depends on it: the value lives in :data:`PLANTED_SECRET`, in plain sight, so a reader can
see exactly what the scanner is supposed to find and what it must never echo.

That value is **assembled at runtime** rather than written as one literal, and deliberately so:
a repository containing a credential-shaped string is indistinguishable from a repository that
leaked one — to a secret scanner, to a reviewer, and to ARACHNE's own ``aws-access-key-id``
detector, which guards this repo's CI. The concatenation below produces the same shape at run
time, so the fixture is deterministic and the detector still fires.

The container is shaped like the real thing — an ``AndroidManifest.xml``, a ``classes.dex`` with
printable strings, a ``lib/`` entry, and resource entries that are *not* code — so the check's
"read the code entries, skip the rest" rule is exercised rather than assumed. The planted
material is:

* an access-key-id shape (a detector ARACHNE already knows, so the finding is reported as a
  detector name and the value is masked — never returned);
* two absolute endpoint URLs, which the check records as assets for M1/M3;
* a non-code resource entry carrying the *same* secret-shaped string, which the check is
  expected **not** to report, because resources are not scanned.

The IPA variant carries the same material in a ``.plist`` so both formats have coverage.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

__all__ = [
    "DECOY_ENTRY",
    "PLANTED_ENDPOINTS",
    "PLANTED_SECRET",
    "build_apk",
    "build_ipa",
]

#: The credential shape planted in the code entries. Composed from fragments at import time so
#: no credential-shaped literal exists in this repository (see the module docstring); the
#: assembled value matches ARACHNE's ``aws-access-key-id`` detector and is entirely synthetic.
PLANTED_SECRET: str = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"

#: The endpoint URLs planted in the code entries (recorded as assets for M1/M3).
PLANTED_ENDPOINTS = (
    "https://api.arachne-lab.test/v2/orders",
    "https://cdn.arachne-lab.test/assets/",
)

#: A resource entry that is not code and carries the same kind of value. The check must skip it:
#: a string in a resource blob is not a credential compiled into code, and reporting it would
#: be the false positive that makes a mobile analysis unusable.
DECOY_ENTRY = "res/raw/config.bin"


def _manifest() -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="test.arachne.lab">\n'
        '  <uses-permission android:name="android.permission.INTERNET"/>\n'
        '  <application android:label="ARACHNE Lab">\n'
        f'    <meta-data android:name="api_base" android:value="{PLANTED_ENDPOINTS[0]}"/>\n'
        "  </application>\n"
        "</manifest>\n"
    )


def _dex_strings() -> str:
    """A ``classes.dex``-shaped payload: printable strings, no valid bytecode needed.

    The analysis is a text scan, so what matters is that the entry is named ``*.dex`` and holds
    the strings a compiled app would hold.
    """
    return (
        "dex\n035\x00"
        "test/arachne/lab/ApiClient;"
        f"BASE_URL={PLANTED_ENDPOINTS[0]};CDN={PLANTED_ENDPOINTS[1]};"
        f"ACCESS_KEY={PLANTED_SECRET};"
        "getOrders()/v2/orders/list;"
        "InternalBuildChannel=staging;"
    )


def _plist() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        "  <key>CFBundleIdentifier</key><string>test.arachne.lab</string>\n"
        "  <key>ApiBaseUrl</key>"
        f"<string>{PLANTED_ENDPOINTS[0]}</string>\n"
        "  <key>BuildChannel</key><string>staging</string>\n"
        "</dict></plist>\n"
    )


def _write(path: Path, entries: dict[str, bytes]) -> Path:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    path.write_bytes(buffer.getvalue())
    return path


def build_apk(directory: Path, name: str = "lab-app.apk") -> Path:
    """A fixture APK: manifest + dex (planted secret and endpoints) + a decoy resource."""
    return _write(
        directory / name,
        {
            "AndroidManifest.xml": _manifest().encode(),
            "classes.dex": _dex_strings().encode(),
            "resources.arsc": b"\x02\x00\x0c\x00" + b"res/strings" + b"\x00" * 16,
            DECOY_ENTRY: f"key_hint={PLANTED_SECRET}\n".encode(),
            "res/drawable/icon.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 32,
        },
    )


def build_ipa(directory: Path, name: str = "lab-app.ipa") -> Path:
    """A fixture IPA: a ``.plist`` carrying the same planted material."""
    return _write(
        directory / name,
        {
            "Payload/App.app/Info.plist": _plist().encode(),
            "Payload/App.app/App": _dex_strings().encode(),
            "Payload/App.app/Assets.car": b"\x00" * 64,
        },
    )
