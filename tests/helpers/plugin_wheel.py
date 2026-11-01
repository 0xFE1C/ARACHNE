"""Build a dependency-free wheel from a plugin example (S14 test helper).

Why not ``pip wheel``/``pip install <dir>``? Both need a PEP 517 build backend, and a CI
image (or an air-gapped operator) may not have ``hatchling`` available. A wheel is just a
zip with a ``.dist-info`` directory, and the property this test must prove — that ARACHNE
discovers a third-party plugin through its entry point *without a core change* — is a
property of the installed distribution metadata, not of the build backend. Building the
wheel by hand keeps the proof offline and deterministic.

The generated wheel is a real, pip-installable artefact:
``pip install --no-deps --target <dir> <wheel>`` unpacks it and ``importlib.metadata``
finds the entry points exactly as it would for a published package.
"""

from __future__ import annotations

import zipfile
from collections.abc import Mapping
from pathlib import Path

__all__ = ["build_wheel"]


def _dist_info_name(name: str, version: str) -> str:
    return f"{name.replace('-', '_')}-{version}.dist-info"


def build_wheel(
    destination: Path,
    *,
    name: str,
    version: str,
    package_dir: Path,
    entry_points: Mapping[str, Mapping[str, str]],
    summary: str = "ARACHNE plugin (test wheel)",
) -> Path:
    """Write a pure-Python wheel for ``package_dir`` into ``destination``.

    ``package_dir`` is the importable package (its name is the directory name). Entry points
    are given as ``{group: {name: "module:attr"}}``.
    """
    destination.mkdir(parents=True, exist_ok=True)
    module_name = package_dir.name
    wheel_name = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    wheel_path = destination / wheel_name
    dist_info = _dist_info_name(name, version)

    metadata = (
        "Metadata-Version: 2.1\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        f"Summary: {summary}\n"
        "Requires-Python: >=3.11\n"
        "\n"
    )
    wheel_meta = (
        "Wheel-Version: 1.0\n"
        "Generator: arachne-test-helper\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    )
    entry_point_lines: list[str] = []
    for group, entries in entry_points.items():
        entry_point_lines.append(f"[{group}]")
        entry_point_lines.extend(f"{key} = {value}" for key, value in entries.items())
        entry_point_lines.append("")
    entry_points_text = "\n".join(entry_point_lines)

    files: list[tuple[str, bytes]] = []
    for path in sorted(package_dir.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            arcname = f"{module_name}/{path.relative_to(package_dir).as_posix()}"
            files.append((arcname, path.read_bytes()))
    files.append((f"{dist_info}/METADATA", metadata.encode("utf-8")))
    files.append((f"{dist_info}/WHEEL", wheel_meta.encode("utf-8")))
    files.append((f"{dist_info}/entry_points.txt", entry_points_text.encode("utf-8")))

    record_lines = [f"{arcname},," for arcname, _ in files]
    record_lines.append(f"{dist_info}/RECORD,,")
    files.append((f"{dist_info}/RECORD", ("\n".join(record_lines) + "\n").encode("utf-8")))

    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for arcname, payload in files:
            archive.writestr(arcname, payload)
    return wheel_path
