"""Generate and verify the committed coverage ledger (REQ-DET-001).

``arachne coverage ledger`` is the operator command; this module is the CI-facing form of the
same generator, mirroring :mod:`arachne.tools.report_schema` and :mod:`arachne.tools.counts`:

    python -m arachne.tools.ledger --check    # exit 1 (naming the check id) if the ledger drifts
    python -m arachne.tools.ledger --write    # regenerate .spec/ledgers/coverage-ledger.{json,md}
    python -m arachne.tools.ledger            # print the JSON ledger to stdout

The ledger is a pure function of ``ModuleRegistry`` plus one committed date, so ``--check``
compares bytes and a stale ledger fails with the ids that moved — never with "the file
changed".
"""

from __future__ import annotations

import sys
from pathlib import Path

from arachne.modules.coverage import (
    build_ledger,
    check_ledger,
    default_ledger_paths,
    render_ledger_json,
    render_ledger_markdown,
)

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    check = "--check" in args
    write = "--write" in args
    date = _option(args, "--generated-at")

    json_path, markdown_path = default_ledger_paths()
    if check:
        ok, differences = check_ledger(json_path, markdown_path)
        if not ok:
            for difference in differences:
                sys.stderr.write(f"error: {difference}\n")
            sys.stderr.write(
                "error: the coverage ledger is stale; run "
                "`python -m arachne.tools.ledger --write`\n"
            )
            return 1
        sys.stdout.write(f"{json_path.name} and {markdown_path.name} are up to date\n")
        return 0

    ledger = build_ledger(generated_at=date)
    if write:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(render_ledger_json(ledger), encoding="utf-8")
        markdown_path.write_text(render_ledger_markdown(ledger), encoding="utf-8")
        sys.stdout.write(f"wrote {json_path} and {markdown_path}\n")
        return 0

    sys.stdout.write(render_ledger_json(ledger))
    return 0


def _option(args: list[str], name: str) -> str | None:
    """``--generated-at VALUE`` or ``--generated-at=VALUE``; ``None`` when absent."""
    for index, arg in enumerate(args):
        if arg == name and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(f"{name}="):
            return arg.split("=", 1)[1]
    return None


def _paths(root: Path | None = None) -> tuple[Path, Path]:  # pragma: no cover - convenience
    return default_ledger_paths(root)


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
