#!/bin/sh
# End-to-end demo scan for `docker compose up` (F-07-04).
#
# Runs the real orchestrator in heuristic mode against the bundled offline target: the
# target's own responses and every third-party OSINT answer come from recordings mounted at
# /app/demo, so this works on a host with no outbound network . Then it
# renders the Markdown and HTML reports to the `reports` volume.
#
# The scan id is read from `arachne scan --json` (stdout is JSON; logs go to stderr).
set -eu

TARGET="${ARACHNE_DEMO_TARGET:-/app/demo/target.yaml}"
REPORT_DIR="${ARACHNE_DEMO_REPORT_DIR:-/reports}"

echo "== ARACHNE demo scan =="
echo "target:     $TARGET"
echo "database:   ${ARACHNE_DATABASE_URL:-<default>}"
echo "http replay: ${ARACHNE_HTTP_FIXTURES:-<none>}"
echo

result=$(arachne scan --target "$TARGET" --json)
scan_id=$(printf '%s' "$result" | python -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')

mkdir -p "$REPORT_DIR"
printf '%s\n' "$result" > "$REPORT_DIR/scan-$scan_id.json"

arachne report --scan "$scan_id" --format md --output "$REPORT_DIR/demo-report.md"
arachne report --scan "$scan_id" --format html --output "$REPORT_DIR/demo-report.html"

echo
echo "scan $scan_id complete"
echo "  report: $REPORT_DIR/demo-report.md"
echo "  report: $REPORT_DIR/demo-report.html"
echo "  scan json: $REPORT_DIR/scan-$scan_id.json"