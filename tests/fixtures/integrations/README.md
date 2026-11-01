Recorded integration payloads (S22, REQ-OPS-001/002 contract tests).

Each file is a **receiver-side document**: the shape the receiving system's own
documentation defines for the call ARACHNE makes, recorded here so the contract is
data, not a paraphrase in a test. The contract tests assert ARACHNE's rendered
payloads carry every key these documents carry — a field the receiver expects that we
stop sending is a broken integration the suite catches, not a support ticket.

- `jira-issue.json` — Jira Server/Cloud `POST /rest/api/2/issue` create body.
- `servicenow-incident.json` — ServiceNow Table API `POST /api/now/table/incident` body.
- `defectdojo-import.json` — DefectDojo `POST /api/v2/import-scan/` body (generic
  parser finding schema).
- `siem-events.jsonl` — one record per line, the newline-delimited JSON a SIEM HTTP
  collector (Elastic/Splunk/Chronicle-style endpoint) accepts.
