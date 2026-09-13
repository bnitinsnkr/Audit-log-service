Tamper-evident audit log service assignment

See [SCENARIO_B.md](SCENARIO_B.md) for retention, redaction, and export (Scenario B).

Scenario B endpoints:
- `POST /audit/retention/archive` — soft-archive events older than `audit.retention.days` (default 90)
- `POST /audit/events/{sequenceNumber}/redact` — structured payload redaction with an append-only proof event
- `GET /audit/export?actorId=...` or `?resourceId=...` — self-contained, verifiable bulk export
