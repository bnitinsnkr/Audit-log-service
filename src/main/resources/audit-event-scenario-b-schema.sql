-- Scenario B: adds soft-archive lifecycle metadata to the audit_event table, for a database
-- where audit_event already existed before Scenario B (audit-event-schema.sql, which runs
-- before this script, already includes these columns for a brand-new table, making this a
-- no-op there). Idempotent (safe to run on every startup); never creates, drops, or recreates
-- the table itself.
ALTER TABLE audit_event ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE audit_event ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP WITH TIME ZONE;
