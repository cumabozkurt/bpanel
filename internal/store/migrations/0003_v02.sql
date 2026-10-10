-- BPANEL schema v3 (v0.2 integration)
-- handoff-ui H-3: dashboard favorites stored per user (JSON array of tool ids)
ALTER TABLE users ADD COLUMN favorites TEXT NOT NULL DEFAULT '';
-- SEC-8: pma_tokens.password now holds a token-sealed value; drop any
-- plaintext rows left from v0.1 (they expire after 2 minutes anyway).
DELETE FROM pma_tokens;
-- handoff-ui H-1: the activity feed reads the caller's rows by id
CREATE INDEX IF NOT EXISTS audit_actor ON audit_log(actor_id, id);
CREATE INDEX IF NOT EXISTS audit_target ON audit_log(target, id);
