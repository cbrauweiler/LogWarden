-- LogWarden 0006 — WinRM collector

BEGIN;

-- ---------------------------------------------------------------------------
-- ingest_sources
-- ---------------------------------------------------------------------------

-- The account the collector binds with. Only the password is a secret and
-- lives in `secrets` behind secret_ref; keeping the username in the clear is
-- what makes "which account stopped working" answerable from the UI.
ALTER TABLE ingest_sources ADD COLUMN username text;

-- 'kerberos' needs a curl with GSSAPI and a keytab, 'ntlm' works everywhere.
ALTER TABLE ingest_sources ADD COLUMN auth_mode text NOT NULL DEFAULT 'ntlm'
    CHECK (auth_mode IN ('ntlm', 'kerberos', 'basic'));

ALTER TABLE ingest_sources ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE ingest_sources ADD COLUMN last_duration_ms integer;

-- Counts *consecutive* failures, reset by the first success. A source that
-- fails once every few hours is a different problem from one that has been
-- down since Tuesday, and only the streak tells them apart.
ALTER TABLE ingest_sources ADD COLUMN consecutive_failures integer NOT NULL DEFAULT 0;

-- One row per host and channel, not per host: Security and the DNS audit
-- channel advance independently, so they need independent bookmarks. The
-- expression index makes that pairing unique without moving the channel out
-- of config.
CREATE UNIQUE INDEX ingest_sources_target_idx
    ON ingest_sources (collector, lower(target_host), (config->>'channel'))
    WHERE target_host IS NOT NULL;

-- The scheduler asks "what is due" on every tick.
CREATE INDEX ingest_sources_due_idx
    ON ingest_sources (last_run_at NULLS FIRST) WHERE enabled;

-- ---------------------------------------------------------------------------
-- ingest_runs
-- ---------------------------------------------------------------------------

-- A run history, for the same reason notification_log exists: "it stopped
-- collecting" is a question about the last few attempts, and the single
-- last_error column on the source only ever remembers one of them.
CREATE TABLE ingest_runs (
    id          bigserial PRIMARY KEY,
    source_id   bigint NOT NULL REFERENCES ingest_sources(id) ON DELETE CASCADE,
    started_at  timestamptz NOT NULL DEFAULT now(),
    duration_ms integer,
    status      text NOT NULL CHECK (status IN ('ok', 'empty', 'partial', 'error')),
    fetched     integer NOT NULL DEFAULT 0,   -- records the collector received
    stored      integer NOT NULL DEFAULT 0,   -- events actually written
    skipped     integer NOT NULL DEFAULT 0,   -- recognised, deliberately dropped
    error       text,
    -- Where the bookmark stood afterwards, so a gap can be reconstructed.
    bookmark    jsonb
);

CREATE INDEX ingest_runs_source_idx ON ingest_runs (source_id, started_at DESC);

COMMIT;
