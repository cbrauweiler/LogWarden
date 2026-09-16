-- LogWarden 0002 — rule engine

BEGIN;

-- ---------------------------------------------------------------------------
-- rules
-- ---------------------------------------------------------------------------

-- Rules are addressed by a short key that the registry resolves to a class.
-- Storing the class name would mean instantiating whatever string happens to
-- be in the database; a key looked up in a discovered allowlist cannot.
ALTER TABLE rules RENAME COLUMN rule_class TO rule_key;

-- Events arrive late: syslog has network delay, a WinRM pull runs on an
-- interval. Evaluating right up to now() would judge windows that are still
-- filling and miss the events that arrive a second later.
ALTER TABLE rules ADD COLUMN lag_seconds integer NOT NULL DEFAULT 60
    CHECK (lag_seconds >= 0);

ALTER TABLE rules ADD COLUMN last_error text;
ALTER TABLE rules ADD COLUMN last_duration_ms integer;

-- ---------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------

ALTER TABLE alerts ADD COLUMN updated_at   timestamptz NOT NULL DEFAULT now();
ALTER TABLE alerts ADD COLUMN last_seen_at timestamptz;
ALTER TABLE alerts ADD COLUMN notified_at  timestamptz;
ALTER TABLE alerts ADD COLUMN notify_count integer NOT NULL DEFAULT 0;

-- The old index keyed on (dedup_key, window_start). Since the evaluation
-- window slides on every run, that never actually caught a repeat: each run
-- produced a new window_start and therefore a new row.
--
-- An open alert is now unique per entity instead. A recurring condition grows
-- the existing alert rather than filling the list with near-identical copies,
-- and a fresh alert is only created once the old one has been acknowledged.
DROP INDEX IF EXISTS alerts_dedup_idx;

CREATE UNIQUE INDEX alerts_open_dedup_idx ON alerts (dedup_key) WHERE status = 'new';
CREATE INDEX alerts_updated_idx ON alerts (updated_at DESC);

-- ---------------------------------------------------------------------------
-- Default rules
-- ---------------------------------------------------------------------------

INSERT INTO rules (name, rule_key, severity, window_minutes, cooldown_s, lag_seconds, params) VALUES
    (
        'Fehlgeschlagene Anmeldungen (Burst)',
        'failed_login_burst',
        4, 10, 900, 60,
        '{
            "threshold": 5,
            "sources": {
                "ad":             ["4625", "4771", "4776"],
                "fortigate_auth": [],
                "fortigate_vpn":  ["ssl-login-fail", "login-fail", "auth-logon-failed", "auth-lockout"]
            },
            "ignore_users": ["krbtgt"]
        }'::jsonb
    ),
    (
        'Account-Lockout',
        'account_lockout',
        4, 15, 300, 60,
        '{
            "event_types": ["4740"],
            "evidence_lookback_minutes": 60
        }'::jsonb
    ),
    (
        'VPN-Login gefolgt von AD-Anmeldefehlern',
        'vpn_then_ad_fail',
        5, 30, 600, 60,
        '{
            "correlation_minutes": 10,
            "min_failures": 3,
            "ad_event_types": ["4625", "4771", "4776"]
        }'::jsonb
    )
ON CONFLICT (name) DO NOTHING;

COMMIT;
