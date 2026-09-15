-- LogWarden 0001 — initial schema
--
-- Target: PostgreSQL 16+
-- Time zone: the database is expected to run with timezone = 'UTC'.

BEGIN;

-- ---------------------------------------------------------------------------
-- Extensions and enum types
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- substring search on user/host names

CREATE TYPE source_type_t  AS ENUM ('ad', 'dns', 'dhcp', 'fortigate_vpn', 'fortigate_auth');
CREATE TYPE event_result_t AS ENUM ('success', 'fail', 'info');
CREATE TYPE user_role_t    AS ENUM ('admin', 'analyst', 'readonly');
CREATE TYPE alert_status_t AS ENUM ('new', 'ack', 'closed');

-- ---------------------------------------------------------------------------
-- Corporate identity / branding
--
-- Singleton row. Only brand chrome is configurable: the severity ramp stays
-- fixed in the design system because those colours carry meaning, and a badly
-- chosen "critical" colour is a safety problem, not a taste problem.
-- ---------------------------------------------------------------------------

CREATE TABLE branding (
    id                smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    product_name      text NOT NULL DEFAULT 'LogWarden',
    org_name          text,
    login_subtitle    text,
    footer_text       text,

    -- Base tokens. Every other shade is derived in CSS via color-mix(), so
    -- three colours are enough to re-skin the whole application.
    color_primary     text NOT NULL DEFAULT '#3d63dd'
                      CHECK (color_primary ~* '^#[0-9a-f]{6}$'),
    color_accent      text NOT NULL DEFAULT '#0d9488'
                      CHECK (color_accent  ~* '^#[0-9a-f]{6}$'),
    color_sidebar     text NOT NULL DEFAULT '#0f172a'
                      CHECK (color_sidebar ~* '^#[0-9a-f]{6}$'),

    font_stack        text NOT NULL DEFAULT 'system',   -- key into a server-side allowlist
    radius_scale      text NOT NULL DEFAULT 'medium'
                      CHECK (radius_scale IN ('sharp', 'medium', 'round')),
    density           text NOT NULL DEFAULT 'comfortable'
                      CHECK (density IN ('compact', 'comfortable')),
    default_theme     text NOT NULL DEFAULT 'auto'
                      CHECK (default_theme IN ('auto', 'light', 'dark')),
    allow_user_theme  boolean NOT NULL DEFAULT true,

    -- Bumped on every change; used as the cache-busting query string on
    -- /assets/theme.css and the logo routes.
    revision          integer NOT NULL DEFAULT 1,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    updated_by        text
);

INSERT INTO branding (id) VALUES (1);

-- Binary assets live in the database so that a multi-node deployment has one
-- source of truth and no file sync between web nodes.
CREATE TABLE branding_assets (
    slot        text PRIMARY KEY
                CHECK (slot IN ('logo_light', 'logo_dark', 'logo_mark', 'favicon')),
    mime_type   text   NOT NULL,
    byte_size   integer NOT NULL,
    checksum    text   NOT NULL,          -- sha256 hex, used as the HTTP ETag
    data        bytea  NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Users, roles, sessions
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL UNIQUE,            -- sAMAccountName, lowercased
    display_name  text,
    email         text,
    auth_provider text NOT NULL DEFAULT 'ldap' CHECK (auth_provider IN ('ldap', 'local')),
    password_hash text,                            -- only for auth_provider = 'local'
    role          user_role_t NOT NULL DEFAULT 'readonly',
    role_source   text NOT NULL DEFAULT 'ldap_group'
                  CHECK (role_source IN ('ldap_group', 'manual')),
    enabled       boolean NOT NULL DEFAULT true,
    last_login_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_local_needs_hash
        CHECK (auth_provider <> 'local' OR password_hash IS NOT NULL)
);

CREATE TABLE ldap_role_map (
    id       bigserial PRIMARY KEY,
    group_dn text NOT NULL UNIQUE,
    role     user_role_t NOT NULL,
    priority smallint NOT NULL DEFAULT 100   -- highest wins on multiple membership
);

CREATE TABLE sessions (
    id         text PRIMARY KEY,                   -- sha256 of the cookie value
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ip         inet,
    user_agent text
);
CREATE INDEX sessions_user_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE audit_log (
    id       bigserial PRIMARY KEY,
    ts       timestamptz NOT NULL DEFAULT now(),
    user_id  bigint REFERENCES users(id) ON DELETE SET NULL,
    username text NOT NULL,                        -- denormalised: outlives the user row
    action   text NOT NULL,                        -- 'rule.update', 'alert.ack', 'branding.update'
    target   text,
    details  jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip       inet
);
CREATE INDEX audit_log_ts_idx     ON audit_log (ts DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, ts DESC);

-- ---------------------------------------------------------------------------
-- Secrets and ingestion sources
-- ---------------------------------------------------------------------------

CREATE TABLE secrets (
    id          bigserial PRIMARY KEY,
    ref_name    text NOT NULL UNIQUE,              -- 'winrm.dc01', 'teams.soc'
    ciphertext  bytea NOT NULL,                    -- libsodium crypto_secretbox
    nonce       bytea NOT NULL,
    key_version smallint NOT NULL DEFAULT 1,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ingest_sources (
    id              bigserial PRIMARY KEY,
    name            text NOT NULL UNIQUE,
    collector       text NOT NULL CHECK (collector IN ('syslog', 'winrm', 'dhcp_csv')),
    source_type     source_type_t NOT NULL,
    target_host     text,                          -- FQDN, IP or UNC path
    enabled         boolean NOT NULL DEFAULT true,
    config          jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_ref      text REFERENCES secrets(ref_name) ON DELETE SET NULL,
    poll_interval_s integer NOT NULL DEFAULT 60,
    bookmark        jsonb,                         -- EventRecordID / file offset
    last_success_at timestamptz,
    last_run_at     timestamptz,
    last_error      text,
    last_error_at   timestamptz,
    events_total    bigint NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Events — the hot table, range-partitioned by day on ts
-- ---------------------------------------------------------------------------

CREATE TABLE events (
    id            bigint GENERATED ALWAYS AS IDENTITY,
    ts            timestamptz    NOT NULL,         -- event time reported by the source
    ingested_at   timestamptz    NOT NULL DEFAULT now(),
    source_type   source_type_t  NOT NULL,
    source_host   text           NOT NULL,
    event_type    text           NOT NULL,         -- '4625', 'vpn-tunnel-up', 'DHCP-ACK'
    username      text,
    username_norm text GENERATED ALWAYS AS (lower(username)) STORED,
    src_ip        inet,
    dst_ip        inet,
    result        event_result_t,
    raw_message   text           NOT NULL,
    details       jsonb          NOT NULL DEFAULT '{}'::jsonb,
    dedup_key     text           NOT NULL,
    search_tsv    tsvector GENERATED ALWAYS AS (to_tsvector('simple', raw_message)) STORED,
    PRIMARY KEY (ts, id),
    UNIQUE (ts, dedup_key)
) PARTITION BY RANGE (ts);

-- Catch-all so a missed maintenance run never rejects an insert. The partition
-- helper below migrates rows out of it when the real partition is created.
CREATE TABLE events_default PARTITION OF events DEFAULT;

CREATE INDEX events_user_ts_idx   ON events (username_norm, ts DESC) WHERE username IS NOT NULL;
CREATE INDEX events_srcip_ts_idx  ON events (src_ip, ts DESC)        WHERE src_ip IS NOT NULL;
CREATE INDEX events_type_ts_idx   ON events (source_type, event_type, ts DESC);
CREATE INDEX events_host_ts_idx   ON events (source_host, ts DESC);
CREATE INDEX events_fail_ts_idx   ON events (ts DESC)                WHERE result = 'fail';
CREATE INDEX events_details_idx   ON events USING gin (details jsonb_path_ops);

-- Note: no global GIN index on search_tsv. bin/logwarden-maintenance creates
-- one per partition for the most recent N days only (see retention_policies),
-- because that index costs roughly 30-40% on top of the table.

-- ---------------------------------------------------------------------------
-- Partition management
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION lw_create_event_partition(p_day date)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    v_name    text := 'events_' || to_char(p_day, 'YYYYMMDD');
    v_from    timestamptz := p_day::timestamptz;
    v_to      timestamptz := (p_day + 1)::timestamptz;
    v_orphans bigint;
BEGIN
    IF to_regclass('public.' || v_name) IS NOT NULL THEN
        RETURN v_name || ' (exists)';
    END IF;

    -- A row already parked in the default partition would make ATTACH fail, so
    -- move any out of the way first. This only happens after a missed run.
    EXECUTE format('SELECT count(*) FROM events_default WHERE ts >= %L AND ts < %L', v_from, v_to)
        INTO v_orphans;

    IF v_orphans > 0 THEN
        LOCK TABLE events_default IN ACCESS EXCLUSIVE MODE;
        CREATE TEMP TABLE lw_orphans ON COMMIT DROP AS
            SELECT * FROM events_default WHERE false;
        EXECUTE format(
            'WITH moved AS (DELETE FROM events_default WHERE ts >= %L AND ts < %L RETURNING *)
             INSERT INTO lw_orphans SELECT * FROM moved', v_from, v_to);
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
        v_name, v_from, v_to);

    IF v_orphans > 0 THEN
        -- OVERRIDING SYSTEM VALUE keeps the original id, so any alert_events
        -- row already pointing at a recovered event stays valid.
        EXECUTE format(
            'INSERT INTO %I (id, ts, ingested_at, source_type, source_host, event_type,
                             username, src_ip, dst_ip, result, raw_message, details, dedup_key)
             OVERRIDING SYSTEM VALUE
             SELECT id, ts, ingested_at, source_type, source_host, event_type,
                    username, src_ip, dst_ip, result, raw_message, details, dedup_key
             FROM lw_orphans', v_name);
        DROP TABLE lw_orphans;
    END IF;

    RETURN v_name || ' (created, ' || v_orphans || ' rows recovered from default)';
END;
$$;

CREATE OR REPLACE FUNCTION lw_drop_event_partition(p_day date)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    v_name text := 'events_' || to_char(p_day, 'YYYYMMDD');
BEGIN
    IF to_regclass('public.' || v_name) IS NULL THEN
        RETURN v_name || ' (absent)';
    END IF;
    EXECUTE format('DROP TABLE %I', v_name);
    RETURN v_name || ' (dropped)';
END;
$$;

CREATE TABLE retention_policies (
    source_type source_type_t PRIMARY KEY,
    keep_days   integer NOT NULL CHECK (keep_days > 0),
    fts_days    integer NOT NULL DEFAULT 14 CHECK (fts_days > 0)
);

INSERT INTO retention_policies (source_type, keep_days, fts_days) VALUES
    ('ad',              365, 30),
    ('dns',              21,  7),
    ('dhcp',             90, 14),
    ('fortigate_vpn',   180, 30),
    ('fortigate_auth',  180, 30);

-- ---------------------------------------------------------------------------
-- Rule engine
-- ---------------------------------------------------------------------------

CREATE TABLE rules (
    id             bigserial PRIMARY KEY,
    name           text NOT NULL UNIQUE,
    rule_class     text NOT NULL,                  -- FQCN implementing RuleInterface
    enabled        boolean NOT NULL DEFAULT true,
    severity       smallint NOT NULL DEFAULT 3 CHECK (severity BETWEEN 1 AND 5),
    params         jsonb NOT NULL DEFAULT '{}'::jsonb,
    window_minutes integer NOT NULL DEFAULT 15 CHECK (window_minutes > 0),
    cooldown_s     integer NOT NULL DEFAULT 900 CHECK (cooldown_s >= 0),
    last_run_at    timestamptz,
    last_cursor_ts timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id           bigserial PRIMARY KEY,
    rule_id      bigint NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    triggered_at timestamptz NOT NULL DEFAULT now(),
    window_start timestamptz NOT NULL,
    window_end   timestamptz NOT NULL,
    severity     smallint NOT NULL CHECK (severity BETWEEN 1 AND 5),
    status       alert_status_t NOT NULL DEFAULT 'new',
    dedup_key    text NOT NULL,
    title        text NOT NULL,
    summary      text NOT NULL,
    entity_user  text,
    entity_ip    inet,
    entity_host  text,
    event_count  integer NOT NULL DEFAULT 0,
    -- Snapshot of the triggering evidence. Deliberately self-contained so an
    -- alert stays readable after its source events are aged out.
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    ack_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    ack_at       timestamptz,
    ack_note     text
);
CREATE INDEX alerts_status_idx ON alerts (status, triggered_at DESC);
CREATE INDEX alerts_user_idx   ON alerts (entity_user, triggered_at DESC);
CREATE INDEX alerts_rule_idx   ON alerts (rule_id, triggered_at DESC);
CREATE UNIQUE INDEX alerts_dedup_idx ON alerts (dedup_key, window_start);

-- Pointers to the triggering events. No foreign key on purpose: an FK into a
-- partitioned table blocks DROP of aged-out partitions.
CREATE TABLE alert_events (
    alert_id bigint      NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_ts timestamptz NOT NULL,
    event_id bigint      NOT NULL,
    PRIMARY KEY (alert_id, event_ts, event_id)
);

-- ---------------------------------------------------------------------------
-- Notification
-- ---------------------------------------------------------------------------

CREATE TABLE notification_channels (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL UNIQUE,
    type         text NOT NULL DEFAULT 'teams_webhook' CHECK (type IN ('teams_webhook')),
    secret_ref   text REFERENCES secrets(ref_name) ON DELETE SET NULL,
    enabled      boolean NOT NULL DEFAULT true,
    min_severity smallint NOT NULL DEFAULT 1 CHECK (min_severity BETWEEN 1 AND 5),
    config       jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE rule_channels (
    rule_id    bigint NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    channel_id bigint NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, channel_id)
);

CREATE TABLE notification_log (
    id          bigserial PRIMARY KEY,
    alert_id    bigint NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    channel_id  bigint NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    attempt     smallint NOT NULL DEFAULT 1,
    sent_at     timestamptz NOT NULL DEFAULT now(),
    http_status integer,
    error       text,
    delivered   boolean NOT NULL DEFAULT false
);
CREATE INDEX notification_log_alert_idx ON notification_log (alert_id);
CREATE INDEX notification_log_retry_idx ON notification_log (delivered, sent_at) WHERE NOT delivered;

-- ---------------------------------------------------------------------------
-- Saved searches
-- ---------------------------------------------------------------------------

CREATE TABLE saved_searches (
    id      bigserial PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name    text NOT NULL,
    query   jsonb NOT NULL,
    shared  boolean NOT NULL DEFAULT false,
    UNIQUE (user_id, name)
);

COMMIT;
