-- LogWarden 0007 — Quellen als Plugins

BEGIN;

-- ---------------------------------------------------------------------------
-- source_type: Enum -> text
-- ---------------------------------------------------------------------------

-- The enum was the thing standing between LogWarden and a plugin system:
-- adding a vendor meant ALTER TYPE, which means a migration shipped by the
-- plugin, which means a plugin that can run DDL. Making the column text moves
-- the vocabulary into `source_types` below, where a plugin can register itself
-- without touching the schema.
--
-- The cost is one byte per row against four, and losing the database-side
-- check. The check moves into SourceType::of(), which is where the events are
-- built anyway.

ALTER TABLE events            ALTER COLUMN source_type TYPE text USING source_type::text;
ALTER TABLE ingest_sources    ALTER COLUMN source_type TYPE text USING source_type::text;
ALTER TABLE retention_policies ALTER COLUMN source_type TYPE text USING source_type::text;

DROP TYPE IF EXISTS source_type_t;

-- ---------------------------------------------------------------------------
-- source_types
-- ---------------------------------------------------------------------------

-- The persisted mirror of what the code declares. It exists so SQL can join a
-- label and a colour without the application having to decorate every row, and
-- so retention stays configurable per kind. `bin/logwarden-plugins --sync`
-- writes it; the authoritative copy is the one in code.
CREATE TABLE source_types (
    key         text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]{1,30}$'),
    label       text NOT NULL,
    -- NULL for the Windows sources, which are part of LogWarden itself.
    plugin      text,
    color       text,
    description text,
    -- What kind of thing this is, independent of who makes it. Rules select by
    -- role so that installing a second VPN vendor does not mean editing every
    -- rule to name it too.
    role        text NOT NULL DEFAULT 'other'
                CHECK (role IN ('vpn','auth','directory','dns','dhcp','firewall','endpoint','other')),
    keep_days   integer NOT NULL DEFAULT 180 CHECK (keep_days > 0),
    fts_days    integer NOT NULL DEFAULT 14  CHECK (fts_days > 0),
    -- Set when the declaring plugin is no longer installed. The events stay
    -- readable; only new ones are refused.
    orphaned    boolean NOT NULL DEFAULT false,
    synced_at   timestamptz NOT NULL DEFAULT now()
);

INSERT INTO source_types (key, label, plugin, color, description, role, keep_days, fts_days) VALUES
    ('ad',             'Active Directory', NULL,        '--series-1', 'Sicherheitsereignisse der Domain Controller', 'directory', 365, 30),
    ('dns',            'DNS',              NULL,        '--series-2', 'Audit- und Serverereignisse des DNS-Dienstes', 'dns',        21,  7),
    ('dhcp',           'DHCP',             NULL,        '--series-3', 'Lease-Vorgänge aus den DHCP-Audit-Protokollen', 'dhcp',      90, 14),
    ('fortigate_vpn',  'FortiGate VPN',    'fortigate', '--series-4', 'SSL- und IPsec-VPN', 'vpn',                                 180, 30),
    ('fortigate_auth', 'FortiGate Auth',   'fortigate', '--series-5', 'Benutzer-Authentifizierung an der Firewall', 'auth',        180, 30)
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- retention_policies geht in source_types auf
-- ---------------------------------------------------------------------------

-- Two tables keyed by the same thing, one of which the plugin would have to
-- write to as well. Carry over whatever was configured, then drop it.
UPDATE source_types s
   SET keep_days = r.keep_days,
       fts_days  = r.fts_days
  FROM retention_policies r
 WHERE r.source_type = s.key;

DROP TABLE retention_policies;

-- ---------------------------------------------------------------------------
-- Sichtbarkeit: welche Quelltypen tragen überhaupt Daten
-- ---------------------------------------------------------------------------

-- Answers "a plugin was removed — what is left behind?" without scanning the
-- events table, which is the point at which somebody would stop asking.
CREATE INDEX events_sourcetype_idx ON events (source_type, ts DESC);

COMMIT;
