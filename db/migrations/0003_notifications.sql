-- LogWarden 0003 — notification delivery

BEGIN;

-- ---------------------------------------------------------------------------
-- notification_channels
-- ---------------------------------------------------------------------------

-- Health, so a webhook that silently stopped working is visible in the UI
-- rather than only in the log.
ALTER TABLE notification_channels ADD COLUMN last_success_at timestamptz;
ALTER TABLE notification_channels ADD COLUMN last_error      text;
ALTER TABLE notification_channels ADD COLUMN last_error_at   timestamptz;
ALTER TABLE notification_channels ADD COLUMN sent_total      bigint NOT NULL DEFAULT 0;
ALTER TABLE notification_channels ADD COLUMN failed_total    bigint NOT NULL DEFAULT 0;
ALTER TABLE notification_channels ADD COLUMN created_at      timestamptz NOT NULL DEFAULT now();

-- 'workflow' is the Power Automate replacement Microsoft is moving customers
-- to; the payload is the same, the accepted response codes differ.
ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('teams_webhook', 'teams_workflow'));

-- ---------------------------------------------------------------------------
-- notification_log
-- ---------------------------------------------------------------------------

ALTER TABLE notification_log ADD COLUMN duration_ms integer;
ALTER TABLE notification_log ADD COLUMN payload_bytes integer;

-- The dispatcher asks "what happened last for this alert on this channel" on
-- every run, to decide between send, back off and give up.
CREATE INDEX notification_log_pair_idx ON notification_log (alert_id, channel_id, sent_at DESC);

COMMIT;
