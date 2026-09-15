-- Default rule set. Applied by hand or via bin/logwarden-migrate once the
-- rule engine ships; kept here so the shipped defaults are reviewable.

INSERT INTO rules (name, rule_class, severity, window_minutes, cooldown_s, params) VALUES
    ('Failed logins burst',
     'LogWarden\Rules\Builtin\FailedLoginBurst',
     4, 10, 900,
     '{"threshold": 5, "window_minutes": 10, "source_types": ["ad", "fortigate_auth", "fortigate_vpn"]}'),

    ('Account lockout',
     'LogWarden\Rules\Builtin\AccountLockout',
     4, 5, 300,
     '{"event_ids": ["4740"]}'),

    ('VPN login followed by AD logon failure',
     'LogWarden\Rules\Builtin\VpnThenAdFail',
     5, 15, 600,
     '{"correlation_minutes": 10, "min_failures": 3}')
ON CONFLICT (name) DO NOTHING;
