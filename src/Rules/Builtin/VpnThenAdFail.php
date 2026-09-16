<?php

declare(strict_types=1);

namespace LogWarden\Rules\Builtin;

use LogWarden\Rules\AlertCandidate;
use LogWarden\Rules\RuleContext;
use LogWarden\Rules\RuleInterface;

/**
 * A successful VPN login followed shortly by failed domain logons for the
 * same account.
 *
 * The shape this looks for: someone gets onto the network with credentials
 * that work at the perimeter, then starts failing against Active Directory.
 * That is what stolen VPN credentials plus guesswork looks like from the
 * inside — and neither half raises an eyebrow on its own. A successful VPN
 * login is the most ordinary event in the estate, and a handful of AD
 * failures is a Monday morning.
 *
 * Correspondingly noisy in the other direction: a user whose laptop holds a
 * stale cached password does exactly this every time they connect. Run it,
 * then tune `min_failures` to your environment.
 */
final class VpnThenAdFail implements RuleInterface
{
    public static function key(): string
    {
        return 'vpn_then_ad_fail';
    }

    public static function title(): string
    {
        return 'VPN-Login gefolgt von AD-Anmeldefehlern';
    }

    public static function description(): string
    {
        return 'Korreliert einen erfolgreichen VPN-Login mit anschließenden fehlgeschlagenen '
            . 'AD-Anmeldungen desselben Kontos innerhalb von `correlation_minutes`.';
    }

    public static function defaultParams(): array
    {
        return [
            'correlation_minutes' => 10,
            'min_failures'        => 3,
            'ad_event_types'      => ['4625', '4771', '4776'],
            'ignore_users'        => [],
        ];
    }

    public function evaluate(RuleContext $context, array $params): array
    {
        $correlation = max(1, min(240, (int) ($params['correlation_minutes'] ?? 10)));
        $minFailures = max(1, (int) ($params['min_failures'] ?? 3));
        $adTypes     = is_array($params['ad_event_types'] ?? null) ? $params['ad_event_types'] : [];
        $ignore      = is_array($params['ignore_users'] ?? null) ? $params['ignore_users'] : [];

        $adFilter = $adTypes === [] ? '' : ' AND f.event_type = ANY(?::text[])';
        $adParams = $adTypes === [] ? [] : [RuleContext::pgArray(array_map('strval', $adTypes))];

        $rows = $context->db()->fetchAll(
            "SELECT v.username,
                    v.username_norm,
                    to_char(v.ts, 'YYYY-MM-DD HH24:MI:SS.USOF') AS vpn_ts_iso,
                    to_char(v.ts, 'YYYY-MM-DD HH24:MI:SS')      AS vpn_ts_label,
                    extract(epoch FROM v.ts)::bigint            AS vpn_epoch,
                    v.id                                        AS vpn_id,
                    host(v.src_ip)                              AS vpn_src_ip,
                    v.source_host                               AS vpn_gateway,
                    count(f.*)                                  AS failures,
                    to_jsonb(array_agg(DISTINCT f.source_host))  AS target_hosts,
                    to_jsonb(array_agg(DISTINCT f.event_type))   AS event_types,
                    to_char(min(f.ts), 'YYYY-MM-DD HH24:MI:SS')  AS first_fail,
                    to_char(max(f.ts), 'YYYY-MM-DD HH24:MI:SS')  AS last_fail
               FROM events v
               JOIN events f
                 ON f.username_norm = v.username_norm
                -- By role, not by name. A second directory or a second VPN
                -- vendor joins this rule by being installed, rather than by
                -- somebody remembering to add it here.
                AND f.source_type   IN (SELECT key FROM source_types WHERE role = 'directory')
                AND f.result        = 'fail'
                AND f.ts >  v.ts
                AND f.ts <= v.ts + make_interval(mins => ?)
                AND f.ts <  ?::timestamptz
                {$adFilter}
              WHERE v.ts >= ?::timestamptz
                AND v.ts <  ?::timestamptz
                AND v.source_type IN (SELECT key FROM source_types WHERE role = 'vpn')
                AND v.result      = 'success'
                AND v.username IS NOT NULL
              GROUP BY v.username, v.username_norm, v.ts, v.id, v.src_ip, v.source_host
             HAVING count(f.*) >= ?
              ORDER BY v.ts DESC",
            [
                $correlation,
                $context->windowEnd(),
                ...$adParams,
                $context->windowStart(),
                $context->windowEnd(),
                $minFailures,
            ],
        );

        $candidates = [];

        foreach ($rows as $row) {
            $username = (string) $row['username'];

            if (RuleContext::matchesAny($username, $ignore)) {
                continue;
            }

            $failures = (int) $row['failures'];
            $hosts    = json_decode((string) $row['target_hosts'], true) ?: [];
            $types    = json_decode((string) $row['event_types'], true) ?: [];

            $candidates[] = new AlertCandidate(
                // Keyed on the VPN session, not just the account: a second
                // login later the same day is a separate incident.
                dedupKey:   'vpn_then_ad_fail:' . $row['username_norm'] . ':' . $row['vpn_epoch'],
                title:      "VPN-Login von {$username}, danach {$failures} AD-Anmeldefehler",
                summary:    sprintf(
                    '%s hat sich um %s Uhr erfolgreich per VPN von %s angemeldet (%s) und '
                    . 'anschließend zwischen %s und %s %d fehlgeschlagene AD-Anmeldungen erzeugt (%s).',
                    $username,
                    substr((string) $row['vpn_ts_label'], 11, 5),
                    $row['vpn_src_ip'] ?? 'unbekannter IP',
                    $row['vpn_gateway'],
                    substr((string) $row['first_fail'], 11, 5),
                    substr((string) $row['last_fail'], 11, 5),
                    $failures,
                    implode(', ', array_filter($hosts)) ?: 'Ziel unbekannt',
                ),
                eventCount: $failures + 1,
                entityUser: $username,
                entityIp:   $row['vpn_src_ip'],
                entityHost: $hosts[0] ?? (string) $row['vpn_gateway'],
                evidence: [
                    'vpn_login_at'        => $row['vpn_ts_label'],
                    'vpn_source_ip'       => $row['vpn_src_ip'],
                    'vpn_gateway'         => $row['vpn_gateway'],
                    'correlation_minutes' => $correlation,
                    'ad_failures'         => $failures,
                    'ad_event_types'      => array_values(array_filter($types)),
                    'target_hosts'        => array_values(array_filter($hosts)),
                    'first_seen'          => $row['first_fail'],
                    'last_failure'        => $row['last_fail'],
                ],
                eventRefs: array_merge(
                    [[(string) $row['vpn_ts_iso'], (int) $row['vpn_id']]],
                    $this->failureRefs($context, $username, (string) $row['vpn_ts_iso'], $correlation),
                ),
            );
        }

        return $candidates;
    }

    /** @return list<array{0:string,1:int}> */
    private function failureRefs(RuleContext $context, string $username, string $vpnTs, int $correlation): array
    {
        $rows = $context->db()->fetchAll(
            "SELECT to_char(ts, 'YYYY-MM-DD HH24:MI:SS.USOF') AS ts, id
               FROM events
              WHERE ts >  ?::timestamptz
                AND ts <= ?::timestamptz + make_interval(mins => ?)
                AND ts <  ?::timestamptz
                AND username_norm = lower(?)
                AND source_type IN (SELECT key FROM source_types WHERE role = 'directory')
                AND result = 'fail'
              ORDER BY ts
              LIMIT 50",
            [$vpnTs, $vpnTs, $correlation, $context->windowEnd(), $username],
        );

        return array_map(static fn (array $r): array => [(string) $r['ts'], (int) $r['id']], $rows);
    }
}
