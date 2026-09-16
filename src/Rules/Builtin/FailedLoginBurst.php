<?php

declare(strict_types=1);

namespace LogWarden\Rules\Builtin;

use LogWarden\Rules\AlertCandidate;
use LogWarden\Rules\RuleContext;
use LogWarden\Rules\RuleInterface;

/**
 * X failed logons for one account within Y minutes, counted across sources.
 *
 * Counting across AD and FortiGate together is the point: three failures at
 * the VPN and three against a domain controller are six attempts on one
 * account, but each source on its own stays under a sensible threshold. That
 * only works because the normalisers reduce CORP\asmith, asmith@corp.local
 * and asmith to the same principal.
 */
final class FailedLoginBurst implements RuleInterface
{
    public static function key(): string
    {
        return 'failed_login_burst';
    }

    public static function title(): string
    {
        return 'Fehlgeschlagene Anmeldungen (Burst)';
    }

    public static function description(): string
    {
        return 'Meldet ein Konto, das im Zeitfenster mindestens `threshold` fehlgeschlagene '
            . 'Anmeldungen ansammelt — quellenübergreifend gezählt.';
    }

    public static function defaultParams(): array
    {
        return [
            'threshold' => 5,
            // source_type => event types that count as a logon failure.
            // An empty list means every failed event of that source counts.
            'sources' => [
                'ad'             => ['4625', '4771', '4776'],
                'fortigate_auth' => [],
                'fortigate_vpn'  => ['ssl-login-fail', 'login-fail', 'auth-logon-failed', 'auth-lockout'],
            ],
            // Service accounts that fail constantly by design would otherwise
            // drown out the accounts that matter.
            'ignore_users' => ['krbtgt'],
        ];
    }

    public function evaluate(RuleContext $context, array $params): array
    {
        $threshold = max(2, (int) ($params['threshold'] ?? 5));
        $sources   = is_array($params['sources'] ?? null) ? $params['sources'] : [];
        $ignore    = is_array($params['ignore_users'] ?? null) ? $params['ignore_users'] : [];

        [$sourceClause, $sourceParams] = self::buildSourceFilter($sources);

        if ($sourceClause === null) {
            return [];   // no source configured, nothing to evaluate
        }

        $rows = $context->db()->fetchAll(
            "WITH failures AS (
                 SELECT username_norm, username, source_type, source_host, src_ip, ts, id
                   FROM events
                  WHERE ts >= ?::timestamptz
                    AND ts <  ?::timestamptz
                    AND result = 'fail'
                    AND username IS NOT NULL
                    AND ({$sourceClause})
             ),
             per_source AS (
                 SELECT username_norm, source_type, count(*) AS c
                   FROM failures GROUP BY 1, 2
             )
             SELECT f.username_norm,
                    min(f.username)                        AS username,
                    count(*)                               AS failures,
                    count(DISTINCT f.source_type)          AS source_count,
                    to_jsonb(array_agg(DISTINCT host(f.src_ip)) FILTER (WHERE f.src_ip IS NOT NULL)) AS src_ips,
                    to_jsonb(array_agg(DISTINCT f.source_host))  AS hosts,
                    to_char(min(f.ts), 'YYYY-MM-DD HH24:MI:SS') AS first_ts,
                    to_char(max(f.ts), 'YYYY-MM-DD HH24:MI:SS') AS last_ts,
                    (SELECT jsonb_object_agg(p.source_type, p.c)
                       FROM per_source p
                      WHERE p.username_norm = f.username_norm)   AS by_source
               FROM failures f
              GROUP BY f.username_norm
             HAVING count(*) >= ?
              ORDER BY count(*) DESC",
            [$context->windowStart(), $context->windowEnd(), ...$sourceParams, $threshold],
        );

        $candidates = [];

        foreach ($rows as $row) {
            $username = (string) $row['username'];

            if (RuleContext::matchesAny($username, $ignore)) {
                continue;
            }

            $failures = (int) $row['failures'];
            $bySource = json_decode((string) $row['by_source'], true) ?: [];
            $srcIps   = json_decode((string) $row['src_ips'], true) ?: [];
            $hosts    = json_decode((string) $row['hosts'], true) ?: [];

            $candidates[] = new AlertCandidate(
                dedupKey:   'failed_login_burst:' . $row['username_norm'],
                title:      "{$failures} fehlgeschlagene Anmeldungen für {$username}",
                summary:    self::summarise($username, $failures, $bySource, $srcIps, (string) $row['first_ts'], (string) $row['last_ts']),
                eventCount: $failures,
                entityUser: $username,
                entityIp:   $srcIps[0] ?? null,
                entityHost: $hosts[0] ?? null,
                evidence: [
                    'failures'     => $failures,
                    'threshold'    => $threshold,
                    'by_source'    => $bySource,
                    'source_ips'   => $srcIps,
                    'target_hosts' => $hosts,
                    'first_seen'   => $row['first_ts'],
                    'last_seen'    => $row['last_ts'],
                    'window'       => $context->windowStart->format('H:i') . '–' . $context->windowEnd->format('H:i'),
                ],
                eventRefs: self::refsFor($context, $username),
                // Several sources at once is a different shape of problem than
                // one person mistyping their password at the VPN.
                severity: (int) $row['source_count'] > 1 ? 5 : null,
            );
        }

        return $candidates;
    }

    /**
     * @param array<string, list<string>> $sources
     * @return array{0: string|null, 1: list<string>}
     */
    private static function buildSourceFilter(array $sources): array
    {
        $clauses = [];
        $params  = [];

        foreach ($sources as $sourceType => $eventTypes) {
            if (!is_string($sourceType) || $sourceType === '') {
                continue;
            }

            if (is_array($eventTypes) && $eventTypes !== []) {
                $clauses[] = '(source_type = ?::source_type_t AND event_type = ANY(?::text[]))';
                $params[]  = $sourceType;
                $params[]  = RuleContext::pgArray(array_map('strval', $eventTypes));
            } else {
                $clauses[] = '(source_type = ?::source_type_t)';
                $params[]  = $sourceType;
            }
        }

        return $clauses === [] ? [null, []] : [implode(' OR ', $clauses), $params];
    }

    /** @return list<array{0:string,1:int}> */
    private static function refsFor(RuleContext $context, string $username): array
    {
        $rows = $context->db()->fetchAll(
            "SELECT to_char(ts, 'YYYY-MM-DD HH24:MI:SS.USOF') AS ts, id
               FROM events
              WHERE ts >= ?::timestamptz AND ts < ?::timestamptz
                AND username_norm = lower(?) AND result = 'fail'
              ORDER BY ts DESC
              LIMIT 50",
            [$context->windowStart(), $context->windowEnd(), $username],
        );

        return array_map(static fn (array $r): array => [(string) $r['ts'], (int) $r['id']], $rows);
    }

    /**
     * @param array<string, int> $bySource
     * @param list<string>       $srcIps
     */
    private static function summarise(
        string $username,
        int $failures,
        array $bySource,
        array $srcIps,
        string $firstTs,
        string $lastTs,
    ): string {
        $parts = [];
        foreach ($bySource as $source => $count) {
            $parts[] = "{$count}× {$source}";
        }

        $summary = "{$failures} fehlgeschlagene Anmeldungen für {$username} zwischen "
            . substr($firstTs, 11, 5) . ' und ' . substr($lastTs, 11, 5)
            . ' (' . implode(', ', $parts) . ').';

        if ($srcIps !== []) {
            $shown = array_slice($srcIps, 0, 5);
            $summary .= ' Quell-IPs: ' . implode(', ', $shown)
                . (count($srcIps) > 5 ? ' und ' . (count($srcIps) - 5) . ' weitere' : '') . '.';
        }

        return $summary;
    }
}
