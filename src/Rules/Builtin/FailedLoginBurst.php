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

            // Which kinds of source count as a logon attempt. Stated as roles
            // so that a newly installed vendor takes part without this rule
            // having to learn its name.
            'roles' => ['directory', 'auth', 'vpn'],

            // Optional narrowing per source type: without an entry, every
            // failed event of a matching role counts. Active Directory needs
            // one because its channel also carries failures that are not logon
            // attempts.
            'event_types' => [
                'ad' => ['4625', '4771', '4776'],
            ],
            // Service accounts that fail constantly by design would otherwise
            // drown out the accounts that matter.
            'ignore_users' => ['krbtgt'],
        ];
    }

    public function evaluate(RuleContext $context, array $params): array
    {
        $threshold  = max(2, (int) ($params['threshold'] ?? 5));
        $roles      = is_array($params['roles'] ?? null) ? $params['roles'] : [];
        $eventTypes = is_array($params['event_types'] ?? null) ? $params['event_types'] : [];
        $ignore     = is_array($params['ignore_users'] ?? null) ? $params['ignore_users'] : [];

        // Rules stored before the move to roles still carry a `sources` map of
        // source_type => event types. Read it rather than falling silent: a
        // rule that quietly stops matching is worse than one that refuses.
        if ($roles === [] && is_array($params['sources'] ?? null)) {
            $eventTypes = $params['sources'] + $eventTypes;
            $roles      = ['directory', 'auth', 'vpn'];
        }

        [$sourceClause, $sourceParams] = self::buildSourceFilter($roles, $eventTypes);

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
     * @param list<string>                $roles
     * @param array<string, list<string>> $eventTypes
     * @return array{0: string|null, 1: list<string>}
     */
    private static function buildSourceFilter(array $roles, array $eventTypes): array
    {
        $roles = array_values(array_filter($roles, static fn (mixed $r): bool => is_string($r) && $r !== ''));

        if ($roles === []) {
            return [null, []];
        }

        // Source types that carry their own event-type filter are taken out of
        // the broad role clause and added back individually. Listing 'ad' then
        // narrows Active Directory without also switching off any other
        // directory that happens to be installed.
        $narrowed = [];

        foreach ($eventTypes as $sourceType => $types) {
            if (is_string($sourceType) && $sourceType !== '' && is_array($types) && $types !== []) {
                $narrowed[$sourceType] = array_map('strval', $types);
            }
        }

        $clause = 'source_type IN (SELECT key FROM source_types WHERE role = ANY(?::text[])';
        $params = [RuleContext::pgArray($roles)];

        if ($narrowed !== []) {
            $clause  .= ' AND key <> ALL(?::text[])';
            $params[] = RuleContext::pgArray(array_keys($narrowed));
        }

        $clauses = [$clause . ')'];

        foreach ($narrowed as $sourceType => $types) {
            $clauses[] = '(source_type = ? AND event_type = ANY(?::text[]))';
            $params[]  = $sourceType;
            $params[]  = RuleContext::pgArray($types);
        }

        return [implode(' OR ', $clauses), $params];
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
