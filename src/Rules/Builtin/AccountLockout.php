<?php

declare(strict_types=1);

namespace LogWarden\Rules\Builtin;

use LogWarden\Rules\AlertCandidate;
use LogWarden\Rules\RuleContext;
use LogWarden\Rules\RuleInterface;

/**
 * Active Directory account lockout (event 4740).
 *
 * The lockout itself is one line and says almost nothing. The question an
 * administrator actually has is "what locked it, and from where" — so the
 * alert carries the preceding failures across all sources, grouped by origin.
 * That usually answers it outright: a stale credential on a phone, a service
 * account with an old password, or an actual attempt from outside.
 */
final class AccountLockout implements RuleInterface
{
    public static function key(): string
    {
        return 'account_lockout';
    }

    public static function title(): string
    {
        return 'Account-Lockout';
    }

    public static function description(): string
    {
        return 'Meldet gesperrte AD-Konten (Event 4740) und stellt die vorausgegangenen '
            . 'Fehlversuche aller Quellen als Kontext bei.';
    }

    public static function defaultParams(): array
    {
        return [
            'event_types'               => ['4740'],
            'evidence_lookback_minutes' => 60,
            'ignore_users'              => [],
        ];
    }

    public function evaluate(RuleContext $context, array $params): array
    {
        $eventTypes = is_array($params['event_types'] ?? null) ? $params['event_types'] : ['4740'];
        $ignore     = is_array($params['ignore_users'] ?? null) ? $params['ignore_users'] : [];
        $lookback   = max(5, min(1440, (int) ($params['evidence_lookback_minutes'] ?? 60)));

        $lockouts = $context->db()->fetchAll(
            "SELECT to_char(ts, 'YYYY-MM-DD HH24:MI:SS.USOF') AS ts_iso,
                    to_char(ts, 'YYYY-MM-DD HH24:MI:SS')      AS ts_label,
                    id, username, username_norm, source_host, details
               FROM events
              WHERE ts >= ?::timestamptz
                AND ts <  ?::timestamptz
                -- Any directory, not specifically Active Directory: the event
                -- ids stay configurable, the vendor does not belong in the query.
                AND source_type IN (SELECT key FROM source_types WHERE role = 'directory')
                AND event_type = ANY(?::text[])
                AND username IS NOT NULL
              ORDER BY ts DESC",
            [
                $context->windowStart(),
                $context->windowEnd(),
                RuleContext::pgArray(array_map('strval', $eventTypes)),
            ],
        );

        $candidates = [];

        foreach ($lockouts as $lockout) {
            $username = (string) $lockout['username'];

            if (RuleContext::matchesAny($username, $ignore)) {
                continue;
            }

            $details = json_decode((string) $lockout['details'], true) ?: [];
            $caller  = $details['caller_computer'] ?? $details['CallerComputerName'] ?? null;

            $context_ = $this->precedingFailures($context, $username, (string) $lockout['ts_iso'], $lookback);

            $candidates[] = new AlertCandidate(
                dedupKey:   'account_lockout:' . $lockout['username_norm'],
                title:      "Konto {$username} wurde gesperrt",
                summary:    $this->summarise($username, (string) $lockout['ts_label'], $caller, $context_),
                eventCount: 1 + $context_['total'],
                entityUser: $username,
                entityIp:   $context_['top_ip'],
                entityHost: is_string($caller) ? $caller : (string) $lockout['source_host'],
                evidence: [
                    'locked_at'        => $lockout['ts_label'],
                    'domain_controller' => $lockout['source_host'],
                    'caller_computer'  => $caller,
                    'lookback_minutes' => $lookback,
                    'preceding_failures' => $context_['total'],
                    'by_source'        => $context_['by_source'],
                    'by_origin'        => $context_['by_origin'],
                    'first_seen'       => $context_['first_ts'],
                ],
                eventRefs: array_merge(
                    [[(string) $lockout['ts_iso'], (int) $lockout['id']]],
                    $context_['refs'],
                ),
            );
        }

        return $candidates;
    }

    /**
     * Deliberately looks further back than the rule's own window: the lockout
     * is the symptom, and the attempts that caused it happened before it.
     *
     * @return array{
     *     total:int, by_source:array<string,int>,
     *     by_origin:list<array<string,mixed>>, top_ip:?string,
     *     first_ts:?string, refs:list<array{0:string,1:int}>
     * }
     */
    private function precedingFailures(RuleContext $context, string $username, string $lockoutTs, int $lookback): array
    {
        $rows = $context->db()->fetchAll(
            "SELECT to_char(ts, 'YYYY-MM-DD HH24:MI:SS.USOF') AS ts_iso,
                    to_char(ts, 'YYYY-MM-DD HH24:MI:SS')      AS ts_label,
                    id, source_type::text AS source_type, source_host,
                    host(src_ip) AS src_ip, event_type
               FROM events
              WHERE ts >= ?::timestamptz - make_interval(mins => ?)
                AND ts <= ?::timestamptz
                AND username_norm = lower(?)
                AND result = 'fail'
              ORDER BY ts DESC
              LIMIT 200",
            [$lockoutTs, $lookback, $lockoutTs, $username],
        );

        $bySource = [];
        $byOrigin = [];
        $refs     = [];
        $firstTs  = null;

        foreach ($rows as $row) {
            $source = (string) $row['source_type'];
            $bySource[$source] = ($bySource[$source] ?? 0) + 1;

            // Group by where it came from, because "23 attempts from one phone"
            // and "23 attempts from 23 addresses" need different responses.
            $originKey = ($row['src_ip'] ?? '—') . '|' . $row['source_host'];
            if (!isset($byOrigin[$originKey])) {
                $byOrigin[$originKey] = [
                    'src_ip'      => $row['src_ip'],
                    'target_host' => $row['source_host'],
                    'source_type' => $source,
                    'count'       => 0,
                    'last_seen'   => $row['ts_label'],
                ];
            }
            $byOrigin[$originKey]['count']++;

            $firstTs = (string) $row['ts_label'];

            if (count($refs) < 50) {
                $refs[] = [(string) $row['ts_iso'], (int) $row['id']];
            }
        }

        usort($byOrigin, static fn (array $a, array $b): int => $b['count'] <=> $a['count']);

        return [
            'total'     => count($rows),
            'by_source' => $bySource,
            'by_origin' => array_slice(array_values($byOrigin), 0, 10),
            'top_ip'    => $byOrigin[0]['src_ip'] ?? null,
            'first_ts'  => $firstTs,
            'refs'      => $refs,
        ];
    }

    /** @param array<string, mixed> $context_ */
    private function summarise(string $username, string $lockedAt, mixed $caller, array $context_): string
    {
        $summary = "Konto {$username} wurde um " . substr($lockedAt, 11, 5) . ' Uhr gesperrt';

        if (is_string($caller) && $caller !== '') {
            $summary .= " (auslösender Rechner: {$caller})";
        }

        $summary .= '. ';

        if ($context_['total'] === 0) {
            // Worth saying out loud: it means the attempts happened somewhere
            // LogWarden is not yet collecting from.
            return $summary . 'Im Betrachtungszeitraum sind keine vorausgegangenen Fehlversuche erfasst — '
                . 'die Versuche liefen vermutlich über eine noch nicht angebundene Quelle.';
        }

        $summary .= "{$context_['total']} vorausgegangene Fehlversuche";

        $top = $context_['by_origin'][0] ?? null;
        if ($top !== null && !empty($top['src_ip'])) {
            $summary .= ", überwiegend von {$top['src_ip']} ({$top['count']}×)";
        }

        $origins = count($context_['by_origin']);
        if ($origins > 1) {
            $summary .= ", insgesamt aus {$origins} Quellen";
        }

        return $summary . '.';
    }
}
