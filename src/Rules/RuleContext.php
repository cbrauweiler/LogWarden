<?php

declare(strict_types=1);

namespace LogWarden\Rules;

use DateTimeImmutable;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;

/**
 * What a rule is handed when it runs: the evaluation window and a database
 * handle, plus the few helpers every rule would otherwise rewrite.
 *
 * Rules always bound their queries with windowStart()/windowEnd(). An
 * unbounded query over `events` would defeat partition pruning and scan every
 * day on disk.
 */
final class RuleContext
{
    public function __construct(
        private readonly Db $db,
        public readonly DateTimeImmutable $windowStart,
        public readonly DateTimeImmutable $windowEnd,
        public readonly Logger $logger,
    ) {
    }

    public function db(): Db
    {
        return $this->db;
    }

    public function windowStart(): string
    {
        return $this->windowStart->format('Y-m-d H:i:s.uP');
    }

    public function windowEnd(): string
    {
        return $this->windowEnd->format('Y-m-d H:i:s.uP');
    }

    /**
     * Events in the window, with the usual filters applied. Returns raw rows;
     * rules aggregate them themselves.
     *
     * @param array{
     *     source_types?: list<string>,
     *     event_types?: list<string>,
     *     result?: string,
     *     username?: string,
     *     limit?: int
     * } $filter
     * @return list<array<string, mixed>>
     */
    public function events(array $filter = []): array
    {
        $where  = ['ts >= ?::timestamptz', 'ts < ?::timestamptz'];
        $params = [$this->windowStart(), $this->windowEnd()];

        if (!empty($filter['source_types'])) {
            $where[]  = 'source_type = ANY(?::source_type_t[])';
            $params[] = self::pgArray($filter['source_types']);
        }

        if (!empty($filter['event_types'])) {
            $where[]  = 'event_type = ANY(?::text[])';
            $params[] = self::pgArray($filter['event_types']);
        }

        if (!empty($filter['result'])) {
            $where[]  = 'result = ?::event_result_t';
            $params[] = $filter['result'];
        }

        if (!empty($filter['username'])) {
            $where[]  = 'username_norm = lower(?)';
            $params[] = $filter['username'];
        }

        $limit    = (int) ($filter['limit'] ?? 500);
        $params[] = $limit;

        return $this->db->fetchAll(
            'SELECT ts, id, source_type::text AS source_type, source_host, event_type,
                    username, host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
                    result::text AS result, details, raw_message
               FROM events
              WHERE ' . implode(' AND ', $where) . '
              ORDER BY ts DESC, id DESC
              LIMIT ?',
            $params,
        );
    }

    /**
     * PostgreSQL array literal. PDO cannot bind a PHP array, and building the
     * literal is safer than interpolating the values into the SQL.
     *
     * @param list<string> $values
     */
    public static function pgArray(array $values): string
    {
        $escaped = array_map(
            static fn (string $value): string => '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"',
            array_values($values),
        );

        return '{' . implode(',', $escaped) . '}';
    }

    /**
     * Shell-style patterns for the ignore lists ("healthmailbox*"), because a
     * regular expression is more than an administrator should need to type to
     * silence a service account.
     *
     * @param list<string> $patterns
     */
    public static function matchesAny(string $value, array $patterns): bool
    {
        $value = mb_strtolower($value);

        foreach ($patterns as $pattern) {
            if (fnmatch(mb_strtolower($pattern), $value, FNM_CASEFOLD)) {
                return true;
            }
        }

        return false;
    }
}
