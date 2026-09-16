<?php

declare(strict_types=1);

namespace LogWarden\Search;

use Generator;
use LogWarden\Core\Db;

/**
 * Turns a SearchCriteria into SQL.
 *
 * Two rules shape everything here. Every query is bounded by the time range,
 * so PostgreSQL prunes partitions instead of reading every day on disk. And
 * paging is keyset, not OFFSET: page 200 of an OFFSET query re-reads the
 * 20.000 rows before it, which is exactly the point at which an analyst is
 * deep in an investigation and least wants to wait.
 */
final class EventQuery
{
    private const EXPORT_CAP = 50_000;

    public function __construct(private readonly Db $db)
    {
    }

    /**
     * One page of results, plus whether another page follows.
     *
     * @return array{rows: list<array<string, mixed>>, hasMore: bool}
     */
    public function search(SearchCriteria $criteria): array
    {
        [$where, $params] = $this->buildWhere($criteria);

        if ($criteria->cursorTs !== null && $criteria->cursorId !== null) {
            // Row-value comparison against the (ts, id) primary key: the index
            // seeks straight to the cursor rather than counting up to it.
            $where[]  = '(e.ts, e.id) < (?::timestamptz, ?)';
            $params[] = $criteria->cursorTs;
            $params[] = $criteria->cursorId;
        }

        // One extra row answers "is there a next page" without a second query.
        $params[] = $criteria->limit + 1;

        $rows = $this->db->fetchAll(
            "SELECT e.ts, e.id, e.source_type::text AS source_type, e.source_host,
                    e.event_type, e.username, host(e.src_ip) AS src_ip,
                    host(e.dst_ip) AS dst_ip, e.result::text AS result,
                    e.raw_message, e.details,
                    to_char(e.ts, 'DD.MM. HH24:MI:SS')        AS ts_label,
                    to_char(e.ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF') AS ts_iso
               FROM events e
              WHERE " . implode(' AND ', $where) . '
              ORDER BY e.ts DESC, e.id DESC
              LIMIT ?',
            $params,
        );

        $hasMore = count($rows) > $criteria->limit;

        return [
            'rows'    => $hasMore ? array_slice($rows, 0, $criteria->limit) : $rows,
            'hasMore' => $hasMore,
        ];
    }

    /**
     * Counting every match over a wide window costs more than the page itself,
     * and "10.000+" answers the question just as well as an exact number does.
     *
     * @return array{count: int, capped: bool}
     */
    public function countCapped(SearchCriteria $criteria): array
    {
        [$where, $params] = $this->buildWhere($criteria);
        $params[] = SearchCriteria::COUNT_CAP + 1;

        $count = (int) $this->db->fetchValue(
            'SELECT count(*) FROM (
                 SELECT 1 FROM events e WHERE ' . implode(' AND ', $where) . ' LIMIT ?
             ) capped',
            $params,
        );

        return [
            'count'  => min($count, SearchCriteria::COUNT_CAP),
            'capped' => $count > SearchCriteria::COUNT_CAP,
        ];
    }

    /**
     * Distribution within the current result set, by source and by outcome.
     * GROUPING SETS gets both dimensions from one pass over the data.
     *
     * Bounded on purpose. An exact aggregate over every match is linear in the
     * volume — 160 ms over 500k rows, and minutes once the store holds what a
     * year of ingestion produces. Past the cap it reports the distribution of
     * the most recent matches instead, and says so.
     *
     * @return array{source: array<string,int>, result: array<string,int>, sampled: bool}
     */
    public function facets(SearchCriteria $criteria, bool $capped = false): array
    {
        [$where, $params] = $this->buildWhere($criteria);
        $clause = implode(' AND ', $where);

        if ($capped) {
            $params[] = SearchCriteria::COUNT_CAP;
            $sql = "SELECT s.source_type::text AS source_type, s.result::text AS result, count(*) AS total
                      FROM (
                          SELECT e.source_type, e.result
                            FROM events e
                           WHERE {$clause}
                           ORDER BY e.ts DESC, e.id DESC
                           LIMIT ?
                      ) s
                     GROUP BY GROUPING SETS ((s.source_type), (s.result))";
        } else {
            $sql = "SELECT e.source_type::text AS source_type, e.result::text AS result, count(*) AS total
                      FROM events e
                     WHERE {$clause}
                     GROUP BY GROUPING SETS ((e.source_type), (e.result))";
        }

        $rows = $this->db->fetchAll($sql, $params);

        $facets = ['source' => [], 'result' => [], 'sampled' => $capped];

        foreach ($rows as $row) {
            if ($row['source_type'] !== null) {
                $facets['source'][(string) $row['source_type']] = (int) $row['total'];
            } elseif ($row['result'] !== null) {
                $facets['result'][(string) $row['result']] = (int) $row['total'];
            }
        }

        arsort($facets['source']);
        arsort($facets['result']);

        return $facets;
    }

    /**
     * A single event. Both parts of the primary key are required: without the
     * timestamp the lookup would have to visit every partition.
     *
     * @return array<string, mixed>|null
     */
    public function find(string $ts, int $id): ?array
    {
        return $this->db->fetchRow(
            "SELECT e.ts, e.id, e.source_type::text AS source_type, e.source_host,
                    e.event_type, e.username, e.username_norm,
                    host(e.src_ip) AS src_ip, host(e.dst_ip) AS dst_ip,
                    e.result::text AS result, e.raw_message, e.details, e.dedup_key,
                    to_char(e.ts, 'DD.MM.YYYY HH24:MI:SS.US') AS ts_label,
                    to_char(e.ingested_at, 'DD.MM.YYYY HH24:MI:SS') AS ingested_label,
                    to_char(e.ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF') AS ts_iso,
                    extract(epoch FROM (e.ingested_at - e.ts))::int AS delay_seconds
               FROM events e
              WHERE e.ts = ?::timestamptz AND e.id = ?",
            [$ts, $id],
        );
    }

    /**
     * What else happened around this event for the same account or address.
     * Usually the first question after opening one: was this alone, or part of
     * something.
     *
     * @param array<string, mixed> $event
     * @return list<array<string, mixed>>
     */
    public function neighbours(array $event, int $minutes = 10, int $limit = 40): array
    {
        $conditions = [];
        $params     = [$event['ts_iso'], $minutes, $event['ts_iso'], $minutes];

        if (!empty($event['username_norm'])) {
            $conditions[] = 'e.username_norm = ?';
            $params[]     = $event['username_norm'];
        }

        if (!empty($event['src_ip'])) {
            $conditions[] = 'e.src_ip = ?::inet';
            $params[]     = $event['src_ip'];
        }

        if ($conditions === []) {
            return [];
        }

        $params[] = (int) $event['id'];
        $params[] = $limit;

        return $this->db->fetchAll(
            "SELECT e.ts, e.id, e.source_type::text AS source_type, e.source_host,
                    e.event_type, e.username, host(e.src_ip) AS src_ip,
                    e.result::text AS result,
                    to_char(e.ts, 'DD.MM. HH24:MI:SS') AS ts_label,
                    to_char(e.ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF') AS ts_iso
               FROM events e
              WHERE e.ts >= ?::timestamptz - make_interval(mins => ?)
                AND e.ts <= ?::timestamptz + make_interval(mins => ?)
                AND (" . implode(' OR ', $conditions) . ')
                AND e.id <> ?
              ORDER BY e.ts DESC
              LIMIT ?',
            $params,
        );
    }

    /**
     * Streams matching rows for CSV export, paging internally so one export
     * never buffers a whole result set in memory.
     *
     * @return Generator<int, array<string, mixed>>
     */
    public function export(SearchCriteria $criteria): Generator
    {
        $cursorTs = $criteria->cursorTs;
        $cursorId = $criteria->cursorId;
        $emitted  = 0;

        while ($emitted < self::EXPORT_CAP) {
            [$where, $params] = $this->buildWhere($criteria);

            if ($cursorTs !== null && $cursorId !== null) {
                $where[]  = '(e.ts, e.id) < (?::timestamptz, ?)';
                $params[] = $cursorTs;
                $params[] = $cursorId;
            }

            $batch    = min(1000, self::EXPORT_CAP - $emitted);
            $params[] = $batch;

            $rows = $this->db->fetchAll(
                "SELECT e.id, e.source_type::text AS source_type, e.source_host,
                        e.event_type, e.username, host(e.src_ip) AS src_ip,
                        host(e.dst_ip) AS dst_ip, e.result::text AS result,
                        e.raw_message,
                        to_char(e.ts, 'YYYY-MM-DD HH24:MI:SS.US')      AS ts_utc,
                        to_char(e.ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF') AS ts_iso
                   FROM events e
                  WHERE " . implode(' AND ', $where) . '
                  ORDER BY e.ts DESC, e.id DESC
                  LIMIT ?',
                $params,
            );

            if ($rows === []) {
                return;
            }

            foreach ($rows as $row) {
                yield $row;
                $emitted++;
                $cursorTs = (string) $row['ts_iso'];
                $cursorId = (int) $row['id'];
            }

            if (count($rows) < $batch) {
                return;
            }
        }
    }

    // -----------------------------------------------------------------------

    /**
     * @return array{0: list<string>, 1: list<mixed>}
     */
    private function buildWhere(SearchCriteria $criteria): array
    {
        // The time bound is first and unconditional: it is what lets the
        // planner discard partitions before reading anything.
        $where  = ['e.ts >= ?::timestamptz', 'e.ts < ?::timestamptz'];
        $params = [
            $criteria->from->format('Y-m-d H:i:sP'),
            $criteria->to->format('Y-m-d H:i:sP'),
        ];

        if ($criteria->sourceTypes !== []) {
            $where[]  = 'e.source_type = ANY(?::text[])';
            $params[] = self::pgArray($criteria->sourceTypes);
        }

        if ($criteria->username !== null) {
            [$clause, $value] = self::textMatch('e.username_norm', mb_strtolower($criteria->username));
            $where[]  = $clause;
            $params[] = $value;
        }

        if ($criteria->host !== null) {
            [$clause, $value] = self::textMatch('e.source_host', $criteria->host);
            $where[]  = $clause;
            $params[] = $value;
        }

        // An invalid address is reported to the user by the controller rather
        // than sent to the database, where it would be a 500.
        if ($criteria->ip !== null && $criteria->ipValid) {
            $where[] = $this->ipClause($criteria, $params);
        }

        if ($criteria->eventType !== null) {
            [$clause, $value] = self::textMatch('e.event_type', $criteria->eventType);
            $where[]  = $clause;
            $params[] = $value;
        }

        if ($criteria->result !== null) {
            $where[]  = 'e.result = ?::event_result_t';
            $params[] = $criteria->result;
        }

        if ($criteria->query !== null) {
            // websearch_to_tsquery accepts what people already type into a
            // search box: quoted phrases, OR, and a leading minus to exclude.
            $where[]  = "e.search_tsv @@ websearch_to_tsquery('simple', ?)";
            $params[] = $criteria->query;
        }

        return [$where, $params];
    }

    /** @param list<mixed> $params */
    private function ipClause(SearchCriteria $criteria, array &$params): string
    {
        $value = (string) $criteria->ip;

        // A plain address uses `=` so the btree index applies; only a network
        // needs the containment operator.
        $operator = str_contains($value, '/') ? '<<=' : '=';

        $fields = match ($criteria->ipField) {
            'src'   => ['e.src_ip'],
            'dst'   => ['e.dst_ip'],
            default => ['e.src_ip', 'e.dst_ip'],
        };

        $parts = [];
        foreach ($fields as $field) {
            $parts[]  = "{$field} {$operator} ?::inet";
            $params[] = $value;
        }

        return '(' . implode(' OR ', $parts) . ')';
    }

    /**
     * `*` is what people type for a wildcard, so translate it rather than
     * demanding SQL syntax. A trailing-only wildcard stays index-friendly.
     *
     * @return array{0: string, 1: string}
     */
    private static function textMatch(string $column, string $value): array
    {
        if (!str_contains($value, '*')) {
            return ["{$column} = ?", $value];
        }

        $pattern = str_replace(['\\', '%', '_', '*'], ['\\\\', '\\%', '\\_', '%'], $value);

        return ["{$column} LIKE ?", $pattern];
    }

    /** @param list<string> $values */
    private static function pgArray(array $values): string
    {
        $escaped = array_map(
            static fn (string $v): string => '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"',
            $values,
        );

        return '{' . implode(',', $escaped) . '}';
    }
}
