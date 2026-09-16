<?php

declare(strict_types=1);

namespace LogWarden\Search;

use LogWarden\Core\Db;
use LogWarden\Event\SourceType;

/**
 * Aggregate queries behind the dashboard.
 *
 * Every query is bounded by an explicit time window so partition pruning can
 * do its job — an unbounded aggregate over `events` would touch every
 * partition on disk.
 */
final class EventStats
{
    public function __construct(private readonly Db $db)
    {
    }

    /** @return array{events:int, failures:int, users:int, sources:int, hosts:int} */
    public function headline(int $hours = 24): array
    {
        $row = $this->db->fetchRow(
            "SELECT count(*)                                            AS events,
                    count(*) FILTER (WHERE result = 'fail')             AS failures,
                    count(DISTINCT username_norm)                       AS users,
                    count(DISTINCT source_type)                         AS sources,
                    count(DISTINCT source_host)                         AS hosts
               FROM events
              WHERE ts >= now() - make_interval(hours => ?)",
            [$hours],
        ) ?? [];

        return [
            'events'   => (int) ($row['events'] ?? 0),
            'failures' => (int) ($row['failures'] ?? 0),
            'users'    => (int) ($row['users'] ?? 0),
            'sources'  => (int) ($row['sources'] ?? 0),
            'hosts'    => (int) ($row['hosts'] ?? 0),
        ];
    }

    /**
     * Event volume per bucket per source type, gap-filled so the chart shows
     * quiet hours as zero rather than closing the gap and implying continuity.
     *
     * @return array{buckets: list<string>, series: array<string, list<int>>, max: int}
     */
    public function volume(int $hours = 24, string $bucket = '1 hour'): array
    {
        $rows = $this->db->fetchAll(
            "WITH slots AS (
                 SELECT generate_series(
                            date_bin(?::interval, now() - make_interval(hours => ?), 'epoch'),
                            date_bin(?::interval, now(), 'epoch'),
                            ?::interval
                        ) AS slot
             )
             SELECT to_char(s.slot, 'YYYY-MM-DD\"T\"HH24:MI') AS bucket,
                    t.source_type::text                       AS source_type,
                    count(e.*)                                AS total
               FROM slots s
               CROSS JOIN unnest(enum_range(NULL::source_type_t)) AS t(source_type)
               LEFT JOIN events e
                      ON e.source_type = t.source_type
                     AND e.ts >= s.slot
                     AND e.ts <  s.slot + ?::interval
              GROUP BY s.slot, t.source_type
              ORDER BY s.slot",
            [$bucket, $hours, $bucket, $bucket, $bucket],
        );

        $buckets = [];
        $series  = [];
        $max     = 0;
        $totals  = [];

        foreach ($rows as $row) {
            $bucketKey = (string) $row['bucket'];
            $type      = (string) $row['source_type'];
            $total     = (int) $row['total'];

            if (!in_array($bucketKey, $buckets, true)) {
                $buckets[] = $bucketKey;
            }

            $series[$type][] = $total;
            $totals[$bucketKey] = ($totals[$bucketKey] ?? 0) + $total;
        }

        foreach ($totals as $sum) {
            $max = max($max, $sum);
        }

        return ['buckets' => $buckets, 'series' => $series, 'max' => $max];
    }

    /** @return list<array{username:string, failures:int, sources:int, last_seen:string}> */
    public function topFailingUsers(int $hours = 24, int $limit = 8): array
    {
        return $this->db->fetchAll(
            "SELECT username,
                    count(*)                      AS failures,
                    count(DISTINCT source_type)   AS sources,
                    to_char(max(ts), 'DD.MM. HH24:MI') AS last_seen
               FROM events
              WHERE ts >= now() - make_interval(hours => ?)
                AND result = 'fail'
                AND username IS NOT NULL
              GROUP BY username
              ORDER BY failures DESC, username
              LIMIT ?",
            [$hours, $limit],
        );
    }

    /** @return list<array<string, mixed>> */
    public function recentEvents(int $limit = 12): array
    {
        return $this->db->fetchAll(
            "SELECT ts, id, source_type::text AS source_type, source_host, event_type,
                    username, host(src_ip) AS src_ip, result::text AS result,
                    to_char(ts, 'DD.MM. HH24:MI:SS') AS ts_label,
                    to_char(ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF') AS ts_iso
               FROM events
              WHERE ts >= now() - interval '7 days'
              ORDER BY ts DESC, id DESC
              LIMIT ?",
            [$limit],
        );
    }

    /** @return list<array<string, mixed>> */
    public function ingestHealth(): array
    {
        return $this->db->fetchAll(
            "SELECT name, collector, source_type::text AS source_type, enabled,
                    last_success_at, last_error, events_total,
                    -- Formatted here rather than in the template, the way every
                    -- other timestamp on the dashboard is; the raw value used
                    -- to reach the page as '2026-09-16 11:24:46.36718+00'.
                    to_char(last_success_at, 'DD.MM. HH24:MI') AS last_success_label
               FROM ingest_sources
              ORDER BY enabled DESC, name"
        );
    }

    /** Human labels for the legend and the source filter. */
    public static function sourceLabels(): array
    {
        $labels = [];

        foreach (SourceType::cases() as $case) {
            $labels[$case->value] = $case->label();
        }

        return $labels;
    }
}
