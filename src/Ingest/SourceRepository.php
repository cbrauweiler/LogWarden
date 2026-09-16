<?php

declare(strict_types=1);

namespace LogWarden\Ingest;

use DateTimeImmutable;
use LogWarden\Core\Db;

/** Reads and updates `ingest_sources` and the run history. */
final class SourceRepository
{
    public function __construct(private readonly Db $db)
    {
    }

    /** @return list<IngestSource> */
    public function all(?string $collector = null): array
    {
        $sql    = 'SELECT * FROM ingest_sources';
        $params = [];

        if ($collector !== null) {
            $sql .= ' WHERE collector = ?';
            $params[] = $collector;
        }

        $sql .= ' ORDER BY name';

        return array_map(
            static fn (array $row): IngestSource => IngestSource::fromRow($row),
            $this->db->query($sql, $params)->fetchAll(),
        );
    }

    public function find(int $id): ?IngestSource
    {
        $row = $this->db->query('SELECT * FROM ingest_sources WHERE id = ?', [$id])->fetch();

        return $row === false ? null : IngestSource::fromRow($row);
    }

    public function findByName(string $name): ?IngestSource
    {
        $row = $this->db->query('SELECT * FROM ingest_sources WHERE name = ?', [$name])->fetch();

        return $row === false ? null : IngestSource::fromRow($row);
    }

    /**
     * Records a successful run and advances the bookmark.
     *
     * Bookmark and counters move in the same statement as the run history, so
     * a crash between them cannot leave a source claiming to have collected a
     * window it has no record of.
     *
     * @param array<string, mixed> $bookmark
     */
    public function recordSuccess(
        IngestSource $source,
        array $bookmark,
        int $fetched,
        int $stored,
        int $skipped,
        int $durationMs,
    ): void {
        $this->db->transaction(function () use ($source, $bookmark, $fetched, $stored, $skipped, $durationMs): void {
            $this->db->execute(
                'UPDATE ingest_sources
                    SET bookmark = ?::jsonb,
                        last_success_at = now(),
                        last_run_at = now(),
                        last_error = NULL,
                        last_error_at = NULL,
                        last_duration_ms = ?,
                        consecutive_failures = 0,
                        events_total = events_total + ?,
                        updated_at = now()
                  WHERE id = ?',
                [json_encode($bookmark, JSON_UNESCAPED_SLASHES), $durationMs, $stored, $source->id],
            );

            $this->db->execute(
                'INSERT INTO ingest_runs (source_id, duration_ms, status, fetched, stored, skipped, bookmark)
                 VALUES (?, ?, ?, ?, ?, ?, ?::jsonb)',
                [
                    $source->id,
                    $durationMs,
                    $fetched === 0 ? 'empty' : 'ok',
                    $fetched,
                    $stored,
                    $skipped,
                    json_encode($bookmark, JSON_UNESCAPED_SLASHES),
                ],
            );
        });
    }

    public function recordFailure(IngestSource $source, string $error, int $durationMs): void
    {
        // The bookmark is deliberately left alone: a failed run collected
        // nothing, so the next one must retry the same window. Advancing it
        // here would turn every transient outage into a silent gap.
        $this->db->transaction(function () use ($source, $error, $durationMs): void {
            $this->db->execute(
                'UPDATE ingest_sources
                    SET last_run_at = now(),
                        last_error = ?,
                        last_error_at = now(),
                        last_duration_ms = ?,
                        consecutive_failures = consecutive_failures + 1,
                        updated_at = now()
                  WHERE id = ?',
                [mb_substr($error, 0, 2000), $durationMs, $source->id],
            );

            $this->db->execute(
                'INSERT INTO ingest_runs (source_id, duration_ms, status, error)
                 VALUES (?, ?, ?, ?)',
                [$source->id, $durationMs, 'error', mb_substr($error, 0, 2000)],
            );
        });
    }

    /** @return list<array<string, mixed>> */
    public function recentRuns(int $sourceId, int $limit = 20): array
    {
        return $this->db->query(
            'SELECT started_at, duration_ms, status, fetched, stored, skipped, error
               FROM ingest_runs
              WHERE source_id = ?
              ORDER BY started_at DESC
              LIMIT ?',
            [$sourceId, $limit],
        )->fetchAll();
    }

    /**
     * Health across all sources, for the settings page and the dashboard.
     *
     * @return list<array<string, mixed>>
     */
    public function health(): array
    {
        return $this->db->query(
            "SELECT s.id, s.name, s.collector, s.source_type::text AS source_type, s.target_host,
                    s.enabled, s.last_success_at, s.last_run_at, s.last_error, s.last_error_at,
                    to_char(s.last_success_at, 'DD.MM. HH24:MI') AS last_success_label,
                    s.events_total, s.consecutive_failures, s.poll_interval_s,
                    -- A DHCP source has no channel; what identifies it is the
                    -- directory it reads. One column, so the overview stays one
                    -- table.
                    coalesce(s.config->>'channel', s.config->>'log_path') AS channel,
                    (SELECT count(*) FROM ingest_runs r
                      WHERE r.source_id = s.id AND r.started_at > now() - interval '24 hours'
                        AND r.status = 'error') AS errors_24h,
                    (SELECT coalesce(sum(r.stored), 0) FROM ingest_runs r
                      WHERE r.source_id = s.id AND r.started_at > now() - interval '24 hours') AS stored_24h
               FROM ingest_sources s
              ORDER BY s.enabled DESC, s.name",
        )->fetchAll();
    }

    /** Housekeeping for the run history; called by bin/logwarden-maintenance. */
    public function pruneRuns(int $keepDays): int
    {
        return $this->db->execute(
            'DELETE FROM ingest_runs WHERE started_at < now() - make_interval(days => ?)',
            [$keepDays],
        );
    }

    public function setEnabled(int $id, bool $enabled): void
    {
        $this->db->execute(
            'UPDATE ingest_sources SET enabled = ?, updated_at = now() WHERE id = ?',
            [$enabled ? 1 : 0, $id],
        );
    }

    /**
     * Clears the bookmark so the next run starts over from `initial_lookback`.
     *
     * The run history is kept: it is the only remaining evidence of what the
     * source did before the reset.
     */
    public function resetBookmark(int $id): void
    {
        $this->db->execute(
            'UPDATE ingest_sources SET bookmark = NULL, updated_at = now() WHERE id = ?',
            [$id],
        );
    }

    public function delete(int $id): void
    {
        $this->db->execute('DELETE FROM ingest_sources WHERE id = ?', [$id]);
    }

    /** @param array<string, mixed> $fields */
    public function upsert(array $fields): int
    {
        $existing = $this->findByName((string) $fields['name']);

        if ($existing !== null) {
            $this->db->execute(
                'UPDATE ingest_sources
                    SET collector = ?, source_type = ?, target_host = ?,
                        enabled = ?, config = ?::jsonb, secret_ref = coalesce(?, secret_ref),
                        username = ?, auth_mode = ?, poll_interval_s = ?, updated_at = now()
                  WHERE id = ?',
                [
                    $fields['collector'], $fields['source_type'], $fields['target_host'],
                    !empty($fields['enabled']) ? 1 : 0,
                    json_encode($fields['config'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                    $fields['secret_ref'] ?? null,
                    $fields['username'] ?? null, $fields['auth_mode'] ?? 'ntlm',
                    (int) ($fields['poll_interval_s'] ?? 300),
                    $existing->id,
                ],
            );

            return $existing->id;
        }

        $row = $this->db->query(
            'INSERT INTO ingest_sources
                 (name, collector, source_type, target_host, enabled, config,
                  secret_ref, username, auth_mode, poll_interval_s)
             VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)
             RETURNING id',
            [
                $fields['name'], $fields['collector'], $fields['source_type'], $fields['target_host'],
                !empty($fields['enabled']) ? 1 : 0,
                json_encode($fields['config'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                $fields['secret_ref'] ?? null,
                $fields['username'] ?? null, $fields['auth_mode'] ?? 'ntlm',
                (int) ($fields['poll_interval_s'] ?? 300),
            ],
        )->fetch();

        return (int) $row['id'];
    }
}
