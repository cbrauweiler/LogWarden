<?php

declare(strict_types=1);

namespace LogWarden\Event;

use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use Throwable;

/**
 * Buffers events and writes them in batches.
 *
 * A per-event INSERT would cap the syslog listener at a few hundred events per
 * second; one multi-row INSERT per batch moves that into the tens of thousands.
 * If the database is unreachable the batch goes to a spool file instead, so a
 * database restart costs latency rather than UDP datagrams.
 */
final class EventWriter
{
    private const COLUMNS = [
        'ts', 'source_type', 'source_host', 'event_type', 'username',
        'src_ip', 'dst_ip', 'result', 'raw_message', 'details', 'dedup_key',
    ];

    /** @var list<Event> */
    private array $buffer = [];

    private float $lastFlush;

    private int $written = 0;
    private int $duplicates = 0;
    private int $spooled = 0;

    public function __construct(
        private readonly Db $db,
        private readonly Logger $logger,
        private readonly int $batchSize = 500,
        private readonly float $flushInterval = 1.0,
        private readonly ?string $spoolDir = null,
    ) {
        $this->lastFlush = microtime(true);
    }

    public function add(Event $event): void
    {
        $this->buffer[] = $event;

        if (count($this->buffer) >= $this->batchSize) {
            $this->flush();
        }
    }

    /**
     * Call from the event loop. Flushes when the batch has been waiting longer
     * than the configured interval, so a quiet listener still persists events
     * promptly instead of holding them until the batch fills.
     */
    public function flushIfDue(): void
    {
        if ($this->buffer !== [] && (microtime(true) - $this->lastFlush) >= $this->flushInterval) {
            $this->flush();
        }
    }

    public function flush(): int
    {
        if ($this->buffer === []) {
            $this->lastFlush = microtime(true);

            return 0;
        }

        $batch        = $this->buffer;
        $this->buffer = [];
        $this->lastFlush = microtime(true);

        try {
            $inserted = $this->insertBatch($batch);
            $this->written    += $inserted;
            $this->duplicates += count($batch) - $inserted;

            return $inserted;
        } catch (Throwable $e) {
            $this->logger->error('Batch insert failed', [
                'events'  => count($batch),
                'error'   => $e->getMessage(),
            ]);

            if ($this->spoolDir !== null) {
                $this->spool($batch);
            } else {
                $this->logger->error('Spooling disabled, dropping batch', ['events' => count($batch)]);
            }

            return 0;
        }
    }

    /** @param list<Event> $batch */
    private function insertBatch(array $batch): int
    {
        $placeholders = [];
        $params       = [];

        foreach ($batch as $event) {
            $row = $event->toRow();
            $placeholders[] = '(' . rtrim(str_repeat('?,', count(self::COLUMNS)), ',') . ')';
            foreach (self::COLUMNS as $column) {
                $params[] = $row[$column];
            }
        }

        $sql = 'INSERT INTO events (' . implode(', ', self::COLUMNS) . ') VALUES '
            . implode(', ', $placeholders)
            // Replays and overlapping pull windows are expected, not errors.
            . ' ON CONFLICT DO NOTHING';

        return $this->db->execute($sql, $params);
    }

    /**
     * Newline-delimited JSON, one file per flush. bin/logwarden-spool-replay
     * feeds these back once the database is available again.
     *
     * @param list<Event> $batch
     */
    private function spool(array $batch): void
    {
        if (!is_dir($this->spoolDir) && !@mkdir($this->spoolDir, 0o750, true) && !is_dir($this->spoolDir)) {
            $this->logger->error('Spool directory unavailable, dropping batch', ['dir' => $this->spoolDir]);

            return;
        }

        $file = sprintf('%s/%s-%s.ndjson', $this->spoolDir, gmdate('Ymd-His'), bin2hex(random_bytes(4)));
        $lines = '';
        foreach ($batch as $event) {
            $lines .= json_encode($event->toRow(), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
        }

        // Write to a temporary name first so the replay job never picks up a
        // half-written file.
        $tmp = $file . '.partial';
        if (@file_put_contents($tmp, $lines, LOCK_EX) === false || !@rename($tmp, $file)) {
            $this->logger->error('Spool write failed, dropping batch', ['file' => $file]);
            @unlink($tmp);

            return;
        }

        $this->spooled += count($batch);
        $this->logger->warning('Batch spooled to disk', ['file' => basename($file), 'events' => count($batch)]);
    }

    public function pending(): int
    {
        return count($this->buffer);
    }

    /** @return array{written:int, duplicates:int, spooled:int, pending:int} */
    public function stats(): array
    {
        return [
            'written'    => $this->written,
            'duplicates' => $this->duplicates,
            'spooled'    => $this->spooled,
            'pending'    => count($this->buffer),
        ];
    }
}
