<?php

declare(strict_types=1);

namespace LogWarden\Ingest;

use DateTimeImmutable;
use LogWarden\Event\SourceType;

/** One configured collection target, as stored in `ingest_sources`. */
final class IngestSource
{
    public function __construct(
        public readonly int $id,
        public readonly string $name,
        public readonly string $collector,
        public readonly SourceType $sourceType,
        public readonly ?string $targetHost,
        public readonly bool $enabled,
        public readonly array $config,
        public readonly ?string $secretRef,
        public readonly ?string $username,
        public readonly string $authMode,
        public readonly int $pollIntervalS,
        public readonly array $bookmark,
        public readonly ?DateTimeImmutable $lastSuccessAt,
        public readonly ?DateTimeImmutable $lastRunAt,
        public readonly ?string $lastError,
        public readonly ?DateTimeImmutable $lastErrorAt,
        public readonly int $eventsTotal,
        public readonly int $consecutiveFailures,
    ) {
    }

    public static function fromRow(array $row): self
    {
        return new self(
            id:                  (int) $row['id'],
            name:                (string) $row['name'],
            collector:           (string) $row['collector'],
            sourceType:          SourceType::from((string) $row['source_type']),
            targetHost:          $row['target_host'] === null ? null : (string) $row['target_host'],
            enabled:             (bool) $row['enabled'],
            config:              self::json($row['config'] ?? null),
            secretRef:           $row['secret_ref'] === null ? null : (string) $row['secret_ref'],
            username:            $row['username'] === null ? null : (string) $row['username'],
            authMode:            (string) ($row['auth_mode'] ?? 'ntlm'),
            pollIntervalS:       (int) ($row['poll_interval_s'] ?? 300),
            bookmark:            self::json($row['bookmark'] ?? null),
            lastSuccessAt:       self::time($row['last_success_at'] ?? null),
            lastRunAt:           self::time($row['last_run_at'] ?? null),
            lastError:           $row['last_error'] === null ? null : (string) $row['last_error'],
            lastErrorAt:         self::time($row['last_error_at'] ?? null),
            eventsTotal:         (int) ($row['events_total'] ?? 0),
            consecutiveFailures: (int) ($row['consecutive_failures'] ?? 0),
        );
    }

    public function channel(): string
    {
        return (string) ($this->config['channel'] ?? 'Security');
    }

    /** @return list<int> */
    public function eventIds(): array
    {
        $ids = $this->config['event_ids'] ?? null;
        if (!is_array($ids)) {
            return [];
        }

        return array_values(array_map('intval', array_filter($ids, 'is_numeric')));
    }

    public function setting(string $key, mixed $default = null): mixed
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Where the last complete window ended.
     *
     * Missing on a new source, which is the only case where a start has to be
     * invented rather than remembered — see WinrmCollector::startOf().
     */
    public function bookmarkTime(): ?DateTimeImmutable
    {
        $value = $this->bookmark['until'] ?? null;
        if (!is_string($value)) {
            return null;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * Same reading as bookmarkTime(), but for a bookmark held in memory —
     * the catch-up loop advances through several windows before any of them
     * reaches the database.
     *
     * @param array<string, mixed> $bookmark
     */
    public function bookmarkTimeFrom(array $bookmark): ?DateTimeImmutable
    {
        $value = $bookmark['until'] ?? null;
        if (!is_string($value)) {
            return null;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (\Exception) {
            return null;
        }
    }

    public function isDue(DateTimeImmutable $now): bool
    {
        if (!$this->enabled) {
            return false;
        }

        if ($this->lastRunAt === null) {
            return true;
        }

        return ($now->getTimestamp() - $this->lastRunAt->getTimestamp()) >= $this->pollIntervalS;
    }

    private static function json(mixed $value): array
    {
        if (is_array($value)) {
            return $value;
        }

        if (!is_string($value) || $value === '') {
            return [];
        }

        $decoded = json_decode($value, true);

        return is_array($decoded) ? $decoded : [];
    }

    private static function time(mixed $value): ?DateTimeImmutable
    {
        if (!is_string($value) || $value === '') {
            return null;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (\Exception) {
            return null;
        }
    }
}
