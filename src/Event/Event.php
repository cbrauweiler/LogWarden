<?php

declare(strict_types=1);

namespace LogWarden\Event;

use DateTimeImmutable;

/**
 * One normalised event, matching the `events` table.
 *
 * Every ingestion module produces these regardless of source, which is what
 * makes cross-source correlation ("VPN login, then AD failure") a plain query.
 */
final class Event
{
    public readonly string $dedupKey;

    public function __construct(
        public readonly DateTimeImmutable $ts,
        public readonly SourceType $sourceType,
        public readonly string $sourceHost,
        public readonly string $eventType,
        public readonly string $rawMessage,
        public readonly ?string $username = null,
        public readonly ?string $srcIp = null,
        public readonly ?string $dstIp = null,
        public readonly ?EventResult $result = null,
        public readonly array $details = [],
        ?string $dedupKey = null,
    ) {
        $this->dedupKey = $dedupKey ?? self::deriveDedupKey($ts, $sourceHost, $eventType, $rawMessage);
    }

    /**
     * Sources that carry a stable record id (Windows EventRecordID, FortiGate
     * eventtime+logid) should pass their own key. For everything else a hash
     * over the raw line is the best available identity: replaying the same
     * file or re-reading an overlapping window stays idempotent.
     */
    public static function deriveDedupKey(
        DateTimeImmutable $ts,
        string $sourceHost,
        string $eventType,
        string $rawMessage,
    ): string {
        return substr(hash('sha256', implode("\0", [
            $ts->format('Y-m-d\TH:i:s.uP'),
            $sourceHost,
            $eventType,
            $rawMessage,
        ])), 0, 40);
    }

    /**
     * PostgreSQL's `inet` rejects anything that is not an address, and its
     * `text` rejects NUL bytes. Both appear in real syslog traffic, so the
     * value objects clean up rather than letting a whole batch fail.
     */
    public static function normaliseIp(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);
        if ($value === '' || $value === '-' || $value === 'N/A') {
            return null;
        }

        // FortiGate occasionally emits "ip:port" for translated addresses.
        if (substr_count($value, ':') === 1 && !str_contains($value, '::')) {
            [$host, ] = explode(':', $value, 2);
            if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
                $value = $host;
            }
        }

        return filter_var($value, FILTER_VALIDATE_IP) === false ? null : $value;
    }

    public static function sanitiseText(string $value, int $maxBytes = 0): string
    {
        $value = str_replace("\0", '', $value);

        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        }

        if ($maxBytes > 0 && strlen($value) > $maxBytes) {
            $value = mb_strcut($value, 0, $maxBytes);
        }

        return $value;
    }

    public static function normaliseUsername(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);
        if ($value === '' || $value === '-' || $value === 'N/A') {
            return null;
        }

        // Strip the domain so DOMAIN\jdoe, jdoe@corp.local and jdoe correlate
        // as the same principal across AD and FortiGate.
        if (str_contains($value, '\\')) {
            $value = substr($value, strrpos($value, '\\') + 1);
        } elseif (str_contains($value, '@')) {
            $value = substr($value, 0, strpos($value, '@'));
        }

        $value = trim($value);

        // AD writes this for events with no associated principal.
        return ($value === '' || $value === '-') ? null : $value;
    }

    /** @return array<string, mixed> */
    public function toRow(): array
    {
        return [
            'ts'          => $this->ts->format('Y-m-d H:i:s.uP'),
            'source_type' => $this->sourceType->value,
            'source_host' => $this->sourceHost,
            'event_type'  => $this->eventType,
            'username'    => $this->username,
            'src_ip'      => $this->srcIp,
            'dst_ip'      => $this->dstIp,
            'result'      => $this->result?->value,
            'raw_message' => $this->rawMessage,
            'details'     => json_encode($this->details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
            'dedup_key'   => $this->dedupKey,
        ];
    }
}
