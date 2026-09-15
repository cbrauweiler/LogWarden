<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Syslog;

use DateTimeImmutable;

/**
 * A syslog envelope with its payload separated out.
 */
final class SyslogMessage
{
    public function __construct(
        public readonly string $raw,
        public readonly string $content,
        public readonly ?int $facility = null,
        public readonly ?int $severity = null,
        public readonly ?DateTimeImmutable $timestamp = null,
        public readonly ?string $hostname = null,
        public readonly ?string $appName = null,
        public readonly ?string $peer = null,
    ) {
    }
}
