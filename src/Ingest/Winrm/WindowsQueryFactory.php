<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use DateTimeImmutable;
use LogWarden\Ingest\IngestSource;

/**
 * Builds the PowerShell for a source.
 *
 * Event logs and the DHCP audit log are read completely differently — one is
 * a channel with a structured query, the other a localised CSV file on disk —
 * but both fit the same bounded-window contract, which is why they can share
 * the collector, the bookmark and the catch-up logic.
 */
final class WindowsQueryFactory
{
    public static function script(IngestSource $source, DateTimeImmutable $from, DateTimeImmutable $to): string
    {
        if ($source->collector === 'dhcp_csv') {
            return (new DhcpLogQuery(
                (string) $source->setting('log_path', DhcpLogQuery::DEFAULT_PATH),
                array_map('strval', $source->setting('event_ids', []) ?: []),
                (int) $source->setting('max_events', 200000),
                (bool) $source->setting('ipv6', false),
            ))->script($from, $to);
        }

        return (new EventLogQuery(
            $source->channel(),
            $source->eventIds(),
            (bool) $source->setting('include_message', false),
            max(100, (int) $source->setting('max_events', 5000)),
        ))->script($from, $to);
    }
}
