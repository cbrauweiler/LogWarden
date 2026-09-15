<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Syslog;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Parses the syslog envelope (RFC 3164 and RFC 5424).
 *
 * Deliberately forgiving: a FortiGate configured for "FortiAnalyzer format"
 * sends `<189>date=... time=...` with no header at all, and appliances in
 * general are casual about the spec. Anything that cannot be parsed is handed
 * on as content rather than dropped, because a log line nobody can read is
 * still better than a log line nobody has.
 */
final class SyslogParser
{
    private const RFC3164_MONTHS = [
        'Jan' => 1, 'Feb' => 2, 'Mar' => 3, 'Apr' => 4,  'May' => 5,  'Jun' => 6,
        'Jul' => 7, 'Aug' => 8, 'Sep' => 9, 'Oct' => 10, 'Nov' => 11, 'Dec' => 12,
    ];

    public function parse(string $line, ?string $peer = null, ?DateTimeImmutable $now = null): SyslogMessage
    {
        $raw       = rtrim($line, "\r\n\0");
        $remainder = $raw;
        $facility  = null;
        $severity  = null;

        if (preg_match('/^<(\d{1,3})>/', $remainder, $m) === 1) {
            $pri = (int) $m[1];
            if ($pri <= 191) {
                $facility  = intdiv($pri, 8);
                $severity  = $pri % 8;
                $remainder = substr($remainder, strlen($m[0]));
            }
        }

        // RFC 5424: "1 2026-09-15T10:00:01.123+02:00 host app procid msgid ..."
        if (preg_match('/^1 (\S+) (\S+) (\S+) (\S+) (\S+) /', $remainder, $m) === 1) {
            $timestamp = $this->parseIso($m[1]);
            $rest      = substr($remainder, strlen($m[0]));
            $rest      = $this->stripStructuredData($rest);

            return new SyslogMessage(
                raw:       $raw,
                content:   $rest,
                facility:  $facility,
                severity:  $severity,
                timestamp: $timestamp,
                hostname:  $m[2] === '-' ? null : $m[2],
                appName:   $m[3] === '-' ? null : $m[3],
                peer:      $peer,
            );
        }

        // RFC 3164: "Sep 15 10:00:01 hostname tag: message"
        if (preg_match('/^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (?:(\S+) )?/', $remainder, $m) === 1) {
            $timestamp = $this->parseBsd($m[1], (int) $m[2], (int) $m[3], (int) $m[4], (int) $m[5], $now);
            $rest      = substr($remainder, strlen($m[0]));
            $hostname  = $m[6] ?? null;
            $appName   = null;

            if (preg_match('/^([A-Za-z0-9_\/\.\-]{1,48})(?:\[\d+\])?:\s*/', $rest, $tag) === 1) {
                $appName = $tag[1];
                $rest    = substr($rest, strlen($tag[0]));
            }

            return new SyslogMessage(
                raw:       $raw,
                content:   $rest,
                facility:  $facility,
                severity:  $severity,
                timestamp: $timestamp,
                hostname:  $hostname,
                appName:   $appName,
                peer:      $peer,
            );
        }

        // No recognisable header — the payload starts right after the priority.
        return new SyslogMessage(
            raw:      $raw,
            content:  $remainder,
            facility: $facility,
            severity: $severity,
            peer:     $peer,
        );
    }

    private function parseIso(string $value): ?DateTimeImmutable
    {
        if ($value === '-') {
            return null;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * RFC 3164 timestamps carry no year and no zone. We assume the collector's
     * clock is right and interpret the value as UTC; if that lands more than a
     * day in the future it must belong to the previous year (a line received
     * on 1 January that was stamped in December).
     */
    private function parseBsd(
        string $month,
        int $day,
        int $hour,
        int $minute,
        int $second,
        ?DateTimeImmutable $now,
    ): ?DateTimeImmutable {
        $monthNum = self::RFC3164_MONTHS[$month] ?? null;
        if ($monthNum === null) {
            return null;
        }

        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $year  = (int) $now->format('Y');

        $candidate = DateTimeImmutable::createFromFormat(
            'Y-n-j H:i:s',
            sprintf('%d-%d-%d %02d:%02d:%02d', $year, $monthNum, $day, $hour, $minute, $second),
            new DateTimeZone('UTC'),
        );

        if ($candidate === false) {
            return null;
        }

        if ($candidate->getTimestamp() - $now->getTimestamp() > 86400) {
            $candidate = $candidate->modify('-1 year') ?: $candidate;
        }

        return $candidate;
    }

    /**
     * Drop RFC 5424 structured data ("[id key="value"]...") ahead of the
     * message. FortiGate does not emit it, but collectors in front of it do.
     */
    private function stripStructuredData(string $rest): string
    {
        if ($rest === '' || $rest[0] !== '[') {
            return str_starts_with($rest, '- ') ? substr($rest, 2) : $rest;
        }

        $length   = strlen($rest);
        $offset   = 0;
        $inQuotes = false;

        while ($offset < $length) {
            $char = $rest[$offset];

            if ($char === '\\' && $inQuotes) {
                $offset += 2;
                continue;
            }
            if ($char === '"') {
                $inQuotes = !$inQuotes;
            } elseif ($char === ']' && !$inQuotes) {
                // End of one SD element; another may follow immediately.
                if (($rest[$offset + 1] ?? '') !== '[') {
                    return ltrim(substr($rest, $offset + 1));
                }
            }
            $offset++;
        }

        return $rest;
    }
}
