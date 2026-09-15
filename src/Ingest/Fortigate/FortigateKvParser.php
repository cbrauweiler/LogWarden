<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Fortigate;

/**
 * Parser for FortiOS native syslog, which is a flat list of key=value pairs:
 *
 *   date=2026-09-15 time=10:00:01 devname="FGT-01" logid="0101039426"
 *   type="event" subtype="vpn" action="tunnel-up" remip=203.0.113.9 user="jdoe"
 *
 * Quoted values may contain spaces and `\"` escapes; unquoted values run to the
 * next space.
 */
final class FortigateKvParser
{
    private const PATTERN = '/([A-Za-z0-9_.\-]+)=("(?:[^"\\\\]|\\\\.)*"|[^\s]*)/';

    public static function looksLikeFortigate(string $line): bool
    {
        // `devname=` and `logid=` are present on every FortiOS log line and
        // are specific enough not to collide with other appliances.
        return str_contains($line, 'devname=')
            || str_contains($line, 'logid=')
            || (str_contains($line, 'date=') && str_contains($line, 'devid='));
    }

    /** @return array<string, string> */
    public function parse(string $line): array
    {
        if (preg_match_all(self::PATTERN, $line, $matches, PREG_SET_ORDER) === 0) {
            return [];
        }

        $result = [];
        foreach ($matches as $match) {
            $value = $match[2];

            if (strlen($value) >= 2 && $value[0] === '"' && str_ends_with($value, '"')) {
                // Only `\"` and `\\` are escapes here. stripcslashes() would also
                // interpret C sequences, turning the very common DOMAIN\asmith
                // into DOMAIN<BEL>smith.
                $value = preg_replace('/\\\\(["\\\\])/', '$1', substr($value, 1, -1)) ?? '';
            }

            // FortiOS writes N/A for "field not applicable here". Keeping it
            // would make every unrelated event look like it had a value.
            $result[$match[1]] = ($value === 'N/A') ? '' : $value;
        }

        return $result;
    }
}
