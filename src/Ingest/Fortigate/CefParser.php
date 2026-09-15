<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Fortigate;

/**
 * ArcSight Common Event Format parser.
 *
 *   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key=value
 *
 * The header uses `\|` and `\\` escapes; the extension uses `\=` and `\\`, and
 * values may contain spaces. That last part is why the extension cannot simply
 * be exploded on whitespace: the only reliable delimiter is the next `key=`.
 */
final class CefParser
{
    public static function looksLikeCef(string $line): bool
    {
        return str_contains($line, 'CEF:');
    }

    /**
     * @return array{
     *     version:int, vendor:string, product:string, device_version:string,
     *     signature_id:string, name:string, severity:string,
     *     extensions:array<string,string>
     * }|null
     */
    public function parse(string $line): ?array
    {
        $start = strpos($line, 'CEF:');
        if ($start === false) {
            return null;
        }

        $body = substr($line, $start + 4);

        // Split the seven header fields on unescaped pipes.
        $fields   = [];
        $current  = '';
        $length   = strlen($body);
        $offset   = 0;

        while ($offset < $length && count($fields) < 7) {
            $char = $body[$offset];

            if ($char === '\\' && $offset + 1 < $length) {
                $current .= $body[$offset + 1];
                $offset  += 2;
                continue;
            }
            if ($char === '|') {
                $fields[] = $current;
                $current  = '';
                $offset++;
                continue;
            }

            $current .= $char;
            $offset++;
        }

        if (count($fields) < 7) {
            return null;
        }

        return [
            'version'        => (int) $fields[0],
            'vendor'         => $fields[1],
            'product'        => $fields[2],
            'device_version' => $fields[3],
            'signature_id'   => $fields[4],
            'name'           => $fields[5],
            'severity'       => $fields[6],
            'extensions'     => $this->parseExtensions(substr($body, $offset)),
        ];
    }

    /**
     * @return array<string, string>
     */
    public function parseExtensions(string $extension): array
    {
        // Key boundaries are "start-or-whitespace, key, unescaped =".
        $pattern = '/(?:^|\s)([A-Za-z][A-Za-z0-9_.\-]*)(?<!\\\\)=/';

        if (preg_match_all($pattern, $extension, $matches, PREG_OFFSET_CAPTURE) === 0) {
            return [];
        }

        $result = [];
        $count  = count($matches[0]);

        for ($i = 0; $i < $count; $i++) {
            $key        = $matches[1][$i][0];
            $valueStart = $matches[0][$i][1] + strlen($matches[0][$i][0]);
            $valueEnd   = $i + 1 < $count ? $matches[0][$i + 1][1] : strlen($extension);

            $result[$key] = $this->unescape(trim(substr($extension, $valueStart, $valueEnd - $valueStart)));
        }

        // CEF carries custom fields as csN with a matching csNLabel. Resolving
        // them here means downstream code sees the vendor's own field names.
        return $this->resolveCustomLabels($result);
    }

    /** @param array<string,string> $fields @return array<string,string> */
    private function resolveCustomLabels(array $fields): array
    {
        foreach ($fields as $key => $value) {
            if (!str_ends_with($key, 'Label')) {
                continue;
            }

            $target = substr($key, 0, -5);
            if (isset($fields[$target]) && $value !== '') {
                $fields[$value] = $fields[$target];
                unset($fields[$key], $fields[$target]);
            }
        }

        return $fields;
    }

    private function unescape(string $value): string
    {
        return strtr($value, [
            '\\\\' => '\\',
            '\\='  => '=',
            '\\|'  => '|',
            '\\n'  => "\n",
            '\\r'  => "\r",
        ]);
    }
}
