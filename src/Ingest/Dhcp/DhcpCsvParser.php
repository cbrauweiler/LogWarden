<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Dhcp;

/**
 * Splits a line of `DhcpSrvLog-<Tag>.log` into named columns.
 *
 * The file is not plain CSV. It opens with roughly thirty lines of prose that
 * document the event ids, then a blank line, then the column header, then the
 * data. The header has to be found rather than assumed, because its column
 * count has grown between Windows versions — 2008 wrote eleven columns, 2016
 * and later write nineteen. Positional parsing against a fixed list would
 * therefore silently shift every field on the older or newer of the two.
 */
final class DhcpCsvParser
{
    /**
     * The columns as Windows Server 2016 and later name them. Used only when a
     * caller hands over data without its header — normally the header from the
     * file itself decides.
     */
    public const DEFAULT_COLUMNS = [
        'ID', 'Date', 'Time', 'Description', 'IP Address', 'Host Name', 'MAC Address',
        'User Name', 'TransactionID', 'QResult', 'Probationtime', 'CorrelationID',
        'Dhcid', 'VendorClass(Hex)', 'VendorClass(ASCII)', 'UserClass(Hex)',
        'UserClass(ASCII)', 'RelayAgentInformation', 'DnsRegError',
    ];

    /** @var list<string> */
    private array $columns;

    /** @param list<string>|null $columns */
    public function __construct(?array $columns = null)
    {
        $this->columns = $columns ?? self::DEFAULT_COLUMNS;
    }

    /**
     * Recognises the header row of a DHCP audit log.
     *
     * Matched on the first three columns rather than the whole line, so that a
     * version with extra columns is still recognised as a header instead of
     * being parsed as data.
     */
    public static function isHeaderRow(string $line): bool
    {
        $fields = str_getcsv(trim($line), ',', '"', '\\');

        return count($fields) >= 3
            && strcasecmp(trim($fields[0]), 'ID') === 0
            && strcasecmp(trim($fields[1]), 'Date') === 0
            && strcasecmp(trim($fields[2]), 'Time') === 0;
    }

    /** @return list<string> */
    public static function columnsFrom(string $headerLine): array
    {
        return array_map(
            static fn (string $c): string => trim($c),
            str_getcsv(trim($headerLine), ',', '"', '\\'),
        );
    }

    public static function fromHeaderLine(string $headerLine): self
    {
        return new self(self::columnsFrom($headerLine));
    }

    /**
     * True for a line that carries an event rather than prose.
     *
     * The documentation block at the top of the file is indented text, some of
     * which begins with a number — "10  A new IP address was leased..." — so
     * "starts with digits" is not enough. A data row has the id followed
     * immediately by a comma and then a date.
     */
    public static function isDataRow(string $line): bool
    {
        // The separator is part of the server's locale: 09/16/26 on an English
        // install, 16.09.26 on a German one, 2026-09-16 where ISO is set. An
        // expression that accepted only slashes treated every line of a German
        // server's log as prose — the source would have collected nothing at
        // all, and reported success while doing it.
        return preg_match('/^\s*\d{1,2},\s*\d{1,4}[.\/-]\d{1,2}[.\/-]\d{1,4},/', $line) === 1;
    }

    /**
     * @return array<string, string>|null  null when the line is not a data row
     */
    public function parse(string $line): ?array
    {
        $line = rtrim($line, "\r\n");

        if (!self::isDataRow($line)) {
            return null;
        }

        $fields = str_getcsv($line, ',', '"', '\\');
        $out    = [];

        foreach ($fields as $index => $value) {
            $name = $this->columns[$index] ?? ('column_' . $index);
            $value = is_string($value) ? trim($value) : '';

            if ($value !== '') {
                $out[$name] = $value;
            }
        }

        return $out === [] ? null : $out;
    }

    /** @return list<string> */
    public function columns(): array
    {
        return $this->columns;
    }
}
