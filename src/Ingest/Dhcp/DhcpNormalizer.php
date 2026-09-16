<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Dhcp;

use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\NormalizerInterface;
use LogWarden\Event\SourceType;

/**
 * Turns a line of the Windows DHCP audit log into an Event.
 *
 * ### What DHCP is for here
 *
 * Individually, "lease renewed" answers nothing. What makes the channel worth
 * collecting is attribution: three weeks later a FortiGate log says
 * 10.20.30.44 did something, and the only thing that can still say *which
 * machine that was* is the lease. So the host name and the MAC address are
 * the point of every record, and the summary line is built around them.
 *
 * ### The date trap
 *
 * The log writes dates in the server's locale — `09/16/26` on an English
 * install, `16.09.26` on a German one — and `05/06/26` is ambiguous between
 * them. Guessing from here would put events on the wrong day for half the
 * year. The collector therefore has PowerShell resolve the timestamp on the
 * server, where the culture is known, and sends it along; {@see timestamp}
 * only falls back to guessing for a file imported by hand, and refuses the
 * ambiguous case rather than inventing a day.
 */
final class DhcpNormalizer implements NormalizerInterface
{
    public function __construct(
        private readonly string $sourceHost,
        private readonly ?DhcpCsvParser $parser = null,
        /** @var list<string> */
        private readonly array $onlyIds = [],
    ) {
    }

    public function supports(string $raw, array $context = []): bool
    {
        $trimmed = ltrim($raw);

        if ($trimmed === '') {
            return false;
        }

        // Either the NDJSON envelope the collector produces, or a bare CSV line
        // from a file somebody copied off the server.
        return ($trimmed[0] === '{' && str_contains($trimmed, '"l"'))
            || DhcpCsvParser::isDataRow($trimmed);
    }

    /** @return list<Event> */
    public function normalize(string $raw, array $context = []): array
    {
        [$line, $isoTs, $host] = $this->unwrap(trim($raw));

        if ($line === null) {
            return [];
        }

        $parser = $this->parser ?? new DhcpCsvParser();
        $fields = $parser->parse($line);

        if ($fields === null) {
            return [];
        }

        $id = str_pad(trim($fields['ID'] ?? ''), 2, '0', STR_PAD_LEFT);

        if ($id === '' || ($this->onlyIds !== [] && !in_array($id, $this->onlyIds, true))) {
            return [];
        }

        $ts = $this->timestamp($isoTs, $fields);

        if ($ts === null) {
            return [];
        }

        $meaning  = DhcpEventCatalog::describe($id);
        $label    = $meaning['label']    ?? $this->fallbackLabel($id, $fields);
        $category = $meaning['category'] ?? 'sonstige';

        $ip       = Event::normaliseIp($fields['IP Address'] ?? null);
        $hostName = $this->clean($fields['Host Name'] ?? null);
        $mac      = $this->mac($fields['MAC Address'] ?? null);
        $user     = Event::normaliseUsername($fields['User Name'] ?? null);

        return [new Event(
            ts:         $ts,
            sourceType: SourceType::of('dhcp'),
            sourceHost: $host ?? $this->sourceHost,
            eventType:  $id,
            rawMessage: $this->summary($id, $label, $ip, $hostName, $mac, $fields),
            username:   $user,
            // The leased address is the subject of the record, so it goes in
            // src_ip — that is the column a search for an address looks at.
            srcIp:      $ip,
            dstIp:      null,
            result:     $meaning['result'] ?? EventResult::Info,
            details:    $this->details($id, $label, $category, $hostName, $mac, $fields),
            dedupKey:   $this->dedupKey($host ?? $this->sourceHost, $ts, $line),
        )];
    }

    /**
     * @return array{0: ?string, 1: ?string, 2: ?string}  line, ISO timestamp, host
     */
    private function unwrap(string $raw): array
    {
        if ($raw === '' || $raw[0] !== '{') {
            return [$raw, null, null];
        }

        $record = json_decode($raw, true);

        if (!is_array($record) || !isset($record['l']) || !is_string($record['l'])) {
            return [null, null, null];
        }

        return [
            $record['l'],
            isset($record['t']) && is_string($record['t']) ? $record['t'] : null,
            isset($record['c']) && is_string($record['c']) && trim($record['c']) !== ''
                ? Event::sanitiseText(trim($record['c']), 255)
                : null,
        ];
    }

    /**
     * Identity of a record.
     *
     * The audit log has no record id, so the line itself is the identity.
     * Two byte-identical lines within the same second would collapse into one
     * event — an acceptable loss, and the price of being able to re-read an
     * overlapping window without duplicating everything in it.
     */
    private function dedupKey(string $host, DateTimeImmutable $ts, string $line): string
    {
        return substr(hash('sha256', implode("\0", [
            'dhcp',
            strtolower($host),
            $ts->format('Y-m-d\TH:i:s'),
            trim($line),
        ])), 0, 40);
    }

    /** @param array<string, string> $fields */
    private function details(
        string $id,
        string $label,
        string $category,
        ?string $hostName,
        ?string $mac,
        array $fields,
    ): array {
        $details = [
            'label'    => $label,
            'category' => $category,
        ];

        if ($hostName !== null) {
            $details['hostname'] = $hostName;
        }

        if ($mac !== null) {
            $details['mac'] = $mac;
            // The first three octets identify the manufacturer. Kept separate
            // because "every lease from this vendor prefix" is a question one
            // asks when hunting for a rogue device.
            $details['mac_oui'] = substr($mac, 0, 8);
        }

        foreach ([
            'Description'           => 'description',
            'TransactionID'         => 'transaction_id',
            'QResult'               => 'nap_result',
            'CorrelationID'         => 'correlation_id',
            'VendorClass(ASCII)'    => 'vendor_class',
            'UserClass(ASCII)'      => 'user_class',
            'RelayAgentInformation' => 'relay_agent',
            'DnsRegError'           => 'dns_error',
        ] as $source => $target) {
            $value = $this->clean($fields[$source] ?? null);

            if ($value !== null && $value !== '0') {
                $details[$target] = Event::sanitiseText($value, 255);
            }
        }

        return $details;
    }

    /**
     * `10.20.30.44 an WS-ASMITH (A0-B1-C2-D3-E4-F5)` — the attribution, first.
     *
     * @param array<string, string> $fields
     */
    private function summary(string $id, string $label, ?string $ip, ?string $host, ?string $mac, array $fields): string
    {
        $parts = [$label];

        if ($ip !== null) {
            $parts[] = $ip;
        }

        if ($host !== null) {
            $parts[] = 'an ' . $host;
        }

        if ($mac !== null) {
            $parts[] = '(' . $mac . ')';
        }

        // For the authorisation events there is no lease at all; the
        // description is the whole content.
        if ($ip === null && $host === null) {
            $description = $this->clean($fields['Description'] ?? null);

            if ($description !== null && $description !== $label) {
                $parts[] = '— ' . $description;
            }
        }

        return Event::sanitiseText(sprintf('[%s] %s', $id, implode(' ', $parts)), 2000);
    }

    /** @param array<string, string> $fields */
    private function fallbackLabel(string $id, array $fields): string
    {
        // The server writes a description on every row, so an id the catalogue
        // does not know still arrives with Microsoft's own wording.
        return $this->clean($fields['Description'] ?? null) ?? ('DHCP-Ereignis ' . $id);
    }

    /** `A0B1C2D3E4F5` → `A0-B1-C2-D3-E4-F5`, which is how Windows shows it elsewhere. */
    private function mac(?string $value): ?string
    {
        $value = $this->clean($value);

        if ($value === null) {
            return null;
        }

        $hex = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $value) ?? '');

        if (strlen($hex) !== 12) {
            return $value === '' ? null : Event::sanitiseText($value, 64);
        }

        return implode('-', str_split($hex, 2));
    }

    /**
     * @param array<string, string> $fields
     */
    private function timestamp(?string $iso, array $fields): ?DateTimeImmutable
    {
        if ($iso !== null) {
            $parsed = $this->parseIso($iso);

            if ($parsed !== null) {
                return $parsed;
            }
        }

        $date = $this->clean($fields['Date'] ?? null);
        $time = $this->clean($fields['Time'] ?? null);

        if ($date === null || $time === null) {
            return null;
        }

        return $this->guessLocalDate($date, $time);
    }

    private function parseIso(string $value): ?DateTimeImmutable
    {
        if (preg_match(
            '/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$/',
            trim($value),
            $m,
        ) !== 1) {
            return null;
        }

        $offset = $m[4] ?? 'Z';
        $offset = ($offset === 'Z' || $offset === '') ? '+0000' : str_replace(':', '', $offset);

        $parsed = DateTimeImmutable::createFromFormat(
            'Y-m-d H:i:s.uO',
            sprintf('%s %s.%s%s', $m[1], $m[2], str_pad(substr($m[3] ?? '', 0, 6), 6, '0'), $offset),
            new DateTimeZone('UTC'),
        );

        return $parsed === false ? null : $parsed->setTimezone(new DateTimeZone('UTC'));
    }

    /**
     * Last resort for a file imported by hand, where nothing resolved the
     * server's locale.
     *
     * `16.09.26` and `09/16/26` are both unambiguous — one component exceeds
     * twelve. `05/06/26` is not, and rather than putting the event on the
     * wrong day for half the year, it is refused.
     */
    private function guessLocalDate(string $date, string $time): ?DateTimeImmutable
    {
        // Year first is unambiguous by construction, and a server whose short
        // date format is ISO writes exactly that.
        if (preg_match('/^(\d{4})[.\/-](\d{1,2})[.\/-](\d{1,2})$/', $date, $m) === 1) {
            return $this->build((int) $m[1], (int) $m[2], (int) $m[3], $time);
        }

        if (preg_match('/^(\d{1,2})[.\/-](\d{1,2})[.\/-](\d{2,4})$/', $date, $m) !== 1) {
            return null;
        }

        [$first, $second, $year] = [(int) $m[1], (int) $m[2], (int) $m[3]];

        if ($year < 100) {
            $year += 2000;
        }

        if ($first > 12 && $second <= 12) {
            [$day, $month] = [$first, $second];       // 16.09.26
        } elseif ($second > 12 && $first <= 12) {
            [$day, $month] = [$second, $first];       // 09/16/26
        } else {
            return null;                              // 05/06/26 — undecidable
        }

        return $this->build($year, $month, $day, $time);
    }

    private function build(int $year, int $month, int $day, string $time): ?DateTimeImmutable
    {
        if ($month < 1 || $month > 12 || $day < 1 || $day > 31) {
            return null;
        }

        $parsed = DateTimeImmutable::createFromFormat(
            'Y-n-j H:i:s',
            sprintf('%04d-%d-%d %s', $year, $month, $day, $time),
            new DateTimeZone('UTC'),
        );

        return $parsed === false ? null : $parsed;
    }

    private function clean(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = trim($value);

        return ($value === '' || $value === '-') ? null : Event::sanitiseText($value, 255);
    }
}
