<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Windows;

use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\NormalizerInterface;
use LogWarden\Event\SourceType;

/**
 * Turns a record from the Windows DNS server channels into an Event.
 *
 * Separate from AdNormalizer because almost nothing carries over. DNS audit
 * events have no logon type, no NTSTATUS, no SID of a target account; they
 * have a zone, a node name, a record type and a record value. Running them
 * through the AD normaliser produced lines like "Ereignis 542" with an empty
 * user — technically stored, practically useless.
 *
 * What an administrator wants out of this channel is a change log: who
 * changed which record in which zone, and when. That is what the summary line
 * is built to be.
 */
final class DnsNormalizer implements NormalizerInterface
{
    /**
     * Fields the DNS channels use, in the order they are tried.
     *
     * Microsoft spells the acting account differently per event; the zone
     * appears as `Zone` in audit events and as `ZoneName` in some of the
     * service ones.
     */
    private const USER_FIELDS = ['User', 'UserName', 'ClientUserName', 'SubjectUserName'];
    private const ZONE_FIELDS = ['Zone', 'ZoneName', 'ZoneScope'];
    private const NODE_FIELDS = ['NodeName', 'Name', 'RecordName', 'OwnerName'];

    public function __construct(
        private readonly string $sourceHost,
        private readonly string $channel = 'Microsoft-Windows-DNSServer/Audit',
        private readonly bool $includeRoutine = true,
    ) {
    }

    public function supports(string $raw, array $context = []): bool
    {
        $trimmed = ltrim($raw);

        return $trimmed !== '' && $trimmed[0] === '{' && str_contains($trimmed, '"r"');
    }

    /** @return list<Event> */
    public function normalize(string $raw, array $context = []): array
    {
        $record = json_decode(trim($raw), true);

        if (!is_array($record) || !isset($record['i'], $record['t'], $record['r'])
            || !is_numeric($record['i']) || !is_string($record['t'])) {
            return [];
        }

        $id      = (int) $record['i'];
        $data    = is_array($record['d'] ?? null) ? $record['d'] : [];
        $meaning = DnsEventCatalog::describe($id, $this->channel);

        // Unknown ids are kept, not dropped — see the note in DnsEventCatalog.
        $label    = $meaning['label']    ?? ('DNS-Ereignis ' . $id);
        $category = $meaning['category'] ?? 'sonstige';

        $ts = $this->timestamp((string) $record['t']);
        if ($ts === null) {
            return [];
        }

        // Zone reloads and write-backs happen continuously on a healthy server
        // and record nobody's decision. They stay available, but a source that
        // only wants the change log can switch them off.
        if (!$this->includeRoutine && in_array($id, [517, 518, 519, 520], true)) {
            return [];
        }

        $zone   = $this->field($data, self::ZONE_FIELDS);
        $node   = $this->field($data, self::NODE_FIELDS);
        $user   = Event::normaliseUsername($this->field($data, self::USER_FIELDS));
        $source = Event::normaliseIp($this->field($data, ['Source', 'ClientIP', 'IPAddress']));

        return [new Event(
            ts:         $ts,
            sourceType: SourceType::of('dns'),
            sourceHost: $this->host($record),
            eventType:  (string) $id,
            rawMessage: $this->summary($id, $label, $zone, $node, $data, $user, $source),
            username:   $user,
            srcIp:      $source,
            dstIp:      null,
            result:     $meaning['result'] ?? EventResult::Info,
            details:    $this->details($id, $label, $category, $zone, $node, $data, $record),
            dedupKey:   $this->dedupKey($record),
        )];
    }

    /** @return array<string, mixed> */
    private function details(
        int $id,
        string $label,
        string $category,
        ?string $zone,
        ?string $node,
        array $data,
        array $record,
    ): array {
        $details = [
            'label'     => $label,
            'category'  => $category,
            'channel'   => $this->channel,
            'record_id' => (int) $record['r'],
            'notable'   => DnsEventCatalog::isNotable($id),
        ];

        if ($zone !== null) {
            $details['zone'] = Event::sanitiseText($zone, 255);
        }

        if ($node !== null) {
            $details['record'] = Event::sanitiseText($node, 255);
        }

        foreach ([
            'RecordType'       => 'record_type',
            'Type'             => 'record_type',
            'RecordData'       => 'record_data',
            'Data'             => 'record_data',
            'TTL'              => 'ttl',
            'PreviousZoneType' => 'previous_zone_type',
            'NewZoneType'      => 'new_zone_type',
            'Forwarders'       => 'forwarders',
            'SecondaryServers' => 'secondary_servers',
            'VirtualizationID' => 'virtualization_id',
        ] as $source => $target) {
            $value = $this->field($data, [$source]);

            if ($value !== null && !isset($details[$target])) {
                $details[$target] = Event::sanitiseText($value, 512);
            }
        }

        if (!empty($record['p'])) {
            $details['provider'] = Event::sanitiseText((string) $record['p'], 128);
        }

        if (!empty($record['m'])) {
            $details['win_message'] = Event::sanitiseText((string) $record['m'], 4096);
        }

        return $details;
    }

    /**
     * The change-log line.
     *
     *   [542] Record angelegt ws-asmith.corp.local A 10.20.30.44 in "corp.local" durch admin
     *   [522] Zonentransfer-Einstellungen geändert für "corp.local" durch admin
     */
    private function summary(
        int $id,
        string $label,
        ?string $zone,
        ?string $node,
        array $data,
        ?string $user,
        ?string $source,
    ): string {
        $parts = [$label];

        if ($node !== null) {
            $parts[] = $node;

            $type = $this->field($data, ['RecordType', 'Type']);
            if ($type !== null) {
                $parts[] = $type;
            }

            $value = $this->field($data, ['RecordData', 'Data']);
            if ($value !== null) {
                $parts[] = $value;
            }
        }

        if ($zone !== null) {
            $parts[] = ($node === null ? 'für ' : 'in ') . '"' . $zone . '"';
        }

        // The new value is the point of a configuration change. "Weiterleitungen
        // geändert durch jdoe" tells nobody whether resolution now goes
        // somewhere it should not.
        $target = $this->field($data, ['Forwarders', 'SecondaryServers', 'MasterServers', 'ScavengeServers']);
        if ($target !== null) {
            $parts[] = 'auf ' . $target;
        }

        $zoneChange = $this->field($data, ['NewZoneType']);
        if ($zoneChange !== null) {
            $previous = $this->field($data, ['PreviousZoneType']);
            $parts[]  = $previous === null ? ('auf ' . $zoneChange) : sprintf('von %s auf %s', $previous, $zoneChange);
        }

        if ($user !== null) {
            $parts[] = 'durch ' . $user;
        } elseif ($source !== null) {
            // Dynamic updates and refused transfers have no logged-on account;
            // the address is the only actor there is.
            $parts[] = 'von ' . $source;
        }

        return Event::sanitiseText(sprintf('[%d] %s', $id, implode(' ', $parts)), 2000);
    }

    private function dedupKey(array $record): string
    {
        return substr(hash('sha256', implode("\0", [
            'winrm',
            strtolower($this->host($record)),
            strtolower($this->channel),
            (string) $record['r'],
        ])), 0, 40);
    }

    private function host(array $record): string
    {
        $host = trim((string) ($record['c'] ?? ''));

        return $host === '' ? $this->sourceHost : Event::sanitiseText($host, 255);
    }

    /** @param list<string> $names */
    private function field(array $data, array $names): ?string
    {
        foreach ($names as $name) {
            $value = $data[$name] ?? null;

            if (!is_scalar($value)) {
                continue;
            }

            $value = trim((string) $value);

            if ($value !== '' && $value !== '-') {
                return $value;
            }
        }

        return null;
    }

    /** Same strict parse as AdNormalizer; see the note there on why. */
    private function timestamp(string $value): ?DateTimeImmutable
    {
        $matched = preg_match(
            '/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$/',
            trim($value),
            $m,
        );

        if ($matched !== 1) {
            return null;
        }

        $fraction = str_pad(substr($m[3] ?? '', 0, 6), 6, '0');
        $offset   = $m[4] ?? 'Z';
        $offset   = ($offset === 'Z' || $offset === '') ? '+0000' : str_replace(':', '', $offset);

        $parsed = DateTimeImmutable::createFromFormat(
            'Y-m-d H:i:s.uO',
            sprintf('%s %s.%s%s', $m[1], $m[2], $fraction, $offset),
            new DateTimeZone('UTC'),
        );

        return $parsed === false ? null : $parsed->setTimezone(new DateTimeZone('UTC'));
    }
}
