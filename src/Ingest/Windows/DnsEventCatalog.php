<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Windows;

use LogWarden\Event\EventResult;

/**
 * Event ids of the Windows DNS server channels.
 *
 * ### Read this before trusting the numbers
 *
 * These come from Microsoft's documentation of the DNS audit channel, **not**
 * from a domain controller this code has ever talked to — there was no Windows
 * system available while it was written, and docs/dns.md says so. Microsoft has
 * also changed parts of the range between server versions.
 *
 * The normaliser therefore does not depend on this table to work: an id that
 * is not listed is still collected and stored, labelled with its number. The
 * catalogue only supplies a better label and the right outcome when it
 * recognises something. `bin/logwarden-winrm --discover=<Quelle>` reads what a
 * real channel actually contains and prints it, which is how the list gets
 * confirmed or corrected in a given estate.
 *
 * That asymmetry is deliberate. Cisco drops what it does not recognise,
 * because an ASA emits a flood; the DNS audit channel is tiny — on a quiet day
 * it writes nothing at all — so dropping an unrecognised change would mean
 * losing exactly the rare event the channel exists for.
 */
final class DnsEventCatalog
{
    public const CAT_ZONE    = 'zone';
    public const CAT_RECORD  = 'record';
    public const CAT_CONFIG  = 'config';
    public const CAT_SERVICE = 'service';

    /** id => [label, category, result] */
    private const AUDIT = [
        // --- Zonen ------------------------------------------------------------
        513 => ['Zone angelegt',                        self::CAT_ZONE,   'success'],
        514 => ['Zone gelöscht',                        self::CAT_ZONE,   'success'],
        515 => ['Zone angehalten',                      self::CAT_ZONE,   'success'],
        516 => ['Zone fortgesetzt',                     self::CAT_ZONE,   'success'],
        517 => ['Zone neu geladen',                     self::CAT_ZONE,   'info'],
        518 => ['Zone aktualisiert',                    self::CAT_ZONE,   'info'],
        519 => ['Zone aus dem Verzeichnis aktualisiert', self::CAT_ZONE,  'info'],
        520 => ['Zone zurückgeschrieben',               self::CAT_ZONE,   'info'],
        521 => ['Zonentyp geändert',                    self::CAT_ZONE,   'success'],
        522 => ['Zonentransfer-Einstellungen geändert', self::CAT_CONFIG, 'success'],
        523 => ['Scavenging-Server geändert',           self::CAT_CONFIG, 'success'],
        524 => ['Alterung der Zone geändert',           self::CAT_CONFIG, 'success'],
        525 => ['Master-Server der Zone geändert',      self::CAT_CONFIG, 'success'],
        526 => ['Weiterleitung der Zone geändert',      self::CAT_CONFIG, 'success'],

        // --- Records ------------------------------------------------------------
        540 => ['RRSet gelöscht',                       self::CAT_RECORD, 'success'],
        541 => ['Knoten gelöscht',                      self::CAT_RECORD, 'success'],
        542 => ['Record angelegt',                      self::CAT_RECORD, 'success'],
        543 => ['Record gelöscht',                      self::CAT_RECORD, 'success'],
        544 => ['Record per dynamischem Update angelegt',  self::CAT_RECORD, 'success'],
        545 => ['Record per dynamischem Update gelöscht',  self::CAT_RECORD, 'success'],

        // --- Serverkonfiguration --------------------------------------------------
        560 => ['Serverkonfiguration geändert',         self::CAT_CONFIG, 'success'],
        561 => ['Root-Hints geändert',                  self::CAT_CONFIG, 'success'],
        562 => ['Weiterleitungen geändert',             self::CAT_CONFIG, 'success'],
        563 => ['Scavenging-Einstellungen geändert',    self::CAT_CONFIG, 'success'],
    ];

    /** The classic "DNS Server" event log: the service, not the data. */
    private const SERVER = [
        2    => ['DNS-Dienst gestartet',                self::CAT_SERVICE, 'info'],
        3    => ['DNS-Dienst beendet',                  self::CAT_SERVICE, 'info'],
        4    => ['DNS-Dienst heruntergefahren',         self::CAT_SERVICE, 'info'],
        111  => ['Zone konnte nicht geladen werden',    self::CAT_SERVICE, 'fail'],
        150  => ['Zonendatei fehlerhaft',               self::CAT_SERVICE, 'fail'],
        408  => ['DNS-Server antwortet nicht',          self::CAT_SERVICE, 'fail'],
        4000 => ['Verzeichnisdienst nicht erreichbar',  self::CAT_SERVICE, 'fail'],
        4007 => ['Zone konnte nicht aus dem Verzeichnis geladen werden', self::CAT_SERVICE, 'fail'],
        4013 => ['Wartet auf den Verzeichnisdienst',    self::CAT_SERVICE, 'fail'],
        6527 => ['Zonentransfer verweigert',            self::CAT_SERVICE, 'fail'],
    ];

    /** @return array{label: string, category: string, result: ?EventResult}|null */
    public static function describe(int $id, string $channel): ?array
    {
        $table = self::tableFor($channel);
        $entry = $table[$id] ?? null;

        if ($entry === null) {
            return null;
        }

        return [
            'label'    => $entry[0],
            'category' => $entry[1],
            'result'   => $entry[2] === null ? null : EventResult::from($entry[2]),
        ];
    }

    /**
     * The security-relevant subset.
     *
     * Everything here answers a question somebody asks after an incident:
     * who opened zone transfers, who switched on unsecured dynamic updates,
     * who removed a record, who redirected resolution to a foreign forwarder.
     *
     * @return list<int>
     */
    public static function notableIds(): array
    {
        return [513, 514, 521, 522, 523, 524, 525, 526, 540, 541, 542, 543, 560, 561, 562, 563];
    }

    public static function isNotable(int $id): bool
    {
        return in_array($id, self::notableIds(), true);
    }

    public static function categoryLabel(string $category): string
    {
        return match ($category) {
            self::CAT_ZONE    => 'Zonen',
            self::CAT_RECORD  => 'Records',
            self::CAT_CONFIG  => 'Konfiguration',
            self::CAT_SERVICE => 'Dienst',
            default           => $category,
        };
    }

    public static function isAuditChannel(string $channel): bool
    {
        return stripos($channel, 'DNSServer/Audit') !== false;
    }

    public static function isDnsChannel(string $channel): bool
    {
        return self::isAuditChannel($channel)
            || stripos($channel, 'DNSServer') !== false
            || strcasecmp(trim($channel), 'DNS Server') === 0;
    }

    /** @return array<int, array{0: string, 1: string, 2: ?string}> */
    private static function tableFor(string $channel): array
    {
        return self::isAuditChannel($channel) ? self::AUDIT : self::SERVER;
    }

    /**
     * Everything the catalogue claims to know, for the settings page.
     *
     * @return array<string, list<array{id: int, label: string, notable: bool}>>
     */
    public static function grouped(string $channel): array
    {
        $out = [];

        foreach (self::tableFor($channel) as $id => $entry) {
            $out[$entry[1]][] = [
                'id'      => $id,
                'label'   => $entry[0],
                'notable' => self::isNotable($id),
            ];
        }

        foreach ($out as &$group) {
            usort($group, static fn (array $a, array $b): int => $a['id'] <=> $b['id']);
        }

        return $out;
    }
}
