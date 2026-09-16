<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Dhcp;

use LogWarden\Event\EventResult;

/**
 * Event ids of the Windows DHCP server audit log.
 *
 * Unlike the DNS catalogue, these are not guesswork: the DHCP server writes
 * the list into the header of every log file it produces, so the numbers are
 * self-documenting on any Windows version. `DhcpCsvParser` reads that header
 * and `bin/logwarden-dhcp --header` prints it, which is how a version that
 * added an id makes itself known.
 */
final class DhcpEventCatalog
{
    public const CAT_LEASE   = 'lease';
    public const CAT_POOL    = 'pool';
    public const CAT_DNS     = 'dns';
    public const CAT_ROGUE   = 'rogue';
    public const CAT_SERVICE = 'service';

    /** id => [label, category, result, default-on] */
    private const EVENTS = [
        '00' => ['Protokoll gestartet',                    self::CAT_SERVICE, 'info',    false],
        '01' => ['Protokoll gestoppt',                     self::CAT_SERVICE, 'info',    true],
        '02' => ['Protokoll pausiert, Speicherplatz knapp', self::CAT_SERVICE, 'fail',   true],

        '10' => ['Adresse vergeben',                       self::CAT_LEASE,   'success', true],
        '11' => ['Lease erneuert',                         self::CAT_LEASE,   'success', true],
        '12' => ['Lease freigegeben',                      self::CAT_LEASE,   'info',    true],
        '13' => ['Adresse bereits im Netz in Benutzung',   self::CAT_LEASE,   'fail',    true],
        '14' => ['Adresspool erschöpft',                   self::CAT_POOL,    'fail',    true],
        '15' => ['Lease verweigert',                       self::CAT_LEASE,   'fail',    true],
        '16' => ['Lease gelöscht',                         self::CAT_LEASE,   'info',    true],
        '17' => ['Lease abgelaufen, DNS-Einträge geblieben', self::CAT_LEASE, 'info',    false],
        '18' => ['Lease abgelaufen, DNS-Einträge entfernt',  self::CAT_LEASE, 'info',    false],

        '20' => ['BOOTP-Adresse vergeben',                 self::CAT_LEASE,   'success', false],
        '21' => ['Dynamische BOOTP-Adresse vergeben',      self::CAT_LEASE,   'success', false],
        '22' => ['BOOTP-Adresspool erschöpft',             self::CAT_POOL,    'fail',    true],
        '23' => ['BOOTP-Adresse nach Prüfung gelöscht',    self::CAT_LEASE,   'info',    false],
        '24' => ['Adressbereinigung begonnen',             self::CAT_SERVICE, 'info',    false],
        '25' => ['Statistik der Adressbereinigung',        self::CAT_SERVICE, 'info',    false],

        '30' => ['DNS-Aktualisierung angefordert',         self::CAT_DNS,     'info',    false],
        '31' => ['DNS-Aktualisierung fehlgeschlagen',      self::CAT_DNS,     'fail',    true],
        '32' => ['DNS-Aktualisierung erfolgreich',         self::CAT_DNS,     'success', false],
        '33' => ['Paket wegen NAP-Richtlinie verworfen',   self::CAT_LEASE,   'fail',    true],
        '34' => ['DNS-Aktualisierung: Warteschlange voll', self::CAT_DNS,     'fail',    true],
        '35' => ['DNS-Aktualisierung fehlgeschlagen',      self::CAT_DNS,     'fail',    true],
        '36' => ['Paket verworfen (Failover-Standby)',     self::CAT_LEASE,   'info',    false],

        // --- Autorisierung im Verzeichnis --------------------------------------
        // Diese Gruppe ist der sicherheitsrelevante Teil des Kanals: sie zeigt,
        // ob ein nicht autorisierter DHCP-Server im Netz Adressen verteilt.
        '50' => ['Domäne nicht erreichbar',                self::CAT_ROGUE,   'fail',    true],
        '51' => ['Autorisierung erfolgreich',              self::CAT_ROGUE,   'success', true],
        '52' => ['Server aktualisiert',                    self::CAT_ROGUE,   'info',    false],
        '53' => ['Zwischengespeicherte Autorisierung',     self::CAT_ROGUE,   'success', false],
        '54' => ['Autorisierung fehlgeschlagen',           self::CAT_ROGUE,   'fail',    true],
        '55' => ['Autorisierung erfolgreich',              self::CAT_ROGUE,   'success', false],
        '56' => ['Autorisierung fehlgeschlagen, Dienst eingestellt', self::CAT_ROGUE, 'fail', true],
        '57' => ['Anderer Server in der Domäne gefunden',  self::CAT_ROGUE,   'info',    true],
        '58' => ['Domäne nicht auffindbar',                self::CAT_ROGUE,   'fail',    true],
        '59' => ['Netzwerkfehler bei der Autorisierung',   self::CAT_ROGUE,   'fail',    true],
        '60' => ['Kein Domänencontroller mit Verzeichnisdienst', self::CAT_ROGUE, 'fail', true],
        '61' => ['Fremder Server derselben Domäne gefunden', self::CAT_ROGUE, 'fail',    true],
        '62' => ['Anderer DHCP-Server gefunden',           self::CAT_ROGUE,   'fail',    true],
        '63' => ['Erkennung nicht autorisierter Server neu gestartet', self::CAT_ROGUE, 'info', false],
        '64' => ['Keine DHCP-fähige Schnittstelle',        self::CAT_ROGUE,   'fail',    true],
    ];

    /** @return array{label: string, category: string, result: ?EventResult}|null */
    public static function describe(string $id): ?array
    {
        $entry = self::EVENTS[self::normaliseId($id)] ?? null;

        if ($entry === null) {
            return null;
        }

        return [
            'label'    => $entry[0],
            'category' => $entry[1],
            'result'   => $entry[2] === null ? null : EventResult::from($entry[2]),
        ];
    }

    public static function knows(string $id): bool
    {
        return isset(self::EVENTS[self::normaliseId($id)]);
    }

    /** @return list<string> */
    public static function defaultIds(): array
    {
        $ids = [];

        foreach (self::EVENTS as $id => $entry) {
            if ($entry[3] === true) {
                // Cast: PHP silently turns a numeric-looking array key into an
                // integer, so '10' comes back as int 10. Everything downstream
                // compares ids as strings — the settings page ticks its boxes
                // with a strict in_array — and a mixed list quietly fails all
                // of those comparisons.
                $ids[] = self::normaliseId((string) $id);
            }
        }

        return $ids;
    }

    /**
     * The ids that carry no security meaning but most of the volume.
     *
     * 10 and 11 are one line per client per lease and renewal — on a site with
     * a few hundred devices that is the bulk of the file. They stay on by
     * default anyway, because they are what makes an address traceable back
     * to a machine hours later, which is the main reason to collect DHCP at
     * all. They are simply the first thing to switch off when volume hurts.
     *
     * @return list<string>
     */
    public static function highVolumeIds(): array
    {
        return ['10', '11', '12', '30', '32'];
    }

    public static function categoryLabel(string $category): string
    {
        return match ($category) {
            self::CAT_LEASE   => 'Leases',
            self::CAT_POOL    => 'Adresspool',
            self::CAT_DNS     => 'DNS-Aktualisierung',
            self::CAT_ROGUE   => 'Autorisierung und Fremdserver',
            self::CAT_SERVICE => 'Dienst',
            default           => $category,
        };
    }

    /**
     * @return array<string, list<array{id: string, label: string, default: bool, volume: bool}>>
     */
    public static function grouped(): array
    {
        $out    = [];
        $volume = self::highVolumeIds();

        foreach (self::EVENTS as $id => $entry) {
            $out[$entry[1]][] = [
                'id'      => self::normaliseId((string) $id),
                'label'   => $entry[0],
                'default' => $entry[3],
                'volume'  => in_array($id, $volume, true),
            ];
        }

        return $out;
    }

    /** The log writes single-digit ids as "00".."09"; callers may pass either. */
    public static function normaliseId(string $id): string
    {
        $id = trim($id);

        return strlen($id) === 1 ? '0' . $id : $id;
    }
}
