<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Windows;

use LogWarden\Event\EventResult;

/**
 * Which Active Directory Security events LogWarden collects, and what they mean.
 *
 * The catalogue is the volume decision, not just a translation table. A domain
 * controller's Security channel is dominated by a handful of IDs — 4769 alone
 * can be 80% of it — that answer no question anyone asks, while the events
 * that matter most (4740, 4728, 1102) occur a few times a week. Collecting
 * "everything" therefore costs a hundred times the storage for a *worse*
 * signal, because the useful lines drown.
 *
 * `defaultIds()` is the set that stays useful at a volume a small
 * infrastructure can keep for a year. Everything in `optional()` is a
 * deliberate opt-in with a note on what it costs.
 */
final class AdEventCatalog
{
    public const CAT_LOGON      = 'logon';
    public const CAT_KERBEROS   = 'kerberos';
    public const CAT_ACCOUNT    = 'account';
    public const CAT_GROUP      = 'group';
    public const CAT_PRIVILEGE  = 'privilege';
    public const CAT_POLICY     = 'policy';
    public const CAT_AUDIT      = 'audit';

    /**
     * id => [label, category, result, default-on]
     *
     * `result` is what the event says by itself. Events that carry the outcome
     * in a field instead (4768, 4776) are marked null and resolved per record.
     */
    private const EVENTS = [
        // --- Logon ----------------------------------------------------------
        4624 => ['Anmeldung erfolgreich',               self::CAT_LOGON,     'success', true],
        4625 => ['Anmeldung fehlgeschlagen',            self::CAT_LOGON,     'fail',    true],
        4634 => ['Abmeldung',                           self::CAT_LOGON,     'success', false],
        4647 => ['Abmeldung durch Benutzer',            self::CAT_LOGON,     'success', false],
        4648 => ['Anmeldung mit expliziten Anmeldedaten', self::CAT_LOGON,   'success', true],
        4672 => ['Sonderrechte bei Anmeldung zugewiesen', self::CAT_PRIVILEGE, 'success', true],
        4778 => ['Sitzung wiederverbunden',             self::CAT_LOGON,     'success', false],
        4779 => ['Sitzung getrennt',                    self::CAT_LOGON,     'success', false],
        4800 => ['Arbeitsstation gesperrt',             self::CAT_LOGON,     'success', false],
        4801 => ['Arbeitsstation entsperrt',            self::CAT_LOGON,     'success', false],

        // --- Kerberos / NTLM ------------------------------------------------
        4768 => ['Kerberos-TGT angefordert',            self::CAT_KERBEROS,  null,      false],
        4769 => ['Kerberos-Diensticket angefordert',    self::CAT_KERBEROS,  null,      false],
        4771 => ['Kerberos-Pre-Authentication fehlgeschlagen', self::CAT_KERBEROS, 'fail', true],
        4776 => ['NTLM-Anmeldedaten geprüft',           self::CAT_KERBEROS,  null,      true],
        4777 => ['NTLM-Prüfung durch DC fehlgeschlagen', self::CAT_KERBEROS, 'fail',    true],

        // --- Kontoverwaltung -------------------------------------------------
        4720 => ['Benutzerkonto angelegt',              self::CAT_ACCOUNT,   'success', true],
        4722 => ['Benutzerkonto aktiviert',             self::CAT_ACCOUNT,   'success', true],
        4723 => ['Passwortwechsel durch Benutzer',      self::CAT_ACCOUNT,   'success', true],
        4724 => ['Passwort zurückgesetzt',              self::CAT_ACCOUNT,   'success', true],
        4725 => ['Benutzerkonto deaktiviert',           self::CAT_ACCOUNT,   'success', true],
        4726 => ['Benutzerkonto gelöscht',              self::CAT_ACCOUNT,   'success', true],
        4738 => ['Benutzerkonto geändert',              self::CAT_ACCOUNT,   'success', true],
        4740 => ['Konto gesperrt',                      self::CAT_ACCOUNT,   'fail',    true],
        4767 => ['Kontosperre aufgehoben',              self::CAT_ACCOUNT,   'success', true],
        4781 => ['Konto umbenannt',                     self::CAT_ACCOUNT,   'success', true],
        4794 => ['Versuch, das DSRM-Passwort zu setzen', self::CAT_ACCOUNT,  null,      true],

        // --- Gruppenverwaltung ------------------------------------------------
        4727 => ['Globale Sicherheitsgruppe angelegt',  self::CAT_GROUP,     'success', true],
        4728 => ['Mitglied zu globaler Gruppe hinzugefügt', self::CAT_GROUP, 'success', true],
        4729 => ['Mitglied aus globaler Gruppe entfernt',   self::CAT_GROUP, 'success', true],
        4730 => ['Globale Sicherheitsgruppe gelöscht',  self::CAT_GROUP,     'success', true],
        4731 => ['Lokale Sicherheitsgruppe angelegt',   self::CAT_GROUP,     'success', true],
        4732 => ['Mitglied zu lokaler Gruppe hinzugefügt', self::CAT_GROUP,  'success', true],
        4733 => ['Mitglied aus lokaler Gruppe entfernt',   self::CAT_GROUP,  'success', true],
        4734 => ['Lokale Sicherheitsgruppe gelöscht',   self::CAT_GROUP,     'success', true],
        4735 => ['Lokale Sicherheitsgruppe geändert',   self::CAT_GROUP,     'success', true],
        4737 => ['Globale Sicherheitsgruppe geändert',  self::CAT_GROUP,     'success', true],
        4754 => ['Universelle Sicherheitsgruppe angelegt', self::CAT_GROUP,  'success', true],
        4755 => ['Universelle Sicherheitsgruppe geändert', self::CAT_GROUP,  'success', true],
        4756 => ['Mitglied zu universeller Gruppe hinzugefügt', self::CAT_GROUP, 'success', true],
        4757 => ['Mitglied aus universeller Gruppe entfernt',   self::CAT_GROUP, 'success', true],
        4758 => ['Universelle Sicherheitsgruppe gelöscht',      self::CAT_GROUP, 'success', true],

        // --- Richtlinien und Protokoll ----------------------------------------
        4713 => ['Kerberos-Richtlinie geändert',        self::CAT_POLICY,    'success', true],
        4716 => ['Vertrauensstellung geändert',         self::CAT_POLICY,    'success', true],
        4719 => ['Überwachungsrichtlinie geändert',     self::CAT_POLICY,    'success', true],
        4739 => ['Domänenrichtlinie geändert',          self::CAT_POLICY,    'success', true],
        4764 => ['Gruppentyp geändert',                 self::CAT_GROUP,     'success', true],
        1102 => ['Sicherheitsprotokoll gelöscht',       self::CAT_AUDIT,     'success', true],
        4906 => ['CrashOnAuditFail geändert',           self::CAT_AUDIT,     'success', true],

        // --- Verzeichniszugriff -----------------------------------------------
        5136 => ['Verzeichnisobjekt geändert',          self::CAT_ACCOUNT,   'success', false],
        5137 => ['Verzeichnisobjekt angelegt',          self::CAT_ACCOUNT,   'success', false],
        5141 => ['Verzeichnisobjekt gelöscht',          self::CAT_ACCOUNT,   'success', false],
    ];

    /**
     * Why the high-volume IDs stay off by default. Shown in the settings page
     * next to the checkbox, so the decision is made with the cost in view
     * rather than discovered on the storage graph three weeks later.
     */
    private const VOLUME_NOTES = [
        4769 => 'Sehr hohes Volumen: jedes Diensticket jedes Clients, auf einem DC leicht 80 % des Kanals.',
        4768 => 'Hohes Volumen: ein Eintrag pro Anmeldung und Ticket-Erneuerung.',
        4634 => 'Hohes Volumen und wenig Aussage — die passende Anmeldung steht schon in 4624.',
        4647 => 'Hohes Volumen, Abmeldungen beantworten selten eine Frage.',
        4778 => 'Nur bei Terminalserver-Betrieb interessant.',
        4779 => 'Nur bei Terminalserver-Betrieb interessant.',
        4800 => 'Sehr hohes Volumen: jede Bildschirmsperre.',
        4801 => 'Sehr hohes Volumen: jede Entsperrung.',
        5136 => 'Erfordert "DS-Zugriff"-Überwachung und erzeugt pro Attributänderung eine Zeile.',
        5137 => 'Erfordert "DS-Zugriff"-Überwachung.',
        5141 => 'Erfordert "DS-Zugriff"-Überwachung.',
    ];

    /** @return array{label: string, category: string, result: ?EventResult}|null */
    public static function describe(int $id): ?array
    {
        $entry = self::EVENTS[$id] ?? null;
        if ($entry === null) {
            return null;
        }

        return [
            'label'    => $entry[0],
            'category' => $entry[1],
            'result'   => $entry[2] === null ? null : EventResult::from($entry[2]),
        ];
    }

    public static function knows(int $id): bool
    {
        return isset(self::EVENTS[$id]);
    }

    /** @return list<int> */
    public static function defaultIds(): array
    {
        $ids = [];
        foreach (self::EVENTS as $id => $entry) {
            if ($entry[3] === true) {
                $ids[] = $id;
            }
        }

        sort($ids);

        return $ids;
    }

    /** @return list<int> */
    public static function optionalIds(): array
    {
        $ids = [];
        foreach (self::EVENTS as $id => $entry) {
            if ($entry[3] === false) {
                $ids[] = $id;
            }
        }

        sort($ids);

        return $ids;
    }

    public static function volumeNote(int $id): ?string
    {
        return self::VOLUME_NOTES[$id] ?? null;
    }

    /**
     * Everything the catalogue knows, grouped for the settings page.
     *
     * @return array<string, list<array{id: int, label: string, default: bool, note: ?string}>>
     */
    public static function grouped(): array
    {
        $out = [];

        foreach (self::EVENTS as $id => $entry) {
            $out[$entry[1]][] = [
                'id'      => $id,
                'label'   => $entry[0],
                'default' => $entry[3],
                'note'    => self::VOLUME_NOTES[$id] ?? null,
            ];
        }

        foreach ($out as &$group) {
            usort($group, static fn (array $a, array $b): int => $a['id'] <=> $b['id']);
        }

        return $out;
    }

    public static function categoryLabel(string $category): string
    {
        return match ($category) {
            self::CAT_LOGON     => 'An- und Abmeldung',
            self::CAT_KERBEROS  => 'Kerberos und NTLM',
            self::CAT_ACCOUNT   => 'Kontoverwaltung',
            self::CAT_GROUP     => 'Gruppenverwaltung',
            self::CAT_PRIVILEGE => 'Berechtigungen',
            self::CAT_POLICY    => 'Richtlinien',
            self::CAT_AUDIT     => 'Protokoll selbst',
            default             => $category,
        };
    }
}
