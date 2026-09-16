<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Windows;

/**
 * The lookup tables that turn a Windows Security event from a puzzle into a
 * sentence.
 *
 * Event 4625 carries the reason a logon failed as an NTSTATUS value in
 * `SubStatus`. Without the translation an administrator is left comparing
 * hexadecimal against a web search — and the difference between "wrong
 * password" and "this account does not exist" is precisely what distinguishes
 * a colleague after holiday from someone guessing account names.
 */
final class WindowsCodes
{
    /**
     * Logon types. The interesting split is 2/10/11 (someone sat down at a
     * machine) against 3 (a service reached across the network), because the
     * same failed password means very different things in the two cases.
     */
    private const LOGON_TYPES = [
        0  => 'System',
        2  => 'Interaktiv (lokale Anmeldung)',
        3  => 'Netzwerk (Freigabe, Dienst)',
        4  => 'Batch (geplante Aufgabe)',
        5  => 'Dienst',
        7  => 'Entsperren',
        8  => 'Netzwerk (Klartext)',
        9  => 'Neue Anmeldedaten (RunAs)',
        10 => 'Remotedesktop',
        11 => 'Zwischengespeichert (offline)',
        12 => 'Zwischengespeichert (Remote)',
        13 => 'Zwischengespeichert (Entsperren)',
    ];

    /** NTSTATUS values as they appear in Status/SubStatus of 4625 and 4776. */
    private const STATUS = [
        '0xc0000064' => 'Benutzername existiert nicht',
        '0xc000006a' => 'Falsches Passwort',
        '0xc000006d' => 'Anmeldung fehlgeschlagen (allgemein)',
        '0xc000006e' => 'Kontoeinschränkung verletzt',
        '0xc000006f' => 'Anmeldung außerhalb der erlaubten Zeiten',
        '0xc0000070' => 'Anmeldung von dieser Arbeitsstation nicht erlaubt',
        '0xc0000071' => 'Passwort abgelaufen',
        '0xc0000072' => 'Konto deaktiviert',
        '0xc000009a' => 'Nicht genügend Systemressourcen',
        '0xc0000133' => 'Zeitabweichung zwischen Client und DC zu groß',
        '0xc000015b' => 'Anmeldeart für dieses Konto nicht zugelassen',
        '0xc000018c' => 'Vertrauensstellung zur Domäne fehlgeschlagen',
        '0xc0000192' => 'NetLogon-Dienst nicht gestartet',
        '0xc0000193' => 'Konto abgelaufen',
        '0xc0000224' => 'Passwortwechsel beim nächsten Anmelden erforderlich',
        '0xc0000225' => 'Windows-Fehler, kein Sicherheitsproblem',
        '0xc0000234' => 'Konto gesperrt',
        '0x0'        => 'Erfolg',
    ];

    /**
     * Kerberos failure codes from 4771 and 4768. 0x18 is the everyday wrong
     * password; 0x12 covers disabled, locked and expired alike, which is why
     * it needs 4740 alongside it to be conclusive.
     */
    private const KERBEROS = [
        '0x1'  => 'Client-Principal unbekannt',
        '0x6'  => 'Benutzername existiert nicht',
        '0x7'  => 'Dienst-Principal unbekannt',
        '0x9'  => 'Passwort abgelaufen',
        '0xc'  => 'Anmeldung von dieser Arbeitsstation nicht erlaubt',
        '0x12' => 'Konto deaktiviert, gesperrt oder abgelaufen',
        '0x17' => 'Passwort abgelaufen, muss geändert werden',
        '0x18' => 'Falsches Passwort (Pre-Authentication fehlgeschlagen)',
        '0x19' => 'Pre-Authentication erforderlich',
        '0x20' => 'Ticket abgelaufen',
        '0x25' => 'Zeitabweichung zwischen Client und DC zu groß',
        '0x37' => 'Zeitabweichung zwischen Client und DC zu groß',
    ];

    /** Elevated group memberships in 4672, worth calling out on their own. */
    private const NOTABLE_PRIVILEGES = [
        'SeDebugPrivilege',
        'SeTakeOwnershipPrivilege',
        'SeTcbPrivilege',
        'SeLoadDriverPrivilege',
        'SeBackupPrivilege',
        'SeRestorePrivilege',
        'SeCreateTokenPrivilege',
        'SeImpersonatePrivilege',
    ];

    public static function logonType(?string $value): ?string
    {
        if ($value === null || !is_numeric($value)) {
            return null;
        }

        return self::LOGON_TYPES[(int) $value] ?? ('Typ ' . (int) $value);
    }

    /**
     * Windows writes these both as `0xC000006A` and `%%2313`-style references
     * depending on the field; only the hexadecimal form carries meaning here.
     */
    public static function status(?string $value): ?string
    {
        $key = self::normaliseHex($value);

        return $key === null ? null : (self::STATUS[$key] ?? null);
    }

    public static function kerberos(?string $value): ?string
    {
        $key = self::normaliseHex($value);
        if ($key === null) {
            return null;
        }

        // Kerberos codes are written 0x18 but sometimes 0x00000018.
        $short = '0x' . ltrim(substr($key, 2), '0');
        if ($short === '0x') {
            $short = '0x0';
        }

        return self::KERBEROS[$key] ?? self::KERBEROS[$short] ?? null;
    }

    /** @return list<string> */
    public static function notablePrivileges(?string $privilegeList): array
    {
        if ($privilegeList === null || trim($privilegeList) === '' || trim($privilegeList) === '-') {
            return [];
        }

        $granted = preg_split('/[\s,]+/', trim($privilegeList)) ?: [];

        return array_values(array_intersect(self::NOTABLE_PRIVILEGES, $granted));
    }

    /**
     * A machine account, not a person.
     *
     * On a domain controller these produce the bulk of 4624/4769 traffic, and
     * mixing them into "who logged on" makes every per-user statistic useless.
     */
    public static function isComputerAccount(?string $username): bool
    {
        return $username !== null && str_ends_with($username, '$');
    }

    /**
     * Accounts Windows uses for its own bookkeeping. They appear constantly
     * and never answer a question anybody asked.
     */
    public static function isSystemAccount(?string $username): bool
    {
        if ($username === null) {
            return false;
        }

        return in_array(strtoupper($username), [
            'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON',
            'LOKALER DIENST', 'NETZWERKDIENST', 'DWM-1', 'DWM-2', 'UMFD-0', 'UMFD-1',
        ], true);
    }

    private static function normaliseHex(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $value = strtolower(trim($value));
        if ($value === '' || $value === '-') {
            return null;
        }

        if (!str_starts_with($value, '0x')) {
            if (!ctype_xdigit($value)) {
                return null;
            }
            $value = '0x' . $value;
        }

        return ctype_xdigit(substr($value, 2)) ? $value : null;
    }
}
