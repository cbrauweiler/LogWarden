<?php

declare(strict_types=1);

namespace LogWarden\Plugin\CiscoAsa;

use LogWarden\Event\EventResult;
use LogWarden\Plugin\SourceTypeDefinition;

/**
 * Which ASA message numbers are collected, and what each one means.
 *
 * The same reasoning as the Active Directory catalogue: an ASA at the edge
 * emits an enormous amount of connection bookkeeping (302013/302014 alone are
 * one line per TCP connection) that answers no question anybody asks. What is
 * kept here is VPN sessions and authentication — the two things the rules
 * correlate against the directory.
 */
final class AsaMessageCatalog
{
    /** id => [label, role, result|null] — null means the message text decides. */
    private const MESSAGES = [
        // --- VPN -------------------------------------------------------------
        '113039' => ['AnyConnect-Sitzung gestartet',       SourceTypeDefinition::ROLE_VPN,  'success'],
        '113019' => ['VPN-Sitzung beendet',                SourceTypeDefinition::ROLE_VPN,  'info'],
        '722022' => ['SVC-Verbindung aufgebaut',           SourceTypeDefinition::ROLE_VPN,  'success'],
        '722023' => ['SVC-Verbindung beendet',             SourceTypeDefinition::ROLE_VPN,  'info'],
        '722051' => ['Adresse an VPN-Sitzung vergeben',    SourceTypeDefinition::ROLE_VPN,  'success'],
        '716001' => ['WebVPN-Sitzung gestartet',           SourceTypeDefinition::ROLE_VPN,  'success'],
        '716002' => ['WebVPN-Sitzung beendet',             SourceTypeDefinition::ROLE_VPN,  'info'],
        '716039' => ['WebVPN-Anmeldung fehlgeschlagen',    SourceTypeDefinition::ROLE_VPN,  'fail'],
        '713119' => ['IPsec Phase 1 abgeschlossen',        SourceTypeDefinition::ROLE_VPN,  'success'],
        '713120' => ['IPsec Phase 2 abgeschlossen',        SourceTypeDefinition::ROLE_VPN,  'success'],
        '713904' => ['IPsec-Aushandlung fehlgeschlagen',   SourceTypeDefinition::ROLE_VPN,  'fail'],

        // --- Authentifizierung -------------------------------------------------
        '113004' => ['AAA-Authentifizierung erfolgreich',  SourceTypeDefinition::ROLE_AUTH, 'success'],
        '113005' => ['AAA-Authentifizierung abgelehnt',    SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '113006' => ['Konto gesperrt',                     SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '113012' => ['Anmeldung gegen lokale Datenbank erfolgreich', SourceTypeDefinition::ROLE_AUTH, 'success'],
        '113015' => ['Anmeldung gegen lokale Datenbank abgelehnt',   SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '113021' => ['Anmeldung von unerlaubter Stelle',   SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '605004' => ['Verwaltungsanmeldung abgelehnt',     SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '605005' => ['Verwaltungsanmeldung erlaubt',       SourceTypeDefinition::ROLE_AUTH, 'success'],
        '611101' => ['Benutzer-Authentifizierung erfolgreich', SourceTypeDefinition::ROLE_AUTH, 'success'],
        '611102' => ['Benutzer-Authentifizierung fehlgeschlagen', SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '109005' => ['Authentifizierung erfolgreich',      SourceTypeDefinition::ROLE_AUTH, 'success'],
        '109006' => ['Authentifizierung fehlgeschlagen',   SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '109025' => ['Autorisierung abgelehnt',            SourceTypeDefinition::ROLE_AUTH, 'fail'],
        '315011' => ['SSH-Sitzung beendet',                SourceTypeDefinition::ROLE_AUTH, 'info'],
    ];

    /** Reasons ASA puts after `reason =` in 113005/113015, translated. */
    private const REASONS = [
        'AAA failure'                => 'AAA-Server antwortet nicht',
        'Invalid password'           => 'Falsches Passwort',
        'Unspecified'                => 'Kein Grund angegeben',
        'User was not found'         => 'Benutzer existiert nicht',
        'Simultaneous logins exceeded for user' => 'Zu viele gleichzeitige Sitzungen',
        'Administrative lock'        => 'Konto administrativ gesperrt',
        'Rejected by server'         => 'Vom AAA-Server abgelehnt',
        'Account disabled'           => 'Konto deaktiviert',
    ];

    /** @return array{label: string, role: string, result: ?EventResult}|null */
    public static function describe(string $id): ?array
    {
        $entry = self::MESSAGES[$id] ?? null;

        if ($entry === null) {
            return null;
        }

        return [
            'label'  => $entry[0],
            'role'   => $entry[1],
            'result' => $entry[2] === null ? null : EventResult::from($entry[2]),
        ];
    }

    public static function knows(string $id): bool
    {
        return isset(self::MESSAGES[$id]);
    }

    public static function reason(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }

        $raw = trim($raw);

        return self::REASONS[$raw] ?? ($raw === '' ? null : $raw);
    }

    /** @return list<string> */
    public static function ids(): array
    {
        return array_keys(self::MESSAGES);
    }
}
