<?php

declare(strict_types=1);

namespace LogWarden\Plugin;

/**
 * A kind of event a plugin produces, with everything the rest of LogWarden
 * needs to display and retain it.
 *
 * Declared by the plugin rather than by the schema: a plugin system in which
 * adding a vendor requires a database migration is not a plugin system. The
 * definitions are mirrored into `source_types` by `bin/logwarden-plugins
 * --sync` so that SQL can join labels and colours, but the authoritative copy
 * is the one in code.
 */
final class SourceTypeDefinition
{
    /** The palette is checked as a set for colour-vision deficiency; see docs/plugins.md. */
    public const PALETTE = ['--series-1', '--series-2', '--series-3', '--series-4', '--series-5', '--series-6', '--series-7', '--series-8'];

    /**
     * What kind of thing this source type is, independent of who makes it.
     *
     * This is what lets a rule say "a VPN login followed by directory logon
     * failures" instead of "a fortigate_vpn event followed by an ad event".
     * Without it every rule would name vendors, and installing the Cisco
     * plugin would mean editing every rule to mention Cisco too — at which
     * point the plugin system buys nothing.
     */
    public const ROLE_VPN       = 'vpn';
    public const ROLE_AUTH      = 'auth';
    public const ROLE_DIRECTORY = 'directory';
    public const ROLE_DNS       = 'dns';
    public const ROLE_DHCP      = 'dhcp';
    public const ROLE_FIREWALL  = 'firewall';
    public const ROLE_ENDPOINT  = 'endpoint';
    public const ROLE_OTHER     = 'other';

    public const ROLES = [
        self::ROLE_VPN       => 'VPN-Zugang',
        self::ROLE_AUTH      => 'Authentifizierung',
        self::ROLE_DIRECTORY => 'Verzeichnisdienst',
        self::ROLE_DNS       => 'Namensauflösung',
        self::ROLE_DHCP      => 'Adressvergabe',
        self::ROLE_FIREWALL  => 'Firewall',
        self::ROLE_ENDPOINT  => 'Endgerät',
        self::ROLE_OTHER     => 'Sonstiges',
    ];

    public function __construct(
        public readonly string $key,
        public readonly string $label,
        /**
         * How long events of this kind are kept. A plugin states its own
         * default because volume and value differ enormously between them —
         * DNS queries and account lockouts do not belong under one number.
         */
        public readonly int $keepDays = 180,
        public readonly int $ftsDays = 14,
        public readonly ?string $color = null,
        public readonly ?string $description = null,
        public readonly string $role = self::ROLE_OTHER,
    ) {
        if (!isset(self::ROLES[$role])) {
            throw new \InvalidArgumentException(sprintf(
                'Unbekannte Rolle "%s" für Quelltyp "%s". Erlaubt: %s.',
                $role,
                $key,
                implode(', ', array_keys(self::ROLES)),
            ));
        }

        if (preg_match('/^[a-z][a-z0-9_]{1,30}$/', $key) !== 1) {
            throw new \InvalidArgumentException(
                "Ungültiger Quelltyp-Schlüssel '{$key}': erlaubt sind Kleinbuchstaben, Ziffern und "
                . 'Unterstrich, beginnend mit einem Buchstaben, 2 bis 31 Zeichen.',
            );
        }
    }

    /** @return array<string, mixed> */
    public function toRow(string $plugin): array
    {
        return [
            'key'         => $this->key,
            'label'       => $this->label,
            'plugin'      => $plugin,
            'keep_days'   => $this->keepDays,
            'fts_days'    => $this->ftsDays,
            'color'       => $this->color,
            'description' => $this->description,
            'role'        => $this->role,
        ];
    }
}
