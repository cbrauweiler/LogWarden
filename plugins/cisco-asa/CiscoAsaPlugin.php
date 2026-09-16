<?php

declare(strict_types=1);

namespace LogWarden\Plugin\CiscoAsa;

use LogWarden\Plugin\PluginInterface;
use LogWarden\Plugin\SourceTypeDefinition;

/**
 * Cisco ASA and Firepower Threat Defense over syslog.
 *
 * Exists as much as a second implementation of the plugin contract as for its
 * own sake: a plugin system proved by exactly one plugin is not proved. What
 * it turned up — that source types needed a role, so that rules could say "a
 * VPN login" rather than "a FortiGate VPN login" — is in docs/plugins.md.
 */
final class CiscoAsaPlugin implements PluginInterface
{
    public static function key(): string
    {
        return 'cisco-asa';
    }

    public static function transports(): array
    {
        return ['syslog'];
    }

    public static function sourceTypes(): array
    {
        return [
            new SourceTypeDefinition(
                key:         'cisco_asa_vpn',
                label:       'Cisco ASA VPN',
                keepDays:    180,
                ftsDays:     30,
                color:       '--series-6',
                description: 'AnyConnect-, WebVPN- und IPsec-Sitzungen',
                role:        SourceTypeDefinition::ROLE_VPN,
            ),
            new SourceTypeDefinition(
                key:         'cisco_asa_auth',
                label:       'Cisco ASA Auth',
                keepDays:    180,
                ftsDays:     30,
                color:       '--series-7',
                description: 'AAA- und Verwaltungsanmeldungen an der Appliance',
                role:        SourceTypeDefinition::ROLE_AUTH,
            ),
        ];
    }

    public function normalizers(): array
    {
        return [new CiscoAsaNormalizer()];
    }
}
