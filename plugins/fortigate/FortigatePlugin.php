<?php

declare(strict_types=1);

namespace LogWarden\Plugin\Fortigate;

use LogWarden\Plugin\PluginInterface;
use LogWarden\Plugin\SourceTypeDefinition;

/**
 * FortiGate over syslog.
 *
 * Two kinds of event are kept and everything else is dropped: VPN
 * (`logid 0101…`) and authentication (`logid 0102…`). Traffic and UTM logs
 * would dominate the store by an order of magnitude without serving any of the
 * rules — the decision and the exact signals are in FortigateNormalizer.
 */
final class FortigatePlugin implements PluginInterface
{
    public static function key(): string
    {
        return 'fortigate';
    }

    public static function transports(): array
    {
        return ['syslog'];
    }

    public static function sourceTypes(): array
    {
        return [
            new SourceTypeDefinition(
                key:         'fortigate_vpn',
                label:       'FortiGate VPN',
                keepDays:    180,
                ftsDays:     30,
                color:       '--series-4',
                description: 'SSL- und IPsec-VPN: Tunnelauf- und -abbau, fehlgeschlagene Anmeldungen',
                role:        SourceTypeDefinition::ROLE_VPN,
            ),
            new SourceTypeDefinition(
                key:         'fortigate_auth',
                label:       'FortiGate Auth',
                keepDays:    180,
                ftsDays:     30,
                color:       '--series-5',
                description: 'Benutzer-Authentifizierung an der Firewall',
                role:        SourceTypeDefinition::ROLE_AUTH,
            ),
        ];
    }

    public function normalizers(): array
    {
        return [new FortigateNormalizer()];
    }
}
