<?php

declare(strict_types=1);

namespace LogWarden\Event;

enum SourceType: string
{
    case Ad            = 'ad';
    case Dns           = 'dns';
    case Dhcp          = 'dhcp';
    case FortigateVpn  = 'fortigate_vpn';
    case FortigateAuth = 'fortigate_auth';

    public function label(): string
    {
        return match ($this) {
            self::Ad            => 'Active Directory',
            self::Dns           => 'DNS',
            self::Dhcp          => 'DHCP',
            self::FortigateVpn  => 'FortiGate VPN',
            self::FortigateAuth => 'FortiGate Auth',
        };
    }
}
