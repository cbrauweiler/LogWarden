<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Syslog;

/**
 * Allow-list of hosts and networks permitted to send events.
 *
 * UDP syslog has no authentication whatsoever and the source address is
 * trivially spoofed, so this is not a security boundary on its own — it keeps
 * accidental and opportunistic traffic out. Anything stronger needs TCP/TLS
 * with client certificates.
 */
final class PeerFilter
{
    /** @var list<array{0:string,1:int}> */
    private array $networks = [];

    private bool $allowAll;

    /** @param list<string> $allowed CIDR notation or plain addresses */
    public function __construct(array $allowed)
    {
        $this->allowAll = $allowed === [];

        foreach ($allowed as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }

            if (str_contains($entry, '/')) {
                [$address, $bits] = explode('/', $entry, 2);
                $packed = @inet_pton($address);
                if ($packed !== false) {
                    $this->networks[] = [$packed, (int) $bits];
                }
                continue;
            }

            $packed = @inet_pton($entry);
            if ($packed !== false) {
                $this->networks[] = [$packed, strlen($packed) * 8];
            }
        }
    }

    public function allows(?string $ip): bool
    {
        if ($this->allowAll) {
            return true;
        }
        if ($ip === null) {
            return false;
        }

        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }

        foreach ($this->networks as [$network, $bits]) {
            if (strlen($network) !== strlen($packed)) {
                continue;   // mixing IPv4 and IPv6 never matches
            }
            if ($this->inNetwork($packed, $network, $bits)) {
                return true;
            }
        }

        return false;
    }

    private function inNetwork(string $address, string $network, int $bits): bool
    {
        $maxBits = strlen($network) * 8;
        $bits    = max(0, min($bits, $maxBits));

        $wholeBytes = intdiv($bits, 8);
        if ($wholeBytes > 0 && strncmp($address, $network, $wholeBytes) !== 0) {
            return false;
        }

        $remainder = $bits % 8;
        if ($remainder === 0) {
            return true;
        }

        $mask = ~((1 << (8 - $remainder)) - 1) & 0xFF;

        return (ord($address[$wholeBytes]) & $mask) === (ord($network[$wholeBytes]) & $mask);
    }
}
