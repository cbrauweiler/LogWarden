<?php

declare(strict_types=1);

namespace LogWarden\Security;

/**
 * What a provider says about one login attempt.
 *
 * The failure reason is recorded but never shown: telling an attacker whether
 * the account exists turns a password guess into two separate, easier problems.
 */
final class AuthResult
{
    private function __construct(
        public readonly bool $success,
        public readonly ?string $username = null,
        public readonly ?string $displayName = null,
        public readonly ?string $email = null,
        /** @var list<string> Directory groups, empty for local accounts */
        public readonly array $groups = [],
        public readonly ?string $reason = null,
        public readonly string $provider = 'unknown',
        /** A provider outage is not a wrong password and must not lock anyone out. */
        public readonly bool $providerUnavailable = false,
    ) {
    }

    /** @param list<string> $groups */
    public static function ok(
        string $username,
        string $provider,
        ?string $displayName = null,
        ?string $email = null,
        array $groups = [],
    ): self {
        return new self(true, $username, $displayName, $email, $groups, null, $provider);
    }

    public static function fail(string $reason, string $provider): self
    {
        return new self(false, reason: $reason, provider: $provider);
    }

    public static function unavailable(string $reason, string $provider): self
    {
        return new self(false, reason: $reason, provider: $provider, providerUnavailable: true);
    }
}
