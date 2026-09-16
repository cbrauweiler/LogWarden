<?php

declare(strict_types=1);

namespace LogWarden\Security;

/**
 * The authenticated account for this request.
 */
final class CurrentUser
{
    /** @param list<string> $ldapGroups */
    public function __construct(
        public readonly int $id,
        public readonly string $username,
        public readonly ?string $displayName,
        public readonly ?string $email,
        public readonly Role $role,
        public readonly string $authProvider,
        public readonly bool $mustChangePassword,
        public readonly string $sessionId,
        public readonly string $csrfToken,
        public readonly array $ldapGroups = [],
        public readonly ?string $roleMatchedBy = null,
        public readonly ?string $lastLoginAt = null,
    ) {
    }

    public function can(string $permission): bool
    {
        return $this->role->can($permission);
    }

    public function name(): string
    {
        return $this->displayName ?? $this->username;
    }

    public function isLocal(): bool
    {
        return $this->authProvider === 'local';
    }

    /** Two letters for the avatar, from the display name where there is one. */
    public function initials(): string
    {
        $source = trim((string) ($this->displayName ?? $this->username));
        $parts  = preg_split('/[\s._-]+/', $source, -1, PREG_SPLIT_NO_EMPTY) ?: [];

        if (count($parts) >= 2) {
            return mb_strtoupper(mb_substr($parts[0], 0, 1) . mb_substr($parts[1], 0, 1));
        }

        return mb_strtoupper(mb_substr($source, 0, 2));
    }
}
