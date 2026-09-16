<?php

declare(strict_types=1);

namespace LogWarden\Security;

use SensitiveParameter;

/**
 * Contract for a credential check.
 *
 * A provider only answers "are these credentials valid, and who is this".
 * Deciding the role, creating the session, rate limiting and lockout all live
 * outside, so a second provider cannot get any of it subtly wrong.
 */
interface AuthProviderInterface
{
    public function name(): string;

    public function authenticate(string $username, #[SensitiveParameter] string $password): AuthResult;

    /** Used by the settings page to report whether the directory is reachable. */
    public function healthCheck(): AuthResult;
}
