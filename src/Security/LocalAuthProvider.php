<?php

declare(strict_types=1);

namespace LogWarden\Security;

use LogWarden\Core\Db;
use SensitiveParameter;

/**
 * Authenticates against local accounts stored in `users`.
 *
 * Its reason to exist is the failure case: when the domain controller is down,
 * the one system you need in order to investigate why must still let you in.
 */
final class LocalAuthProvider implements AuthProviderInterface
{
    /**
     * A real Argon2id hash of a random string, used to spend the same time on
     * an unknown account as on a known one. It has to be genuine: password_verify()
     * returns immediately on a malformed hash, which would leave the timing
     * difference it is meant to hide.
     */
    private const TIMING_EQUALISER = '$argon2id$v=19$m=65536,t=4,p=1$M3VPcDNndFJyaXo2czU1Qw$j5msqRBBMBlVGiSp3trUdd60fS9Q3jO7K755WjoYKUU';

    public function __construct(private readonly Db $db)
    {
    }

    public function name(): string
    {
        return 'local';
    }

    public function authenticate(string $username, #[SensitiveParameter] string $password): AuthResult
    {
        $username = mb_strtolower(trim($username));

        if ($username === '' || $password === '') {
            return AuthResult::fail('empty_credentials', 'local');
        }

        $row = $this->db->fetchRow(
            "SELECT username, display_name, email, password_hash, enabled
               FROM users
              WHERE username = ? AND auth_provider = 'local'",
            [$username],
        );

        if ($row === null) {
            // Hash anyway: returning early for an unknown account makes the
            // response measurably faster and turns timing into an account
            // enumeration oracle.
            PasswordPolicy::verify($password, self::TIMING_EQUALISER);

            return AuthResult::fail('unknown_account', 'local');
        }

        if (!PasswordPolicy::verify($password, (string) $row['password_hash'])) {
            return AuthResult::fail('invalid_credentials', 'local');
        }

        if (!$row['enabled']) {
            return AuthResult::fail('account_disabled', 'local');
        }

        // Upgrade the stored hash while we legitimately hold the plaintext.
        if (PasswordPolicy::needsRehash((string) $row['password_hash'])) {
            $this->db->execute(
                'UPDATE users SET password_hash = ? WHERE username = ?',
                [PasswordPolicy::hash($password), $username],
            );
        }

        return AuthResult::ok(
            username:    (string) $row['username'],
            provider:    'local',
            displayName: $row['display_name'],
            email:       $row['email'],
        );
    }

    public function healthCheck(): AuthResult
    {
        $count = (int) $this->db->fetchValue(
            "SELECT count(*) FROM users WHERE auth_provider = 'local' AND enabled"
        );

        return $count > 0
            ? AuthResult::ok('local', 'local')
            : AuthResult::unavailable('Kein aktives lokales Konto vorhanden', 'local');
    }
}
