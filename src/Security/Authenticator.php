<?php

declare(strict_types=1);

namespace LogWarden\Security;

use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use SensitiveParameter;
use Throwable;

/**
 * Orchestrates a login: rate limiting, provider chain, role resolution,
 * account upsert and session creation.
 *
 * The providers only answer "are these credentials valid". Everything that can
 * be got subtly wrong — lockout, enumeration, what happens when the directory
 * is down — lives here once, instead of once per provider.
 */
final class Authenticator
{
    /** Failed attempts before an account is locked. */
    private const MAX_FAILURES = 8;

    /** How long an account stays locked. */
    private const LOCKOUT_SECONDS = 900;

    /** Attempts per address within the window, whatever account they target. */
    private const IP_MAX_ATTEMPTS = 30;
    private const IP_WINDOW_SECONDS = 600;

    /** @param list<AuthProviderInterface> $providers */
    public function __construct(
        private readonly Db $db,
        private readonly array $providers,
        private readonly RoleResolver $roles,
        private readonly SessionStore $sessions,
        private readonly Logger $logger,
        private readonly ?Role $defaultRole = null,
    ) {
    }

    /**
     * @return array{ok: bool, token?: string, user?: CurrentUser, message?: string}
     */
    public function login(
        string $username,
        #[SensitiveParameter] string $password,
        ?string $ip,
        ?string $userAgent,
    ): array {
        $username = mb_strtolower(trim($username));

        if ($username === '' || $password === '') {
            return $this->reject($username, $ip, $userAgent, 'empty', null);
        }

        if ($this->ipIsThrottled($ip)) {
            $this->record($username, $ip, $userAgent, false, 'ip_throttled', null);

            return [
                'ok'      => false,
                'message' => 'Zu viele Anmeldeversuche von dieser Adresse. Bitte später erneut versuchen.',
            ];
        }

        $lockedUntil = $this->lockedUntil($username);

        if ($lockedUntil !== null) {
            $this->record($username, $ip, $userAgent, false, 'locked', null);

            return [
                'ok'      => false,
                'message' => 'Das Konto ist vorübergehend gesperrt. Bitte in einigen Minuten erneut versuchen.',
            ];
        }

        $unavailable = [];

        foreach ($this->providers as $provider) {
            try {
                $result = $provider->authenticate($username, $password);
            } catch (Throwable $e) {
                $this->logger->exception($e, 'Auth provider threw');
                $result = AuthResult::unavailable($e->getMessage(), $provider->name());
            }

            if ($result->providerUnavailable) {
                // Not a wrong password. It must not count toward lockout, and
                // the next provider still gets a turn — that is what makes the
                // local break-glass account work when the DC is down.
                $unavailable[] = $provider->name();
                $this->logger->error('Auth provider unavailable', [
                    'provider' => $provider->name(),
                    'reason'   => $result->reason,
                ]);
                continue;
            }

            if (!$result->success) {
                continue;
            }

            return $this->establish($result, $ip, $userAgent);
        }

        if ($unavailable !== [] && count($unavailable) === count($this->providers)) {
            $this->record($username, $ip, $userAgent, false, 'providers_unavailable', null);

            return [
                'ok'      => false,
                'message' => 'Die Anmeldung ist derzeit nicht möglich: kein Authentifizierungsdienst erreichbar.',
            ];
        }

        if ($unavailable !== []) {
            // One provider answered "no" while another could not be asked. For
            // a directory account during a domain controller outage that looks
            // identical to a wrong password — and counting it toward lockout
            // would lock people out of the very system they need to find out
            // why the controller is down. An attacker cannot cause a provider
            // outage, so declining to count it is not a way in.
            $this->record($username, $ip, $userAgent, false, 'invalid_credentials_degraded', null);

            return [
                'ok'      => false,
                'message' => 'Anmeldung fehlgeschlagen. Ein Authentifizierungsdienst ist derzeit nicht '
                    . 'erreichbar — bitte später erneut versuchen oder die Administration informieren.',
            ];
        }

        return $this->reject($username, $ip, $userAgent, 'invalid_credentials', null);
    }

    public function logout(string $token): void
    {
        $this->sessions->destroy($token);
    }

    // -----------------------------------------------------------------------

    /**
     * @return array{ok: bool, token?: string, user?: CurrentUser, message?: string}
     */
    private function establish(AuthResult $result, ?string $ip, ?string $userAgent): array
    {
        $username = mb_strtolower((string) $result->username);

        $existing = $this->db->fetchRow(
            'SELECT id, role::text AS role, role_source, enabled FROM users WHERE username = ?',
            [$username],
        );

        if ($existing !== null && !$existing['enabled']) {
            $this->record($username, $ip, $userAgent, false, 'account_disabled', $result->provider);

            return ['ok' => false, 'message' => 'Anmeldung fehlgeschlagen.'];
        }

        $resolved  = $this->roles->resolve($username, $result->groups);
        $manual    = $existing !== null && $existing['role_source'] === 'manual';
        $role      = $resolved['role'];
        $matchedBy = $resolved['matched_by'];

        if ($manual) {
            // An explicitly assigned role wins over the directory: it is how an
            // administrator overrides a mapping without editing AD.
            $role      = Role::tryFromName((string) $existing['role']) ?? $role;
            $matchedBy = 'Manuell zugewiesen';
        }

        if ($role === null && $result->provider === 'local' && $existing !== null) {
            $role      = Role::tryFromName((string) $existing['role']);
            $matchedBy = 'Lokales Konto';
        }

        $role ??= $this->defaultRole;

        if ($role === null) {
            // Authenticated, but nothing grants any access. Saying so plainly
            // beats an empty page the person cannot explain.
            $this->record($username, $ip, $userAgent, false, 'no_role_mapping', $result->provider);
            $this->logger->warning('Login without a role mapping', [
                'username' => $username,
                'groups'   => $result->groups,
            ]);

            return [
                'ok'      => false,
                'message' => 'Anmeldung erfolgreich, aber diesem Konto ist keine Berechtigungsstufe zugewiesen. '
                    . 'Bitte an die Administration wenden.',
            ];
        }

        $userId = $this->upsert($existing, $username, $result, $role, $matchedBy, $manual, $ip);

        $this->db->execute(
            'UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?',
            [$userId],
        );

        $session = $this->sessions->create($userId, $ip, $userAgent);
        $this->record($username, $ip, $userAgent, true, null, $result->provider);

        $this->audit($username, 'auth.login', ['provider' => $result->provider, 'role' => $role->value, 'ip' => $ip]);

        $user = $this->sessions->resolve($session['token']);

        if ($user === null) {
            return ['ok' => false, 'message' => 'Sitzung konnte nicht angelegt werden.'];
        }

        return ['ok' => true, 'token' => $session['token'], 'user' => $user];
    }

    /**
     * Records the login on the account, creating it on first sight.
     *
     * Deliberately not INSERT ... ON CONFLICT: PostgreSQL evaluates check
     * constraints on the proposed row *before* it detects the conflict, so the
     * insert attempt for an existing local account failed on
     * users_local_needs_hash — the proposed row carries no password hash. An
     * explicit update for a known account avoids the whole question.
     *
     * @param array<string, mixed>|null $existing
     */
    private function upsert(
        ?array $existing,
        string $username,
        AuthResult $result,
        Role $role,
        ?string $matchedBy,
        bool $keepManualRole,
        ?string $ip,
    ): int {
        $groups = json_encode(array_values($result->groups), JSON_UNESCAPED_UNICODE);

        if ($existing !== null) {
            $this->db->execute(
                'UPDATE users SET
                     display_name    = COALESCE(?, display_name),
                     email           = COALESCE(?, email),
                     role            = CASE WHEN ? THEN role ELSE ?::user_role_t END,
                     role_source     = CASE WHEN ? THEN role_source ELSE ? END,
                     last_login_at   = now(),
                     last_login_ip   = ?::inet,
                     ldap_groups     = ?::jsonb,
                     role_matched_by = ?
                 WHERE id = ?',
                [
                    $result->displayName,
                    $result->email,
                    $keepManualRole ? 'true' : 'false',
                    $role->value,
                    $keepManualRole ? 'true' : 'false',
                    $keepManualRole ? 'manual' : 'ldap_group',
                    $ip,
                    $groups,
                    $matchedBy,
                    (int) $existing['id'],
                ],
            );

            return (int) $existing['id'];
        }

        return (int) $this->db->fetchValue(
            'INSERT INTO users (username, display_name, email, auth_provider, role, role_source,
                                enabled, last_login_at, last_login_ip, ldap_groups, role_matched_by)
             VALUES (?, ?, ?, ?, ?::user_role_t, ?, true, now(), ?::inet, ?::jsonb, ?)
             RETURNING id',
            [
                $username,
                $result->displayName,
                $result->email,
                $result->provider,
                $role->value,
                $keepManualRole ? 'manual' : 'ldap_group',
                $ip,
                $groups,
                $matchedBy,
            ],
        );
    }

    /**
     * @return array{ok: false, message: string}
     */
    private function reject(string $username, ?string $ip, ?string $userAgent, string $reason, ?string $provider): array
    {
        $this->countFailure($username);
        $this->record($username, $ip, $userAgent, false, $reason, $provider);

        // One message for every failure mode. Distinguishing "no such account"
        // from "wrong password" turns one guess into two easier problems.
        return ['ok' => false, 'message' => 'Benutzername oder Passwort ist falsch.'];
    }

    private function countFailure(string $username): void
    {
        $this->db->execute(
            'UPDATE users
                SET failed_logins = failed_logins + 1,
                    locked_until = CASE
                        WHEN failed_logins + 1 >= ? THEN now() + make_interval(secs => ?)
                        ELSE locked_until
                    END
              WHERE username = ?',
            [self::MAX_FAILURES, self::LOCKOUT_SECONDS, $username],
        );
    }

    private function lockedUntil(string $username): ?string
    {
        $value = $this->db->fetchValue(
            'SELECT locked_until FROM users WHERE username = ? AND locked_until > now()',
            [$username],
        );

        return $value === null || $value === false ? null : (string) $value;
    }

    private function ipIsThrottled(?string $ip): bool
    {
        if ($ip === null) {
            return false;
        }

        $failures = (int) $this->db->fetchValue(
            'SELECT count(*) FROM login_attempts
              WHERE ip = ?::inet AND NOT success AND ts > now() - make_interval(secs => ?)',
            [$ip, self::IP_WINDOW_SECONDS],
        );

        return $failures >= self::IP_MAX_ATTEMPTS;
    }

    private function record(
        string $username,
        ?string $ip,
        ?string $userAgent,
        bool $success,
        ?string $reason,
        ?string $provider,
    ): void {
        $this->db->execute(
            'INSERT INTO login_attempts (username, ip, provider, success, reason, user_agent)
             VALUES (?, ?::inet, ?, ?, ?, ?)',
            [
                mb_substr($username, 0, 200),
                $ip,
                $provider,
                $success ? 'true' : 'false',
                $reason,
                $userAgent === null ? null : mb_substr($userAgent, 0, 500),
            ],
        );
    }

    private function audit(string $username, string $action, array $details): void
    {
        $this->db->execute(
            'INSERT INTO audit_log (user_id, username, action, target, details, ip)
             VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?, ?::jsonb, ?::inet)',
            [
                $username,
                $username,
                $action,
                $username,
                json_encode($details, JSON_UNESCAPED_UNICODE),
                $details['ip'] ?? null,
            ],
        );
    }
}
