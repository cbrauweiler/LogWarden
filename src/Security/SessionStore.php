<?php

declare(strict_types=1);

namespace LogWarden\Security;

use LogWarden\Core\Db;

/**
 * Database-backed sessions.
 *
 * Not PHP's own session handling, for one reason that matters: an
 * administrator has to be able to end someone's session, and with PHP sessions
 * that means finding a file on whichever node happened to serve them. Here it
 * is a DELETE.
 *
 * The cookie carries a random token; the table stores only its SHA-256. A
 * database dump therefore does not hand out live sessions.
 */
final class SessionStore
{
    public const COOKIE = 'lw_session';

    public function __construct(
        private readonly Db $db,
        private readonly int $idleTtl = 3600,
        private readonly int $absoluteTtl = 28800,
    ) {
    }

    /**
     * @return array{token: string, csrf: string, id: string}
     */
    public function create(int $userId, ?string $ip, ?string $userAgent): array
    {
        $token = bin2hex(random_bytes(32));
        $id    = hash('sha256', $token);
        $csrf  = bin2hex(random_bytes(32));

        $this->db->execute(
            'INSERT INTO sessions (id, user_id, expires_at, absolute_expires_at, csrf_token, ip, user_agent)
             VALUES (?, ?, now() + make_interval(secs => ?), now() + make_interval(secs => ?), ?, ?::inet, ?)',
            [
                $id,
                $userId,
                $this->idleTtl,
                $this->absoluteTtl,
                $csrf,
                $ip,
                $userAgent === null ? null : mb_substr($userAgent, 0, 500),
            ],
        );

        return ['token' => $token, 'csrf' => $csrf, 'id' => $id];
    }

    /**
     * Resolves a cookie value to the account behind it, refreshing the idle
     * window. Returns null for anything expired, revoked or disabled.
     */
    public function resolve(?string $token): ?CurrentUser
    {
        if ($token === null || !preg_match('/^[a-f0-9]{64}$/', $token)) {
            return null;
        }

        $id = hash('sha256', $token);

        $row = $this->db->fetchRow(
            "SELECT s.id AS session_id, s.csrf_token,
                    u.id, u.username, u.display_name, u.email, u.role::text AS role,
                    u.auth_provider, u.must_change_password, u.enabled,
                    u.ldap_groups, u.role_matched_by,
                    to_char(u.last_login_at, 'DD.MM.YYYY HH24:MI') AS last_login_at
               FROM sessions s
               JOIN users u ON u.id = s.user_id
              WHERE s.id = ?
                AND s.expires_at > now()
                AND s.absolute_expires_at > now()",
            [$id],
        );

        if ($row === null) {
            return null;
        }

        // A disabled account keeps its session row but must stop working
        // immediately — that is the whole point of disabling it.
        if (!$row['enabled']) {
            $this->destroy($token);

            return null;
        }

        $role = Role::tryFromName((string) $row['role']);

        if ($role === null) {
            $this->destroy($token);

            return null;
        }

        // Slide the idle window, never the absolute one: a stolen session must
        // not be extendable indefinitely by using it.
        $this->db->execute(
            'UPDATE sessions
                SET last_seen  = now(),
                    expires_at = LEAST(now() + make_interval(secs => ?), absolute_expires_at)
              WHERE id = ?',
            [$this->idleTtl, $id],
        );

        $groups = json_decode((string) $row['ldap_groups'], true);

        return new CurrentUser(
            id:                 (int) $row['id'],
            username:           (string) $row['username'],
            displayName:        $row['display_name'],
            email:              $row['email'],
            role:               $role,
            authProvider:       (string) $row['auth_provider'],
            mustChangePassword: (bool) $row['must_change_password'],
            sessionId:          (string) $row['session_id'],
            csrfToken:          (string) $row['csrf_token'],
            ldapGroups:         is_array($groups) ? $groups : [],
            roleMatchedBy:      $row['role_matched_by'],
            lastLoginAt:        $row['last_login_at'],
        );
    }

    public function destroy(string $token): void
    {
        $this->db->execute('DELETE FROM sessions WHERE id = ?', [hash('sha256', $token)]);
    }

    public function destroyById(string $sessionId, int $userId): void
    {
        $this->db->execute('DELETE FROM sessions WHERE id = ? AND user_id = ?', [$sessionId, $userId]);
    }

    /** Used after a password change: every other session has to go. */
    public function destroyOthers(int $userId, string $keepSessionId): int
    {
        return $this->db->execute(
            'DELETE FROM sessions WHERE user_id = ? AND id <> ?',
            [$userId, $keepSessionId],
        );
    }

    public function destroyAllForUser(int $userId): int
    {
        return $this->db->execute('DELETE FROM sessions WHERE user_id = ?', [$userId]);
    }

    /** @return list<array<string, mixed>> */
    public function listForUser(int $userId): array
    {
        return $this->db->fetchAll(
            "SELECT id, host(ip) AS ip, user_agent,
                    to_char(created_at, 'DD.MM.YYYY HH24:MI') AS created_label,
                    to_char(last_seen,  'DD.MM.YYYY HH24:MI') AS last_seen_label,
                    to_char(expires_at, 'DD.MM.YYYY HH24:MI') AS expires_label
               FROM sessions
              WHERE user_id = ? AND expires_at > now()
              ORDER BY last_seen DESC",
            [$userId],
        );
    }

    public function pruneExpired(): int
    {
        return $this->db->execute(
            'DELETE FROM sessions WHERE expires_at < now() OR absolute_expires_at < now()'
        );
    }
}
