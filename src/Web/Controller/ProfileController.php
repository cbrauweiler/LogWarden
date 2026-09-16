<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Core\Db;
use LogWarden\Security\CurrentUser;
use LogWarden\Security\PasswordPolicy;
use LogWarden\Security\Permission;
use LogWarden\Security\SessionStore;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\View;

/**
 * The signed-in account's own page: who you are, what you may do, where you
 * are signed in, and your password.
 */
final class ProfileController
{
    public function __construct(
        private readonly Db $db,
        private readonly SessionStore $sessions,
        private readonly View $view,
        private readonly CurrentUser $user,
    ) {
    }

    public function show(array $flash = [], array $errors = []): Response
    {
        return Response::html($this->view->page('profile', [
            'title'       => 'Profil',
            'active'      => 'profile',
            'account'     => $this->account(),
            'sessions'    => $this->sessions->listForUser($this->user->id),
            'logins'      => $this->recentLogins(),
            'permissions' => $this->user->role->permissions(),
            'allLabels'   => Permission::LABELS,
            'flash'       => $flash,
            'errors'      => $errors,
        ]));
    }

    public function showPasswordForm(array $errors = []): Response
    {
        if (!$this->user->isLocal()) {
            return Response::html($this->view->page('password_external', [
                'title'  => 'Passwort ändern',
                'active' => 'profile',
                'user'   => $this->user,
            ]));
        }

        return Response::html($this->view->page('password', [
            'title'    => 'Passwort ändern',
            'active'   => 'profile',
            'forced'   => isset($_GET['forced']) || $this->user->mustChangePassword,
            'minimum'  => PasswordPolicy::MIN_LENGTH,
            'errors'   => $errors,
        ]));
    }

    public function changePassword(): Response
    {
        if (!Csrf::check($_POST['_csrf'] ?? null)) {
            return $this->showPasswordForm(['Sicherheits-Token abgelaufen. Bitte erneut absenden.']);
        }

        if (!$this->user->isLocal()) {
            // A directory account's password lives in the directory; changing
            // it here would create a second, diverging truth.
            return $this->showPasswordForm(['Für Verzeichniskonten wird das Passwort im Active Directory geändert.']);
        }

        $current = (string) ($_POST['current_password'] ?? '');
        $new     = (string) ($_POST['new_password'] ?? '');
        $repeat  = (string) ($_POST['repeat_password'] ?? '');

        $hash = (string) $this->db->fetchValue('SELECT password_hash FROM users WHERE id = ?', [$this->user->id]);

        if (!PasswordPolicy::verify($current, $hash)) {
            $this->audit('auth.password_change_failed', ['reason' => 'wrong_current']);

            return $this->showPasswordForm(['Das aktuelle Passwort ist falsch.']);
        }

        if ($new !== $repeat) {
            return $this->showPasswordForm(['Die beiden neuen Passwörter stimmen nicht überein.']);
        }

        if (PasswordPolicy::verify($new, $hash)) {
            return $this->showPasswordForm(['Das neue Passwort muss sich vom bisherigen unterscheiden.']);
        }

        $violations = PasswordPolicy::check($new, $this->user->username);

        if ($violations !== []) {
            return $this->showPasswordForm($violations);
        }

        $this->db->execute(
            'UPDATE users
                SET password_hash = ?, password_changed_at = now(), must_change_password = false
              WHERE id = ?',
            [PasswordPolicy::hash($new), $this->user->id],
        );

        // Every other session for this account goes. If the password was
        // changed because it may have leaked, leaving the other sessions alive
        // would defeat the point.
        $ended = $this->sessions->destroyOthers($this->user->id, $this->user->sessionId);

        $this->audit('auth.password_changed', ['sessions_ended' => $ended]);

        return Response::redirect('/profile?passwort=1&beendet=' . $ended);
    }

    public function revokeSession(): Response
    {
        if (!Csrf::check($_POST['_csrf'] ?? null)) {
            return Response::redirect('/profile');
        }

        $id = (string) ($_POST['session_id'] ?? '');

        if ($id === $this->user->sessionId) {
            return Response::redirect('/profile?fehler=selbst');
        }

        $this->sessions->destroyById($id, $this->user->id);
        $this->audit('auth.session_revoked', ['session' => substr($id, 0, 12)]);

        return Response::redirect('/profile?sitzung=1');
    }

    // -----------------------------------------------------------------------

    /** @return array<string, mixed> */
    private function account(): array
    {
        $row = $this->db->fetchRow(
            "SELECT username, display_name, email, auth_provider, role::text AS role, role_source,
                    enabled, must_change_password, ldap_groups, role_matched_by,
                    host(last_login_ip) AS last_login_ip,
                    to_char(created_at,          'DD.MM.YYYY HH24:MI') AS created_label,
                    to_char(last_login_at,       'DD.MM.YYYY HH24:MI') AS last_login_label,
                    to_char(password_changed_at, 'DD.MM.YYYY HH24:MI') AS password_changed_label
               FROM users WHERE id = ?",
            [$this->user->id],
        ) ?? [];

        $groups = json_decode((string) ($row['ldap_groups'] ?? '[]'), true);
        $row['ldap_groups'] = is_array($groups) ? $groups : [];

        return $row;
    }

    /** @return list<array<string, mixed>> */
    private function recentLogins(): array
    {
        return $this->db->fetchAll(
            "SELECT success, provider, reason, host(ip) AS ip,
                    to_char(ts, 'DD.MM.YYYY HH24:MI:SS') AS ts_label
               FROM login_attempts
              WHERE lower(username) = lower(?)
              ORDER BY ts DESC
              LIMIT 15",
            [$this->user->username],
        );
    }

    private function audit(string $action, array $details): void
    {
        $this->db->execute(
            'INSERT INTO audit_log (user_id, username, action, target, details)
             VALUES (?, ?, ?, ?, ?::jsonb)',
            [
                $this->user->id,
                $this->user->username,
                $action,
                $this->user->username,
                json_encode($details, JSON_UNESCAPED_UNICODE),
            ],
        );
    }
}
