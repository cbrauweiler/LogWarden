<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Core\Db;
use LogWarden\Security\AuthProviderInterface;
use LogWarden\Security\CurrentUser;
use LogWarden\Security\PasswordPolicy;
use LogWarden\Security\Role;
use LogWarden\Security\SessionStore;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\View;
use Throwable;

/**
 * Administration of accounts and of what grants which permission level.
 */
final class UserAdminController
{
    /** @param array<string, AuthProviderInterface> $providers */
    public function __construct(
        private readonly Db $db,
        private readonly SessionStore $sessions,
        private readonly View $view,
        private readonly CurrentUser $actor,
        private readonly array $providers = [],
    ) {
    }

    public function show(array $flash = [], array $errors = []): Response
    {
        return Response::html($this->view->page('admin/users', [
            'title'      => 'Benutzer und Berechtigungen',
            'active'     => 'users',
            'users'      => $this->users(),
            'mappings'   => $this->mappings(),
            'roles'      => Role::all(),
            'directory'  => $this->directoryHealth(),
            'suggestion' => PasswordPolicy::suggest(),
            'minimum'    => PasswordPolicy::MIN_LENGTH,
            'flash'      => $flash,
            'errors'     => $errors,
        ]));
    }

    public function save(): Response
    {
        if (!Csrf::check($_POST['_csrf'] ?? null)) {
            return $this->show([], ['Sicherheits-Token abgelaufen. Bitte erneut absenden.']);
        }

        try {
            return match ((string) ($_POST['action'] ?? '')) {
                'add_mapping'      => $this->addMapping(),
                'delete_mapping'   => $this->deleteMapping(),
                'toggle_mapping'   => $this->toggleMapping(),
                'create_local'     => $this->createLocal(),
                'set_role'         => $this->setRole(),
                'toggle_enabled'   => $this->toggleEnabled(),
                'reset_password'   => $this->resetPassword(),
                'reset_lockout'    => $this->resetLockout(),
                'revoke_sessions'  => $this->revokeSessions(),
                'delete_user'      => $this->deleteUser(),
                default            => $this->show([], ['Unbekannte Aktion.']),
            };
        } catch (Throwable $e) {
            return $this->show([], [$e->getMessage()]);
        }
    }

    // --- Mappings ----------------------------------------------------------

    private function addMapping(): Response
    {
        $type    = (string) ($_POST['subject_type'] ?? 'group');
        $subject = trim((string) ($_POST['subject'] ?? ''));
        $role    = Role::tryFromName((string) ($_POST['role'] ?? ''));
        $prio    = max(0, min(999, (int) ($_POST['priority'] ?? 100)));
        $note    = trim((string) ($_POST['description'] ?? ''));

        $errors = [];
        if (!in_array($type, ['group', 'user'], true)) { $errors[] = 'Unbekannter Zuordnungstyp.'; }
        if ($subject === '')      { $errors[] = 'Gruppe oder Konto darf nicht leer sein.'; }
        if (mb_strlen($subject) > 500) { $errors[] = 'Der Eintrag ist zu lang.'; }
        if ($role === null)       { $errors[] = 'Unbekannte Berechtigungsstufe.'; }

        if ($errors !== []) {
            return $this->show([], $errors);
        }

        $exists = $this->db->fetchValue(
            'SELECT 1 FROM ldap_role_map WHERE subject_type = ? AND lower(subject) = lower(?)',
            [$type, $subject],
        );

        if ($exists !== null) {
            return $this->show([], ['Für diesen Eintrag existiert bereits eine Zuordnung.']);
        }

        $this->db->execute(
            'INSERT INTO ldap_role_map (subject_type, subject, role, priority, description, created_by)
             VALUES (?, ?, ?::user_role_t, ?, ?, ?)',
            [$type, $subject, $role->value, $prio, $note === '' ? null : $note, $this->actor->username],
        );

        $this->audit('rbac.mapping.add', $subject, ['type' => $type, 'role' => $role->value, 'priority' => $prio]);

        return Response::redirect('/settings/users?zuordnung=1');
    }

    private function deleteMapping(): Response
    {
        $id  = (int) ($_POST['mapping_id'] ?? 0);
        $row = $this->db->fetchRow('SELECT subject, subject_type FROM ldap_role_map WHERE id = ?', [$id]);

        if ($row === null) {
            return $this->show([], ['Zuordnung nicht gefunden.']);
        }

        $this->db->execute('DELETE FROM ldap_role_map WHERE id = ?', [$id]);
        $this->audit('rbac.mapping.delete', (string) $row['subject'], ['type' => $row['subject_type']]);

        return Response::redirect('/settings/users?zuordnung_geloescht=1');
    }

    private function toggleMapping(): Response
    {
        $id = (int) ($_POST['mapping_id'] ?? 0);
        $this->db->execute('UPDATE ldap_role_map SET enabled = NOT enabled WHERE id = ?', [$id]);
        $this->audit('rbac.mapping.toggle', (string) $id, []);

        return Response::redirect('/settings/users?zuordnung=1');
    }

    // --- Accounts ----------------------------------------------------------

    private function createLocal(): Response
    {
        $username = mb_strtolower(trim((string) ($_POST['username'] ?? '')));
        $display  = trim((string) ($_POST['display_name'] ?? ''));
        $email    = trim((string) ($_POST['email'] ?? ''));
        $role     = Role::tryFromName((string) ($_POST['role'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        $errors = [];

        if (preg_match('/^[a-z0-9._-]{3,64}$/', $username) !== 1) {
            $errors[] = 'Benutzername: 3–64 Zeichen, erlaubt sind a–z, 0–9, Punkt, Unterstrich und Bindestrich.';
        }
        if ($role === null) {
            $errors[] = 'Unbekannte Berechtigungsstufe.';
        }
        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'Die E-Mail-Adresse ist ungültig.';
        }

        $errors = array_merge($errors, PasswordPolicy::check($password, $username));

        if ($errors !== []) {
            return $this->show([], $errors);
        }

        if ($this->db->fetchValue('SELECT 1 FROM users WHERE username = ?', [$username]) !== null) {
            return $this->show([], ["Ein Konto namens '{$username}' existiert bereits."]);
        }

        $this->db->execute(
            "INSERT INTO users (username, display_name, email, auth_provider, password_hash,
                                role, role_source, enabled, must_change_password, password_changed_at)
             VALUES (?, ?, ?, 'local', ?, ?::user_role_t, 'manual', true, true, now())",
            [
                $username,
                $display === '' ? null : $display,
                $email === '' ? null : $email,
                PasswordPolicy::hash($password),
                $role->value,
            ],
        );

        $this->audit('user.create', $username, ['role' => $role->value, 'provider' => 'local']);

        return Response::redirect('/settings/users?angelegt=' . urlencode($username));
    }

    private function setRole(): Response
    {
        $id   = (int) ($_POST['user_id'] ?? 0);
        $role = Role::tryFromName((string) ($_POST['role'] ?? ''));
        $user = $this->db->fetchRow('SELECT username, role::text AS role FROM users WHERE id = ?', [$id]);

        if ($user === null || $role === null) {
            return $this->show([], ['Konto oder Berechtigungsstufe nicht gefunden.']);
        }

        if ($id === $this->actor->id && $role !== Role::Admin && $this->isLastAdmin($id)) {
            return $this->show([], ['Das ist das letzte Administratorkonto — es kann sich nicht selbst herabstufen.']);
        }

        // role_source = manual so the next directory login does not overwrite
        // the decision that was just made here.
        $this->db->execute(
            "UPDATE users SET role = ?::user_role_t, role_source = 'manual', role_matched_by = 'Manuell zugewiesen'
              WHERE id = ?",
            [$role->value, $id],
        );

        $this->audit('user.role', (string) $user['username'], ['from' => $user['role'], 'to' => $role->value]);

        return Response::redirect('/settings/users?rolle=1');
    }

    private function toggleEnabled(): Response
    {
        $id   = (int) ($_POST['user_id'] ?? 0);
        $user = $this->db->fetchRow('SELECT username, enabled FROM users WHERE id = ?', [$id]);

        if ($user === null) {
            return $this->show([], ['Konto nicht gefunden.']);
        }

        if ($user['enabled'] && $this->isLastAdmin($id)) {
            return $this->show([], ['Das letzte Administratorkonto kann nicht deaktiviert werden.']);
        }

        $this->db->execute('UPDATE users SET enabled = NOT enabled WHERE id = ?', [$id]);

        // Disabling has to take effect now, not at the next session expiry.
        if ($user['enabled']) {
            $this->sessions->destroyAllForUser($id);
        }

        $this->audit('user.enabled', (string) $user['username'], ['enabled' => !$user['enabled']]);

        return Response::redirect('/settings/users?konto=1');
    }

    private function resetPassword(): Response
    {
        $id       = (int) ($_POST['user_id'] ?? 0);
        $password = (string) ($_POST['password'] ?? '');
        $user     = $this->db->fetchRow('SELECT username, auth_provider FROM users WHERE id = ?', [$id]);

        if ($user === null) {
            return $this->show([], ['Konto nicht gefunden.']);
        }

        if ($user['auth_provider'] !== 'local') {
            return $this->show([], ['Für Verzeichniskonten wird das Passwort im Active Directory gesetzt.']);
        }

        $violations = PasswordPolicy::check($password, (string) $user['username']);

        if ($violations !== []) {
            return $this->show([], $violations);
        }

        $this->db->execute(
            'UPDATE users
                SET password_hash = ?, password_changed_at = now(), must_change_password = true,
                    failed_logins = 0, locked_until = NULL
              WHERE id = ?',
            [PasswordPolicy::hash($password), $id],
        );

        $this->sessions->destroyAllForUser($id);
        $this->audit('user.password_reset', (string) $user['username'], []);

        return Response::redirect('/settings/users?passwort=1');
    }

    private function resetLockout(): Response
    {
        $id   = (int) ($_POST['user_id'] ?? 0);
        $user = $this->db->fetchRow('SELECT username FROM users WHERE id = ?', [$id]);

        if ($user === null) {
            return $this->show([], ['Konto nicht gefunden.']);
        }

        $this->db->execute('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?', [$id]);
        $this->audit('user.unlock', (string) $user['username'], []);

        return Response::redirect('/settings/users?entsperrt=1');
    }

    private function revokeSessions(): Response
    {
        $id    = (int) ($_POST['user_id'] ?? 0);
        $user  = $this->db->fetchRow('SELECT username FROM users WHERE id = ?', [$id]);
        $count = $this->sessions->destroyAllForUser($id);

        $this->audit('user.sessions_revoked', (string) ($user['username'] ?? $id), ['count' => $count]);

        return Response::redirect('/settings/users?sitzungen=' . $count);
    }

    private function deleteUser(): Response
    {
        $id   = (int) ($_POST['user_id'] ?? 0);
        $user = $this->db->fetchRow('SELECT username FROM users WHERE id = ?', [$id]);

        if ($user === null) {
            return $this->show([], ['Konto nicht gefunden.']);
        }

        if ($id === $this->actor->id) {
            return $this->show([], ['Das eigene Konto kann nicht gelöscht werden.']);
        }

        if ($this->isLastAdmin($id)) {
            return $this->show([], ['Das letzte Administratorkonto kann nicht gelöscht werden.']);
        }

        $this->db->execute('DELETE FROM users WHERE id = ?', [$id]);
        $this->audit('user.delete', (string) $user['username'], []);

        return Response::redirect('/settings/users?geloescht=1');
    }

    // -----------------------------------------------------------------------

    /**
     * Locking the last administrator out of the system is a support call that
     * ends with editing the database by hand.
     */
    private function isLastAdmin(int $id): bool
    {
        $others = (int) $this->db->fetchValue(
            "SELECT count(*) FROM users WHERE role = 'admin' AND enabled AND id <> ?",
            [$id],
        );

        return $others === 0;
    }

    /** @return list<array<string, mixed>> */
    private function users(): array
    {
        return $this->db->fetchAll(
            "SELECT u.id, u.username, u.display_name, u.email, u.auth_provider,
                    u.role::text AS role, u.role_source, u.role_matched_by, u.enabled,
                    u.must_change_password, u.failed_logins,
                    u.locked_until > now() AS locked,
                    to_char(u.last_login_at, 'DD.MM. HH24:MI') AS last_login_label,
                    to_char(u.created_at,    'DD.MM.YYYY')     AS created_label,
                    (SELECT count(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > now()) AS sessions
               FROM users u
              ORDER BY u.auth_provider, u.username"
        );
    }

    /** @return list<array<string, mixed>> */
    private function mappings(): array
    {
        return $this->db->fetchAll(
            "SELECT id, subject_type, subject, role::text AS role, priority, description, enabled,
                    created_by,
                    to_char(created_at, 'DD.MM.YYYY') AS created_label,
                    (SELECT count(*) FROM users u
                      WHERE u.role_matched_by = CASE WHEN m.subject_type = 'user'
                            THEN 'Konto: ' || m.subject ELSE 'Gruppe: ' || m.subject END) AS matched_users
               FROM ldap_role_map m
              ORDER BY priority DESC, subject_type, subject"
        );
    }

    /** @return array<string, array{ok: bool, message: string}> */
    private function directoryHealth(): array
    {
        $health = [];

        foreach ($this->providers as $name => $provider) {
            $result = $provider->healthCheck();
            $health[$name] = [
                'ok'      => $result->success,
                'message' => $result->success ? 'erreichbar' : ($result->reason ?? 'nicht erreichbar'),
            ];
        }

        return $health;
    }

    private function audit(string $action, string $target, array $details): void
    {
        $this->db->execute(
            'INSERT INTO audit_log (user_id, username, action, target, details)
             VALUES (?, ?, ?, ?, ?::jsonb)',
            [
                $this->actor->id,
                $this->actor->username,
                $action,
                $target,
                json_encode($details, JSON_UNESCAPED_UNICODE),
            ],
        );
    }
}
