<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Core\Db;
use LogWarden\Security\Authenticator;
use LogWarden\Security\SessionStore;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\View;

final class AuthController
{
    public function __construct(
        private readonly Authenticator $auth,
        private readonly SessionStore $sessions,
        private readonly Db $db,
        private readonly View $view,
        private readonly bool $secureCookies,
        private readonly bool $ldapEnabled,
    ) {
    }

    public function showLogin(?string $message = null, bool $isError = true): Response
    {
        return $this->renderLogin($message, $isError);
    }

    public function login(): Response
    {
        if (!Csrf::checkLoginToken($_POST['_csrf'] ?? null)) {
            // Usually a stale tab rather than an attack, so the wording is
            // about what to do rather than about what went wrong.
            return $this->renderLogin('Das Formular ist abgelaufen. Bitte erneut absenden.');
        }

        $username = (string) ($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');

        $result = $this->auth->login($username, $password, $this->clientIp(), $this->userAgent());

        if (!$result['ok']) {
            return $this->renderLogin($result['message'] ?? 'Anmeldung fehlgeschlagen.', true, $username);
        }

        $this->setSessionCookie($result['token']);
        Csrf::clearLoginToken($this->secureCookies);

        $target = $result['user']->mustChangePassword
            ? '/profile/password?forced=1'
            : $this->safeRedirect($_POST['next'] ?? null);

        return Response::redirect($target);
    }

    public function logout(): Response
    {
        $token = $_COOKIE[SessionStore::COOKIE] ?? null;

        if (is_string($token)) {
            $this->auth->logout($token);
        }

        setcookie(SessionStore::COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'httponly' => true,
            'secure'   => $this->secureCookies,
            'samesite' => 'Lax',
        ]);

        return Response::redirect('/login?abgemeldet=1');
    }

    // -----------------------------------------------------------------------

    private function renderLogin(?string $message = null, bool $isError = true, string $username = ''): Response
    {
        $branding = $this->db->fetchRow('SELECT * FROM branding WHERE id = 1') ?? [];

        $html = $this->view->render('login', [
            'title'        => 'Anmeldung',
            'branding'     => $branding,
            'assets'       => $this->assetIndex(),
            'csrf'         => Csrf::issueLoginToken($this->secureCookies),
            'message'      => $message,
            'isError'      => $isError,
            'username'     => $username,
            'ldapEnabled'  => $this->ldapEnabled,
            'next'         => $this->safeRedirect($_GET['next'] ?? null),
            'loggedOut'    => isset($_GET['abgemeldet']),
            'sessionEnded' => isset($_GET['abgelaufen']),
        ]);

        // 401 on a rejected attempt so a proxy or a log can tell the difference
        // between "showed the form" and "refused a credential".
        return Response::html($html, $message !== null && $isError ? 401 : 200);
    }

    /** @return array<string, array<string, mixed>> */
    private function assetIndex(): array
    {
        $index = [];

        foreach ($this->db->fetchAll('SELECT slot, mime_type FROM branding_assets') as $row) {
            $index[(string) $row['slot']] = $row;
        }

        return $index;
    }

    private function setSessionCookie(string $token): void
    {
        setcookie(SessionStore::COOKIE, $token, [
            // No expiry: the session ends when the row does, which is the only
            // place that decides. A browser-side lifetime would drift from it.
            'expires'  => 0,
            'path'     => '/',
            'httponly' => true,
            'secure'   => $this->secureCookies,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Only paths within this application, so a crafted ?next= cannot bounce
     * someone to another host straight after they authenticate.
     */
    private function safeRedirect(mixed $next): string
    {
        if (!is_string($next) || $next === '') {
            return '/';
        }

        // Rejects "//evil.example", "https://…", "\\evil" and anything with a
        // scheme or authority.
        if (!str_starts_with($next, '/') || str_starts_with($next, '//') || str_contains($next, '\\')) {
            return '/';
        }

        if (parse_url($next, PHP_URL_HOST) !== null || parse_url($next, PHP_URL_SCHEME) !== null) {
            return '/';
        }

        return $next;
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    private function userAgent(): ?string
    {
        $agent = $_SERVER['HTTP_USER_AGENT'] ?? null;

        return is_string($agent) ? $agent : null;
    }
}
