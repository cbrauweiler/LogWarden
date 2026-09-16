<?php

declare(strict_types=1);

namespace LogWarden\Web;

/**
 * CSRF tokens.
 *
 * The token belongs to the database session rather than to PHP's own session
 * storage, so there is exactly one session mechanism: ending a session in the
 * table really ends it, including its token.
 *
 * The login form has no session yet, so it uses a separate short-lived cookie
 * token. Login CSRF is not harmless — it can silently sign a victim into an
 * account the attacker controls, and everything they then look at goes into
 * that account's history.
 */
final class Csrf
{
    public const LOGIN_COOKIE = 'lw_login_csrf';

    private static ?string $token = null;

    /** Called once per request from the front controller. */
    public static function use(?string $token): void
    {
        self::$token = $token;
    }

    public static function token(): string
    {
        return self::$token ?? '';
    }

    public static function check(?string $candidate): bool
    {
        $expected = self::$token;

        return is_string($candidate)
            && is_string($expected)
            && $expected !== ''
            && hash_equals($expected, $candidate);
    }

    public static function field(): string
    {
        return '<input type="hidden" name="_csrf" value="' . View::e(self::token()) . '">';
    }

    // --- Login form -------------------------------------------------------

    /**
     * Issues (or reuses) the pre-session token for the login form.
     */
    public static function issueLoginToken(bool $secure): string
    {
        $existing = $_COOKIE[self::LOGIN_COOKIE] ?? null;

        if (is_string($existing) && preg_match('/^[a-f0-9]{64}$/', $existing)) {
            return $existing;
        }

        $token = bin2hex(random_bytes(32));

        setcookie(self::LOGIN_COOKIE, $token, [
            'expires'  => time() + 1800,
            'path'     => '/',
            'httponly' => true,
            'secure'   => $secure,
            'samesite' => 'Lax',
        ]);

        return $token;
    }

    public static function checkLoginToken(?string $candidate): bool
    {
        $expected = $_COOKIE[self::LOGIN_COOKIE] ?? null;

        return is_string($candidate)
            && is_string($expected)
            && preg_match('/^[a-f0-9]{64}$/', $expected) === 1
            && hash_equals($expected, $candidate);
    }

    public static function clearLoginToken(bool $secure): void
    {
        setcookie(self::LOGIN_COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'httponly' => true,
            'secure'   => $secure,
            'samesite' => 'Lax',
        ]);
    }
}
