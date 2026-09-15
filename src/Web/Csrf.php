<?php

declare(strict_types=1);

namespace LogWarden\Web;

/**
 * Per-session CSRF token. The branding form changes what every user sees, so
 * it must not be submittable from another origin.
 */
final class Csrf
{
    private const KEY = 'lw_csrf';

    public static function token(): string
    {
        if (empty($_SESSION[self::KEY])) {
            $_SESSION[self::KEY] = bin2hex(random_bytes(32));
        }

        return (string) $_SESSION[self::KEY];
    }

    public static function check(?string $candidate): bool
    {
        $expected = $_SESSION[self::KEY] ?? '';

        return is_string($candidate)
            && $expected !== ''
            && hash_equals((string) $expected, $candidate);
    }

    public static function field(): string
    {
        return '<input type="hidden" name="_csrf" value="' . View::e(self::token()) . '">';
    }
}
