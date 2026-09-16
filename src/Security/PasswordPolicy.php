<?php

declare(strict_types=1);

namespace LogWarden\Security;

use SensitiveParameter;

/**
 * Rules for local account passwords.
 *
 * Length over composition rules: a long passphrase beats a short string with a
 * digit and a symbol bolted on, and composition rules mostly produce
 * Sommer2026! — which is exactly what the rejection list catches.
 */
final class PasswordPolicy
{
    public const MIN_LENGTH = 12;
    public const MAX_LENGTH = 200;

    /** Patterns that keep showing up in this kind of installation. */
    private const REJECTED = [
        'password', 'passwort', 'kennwort', 'geheim', 'logwarden',
        'administrator', '123456', 'qwertz', 'qwerty', 'welcome',
        'willkommen', 'changeme', 'letmein', 'monitoring',
    ];

    /**
     * @return list<string> violations; empty means acceptable
     */
    public static function check(#[SensitiveParameter] string $password, string $username = ''): array
    {
        $errors = [];
        $length = mb_strlen($password);

        if ($length < self::MIN_LENGTH) {
            $errors[] = sprintf('Das Passwort muss mindestens %d Zeichen haben.', self::MIN_LENGTH);
        }

        if ($length > self::MAX_LENGTH) {
            $errors[] = sprintf('Das Passwort darf höchstens %d Zeichen haben.', self::MAX_LENGTH);
        }

        if (trim($password) !== $password) {
            $errors[] = 'Das Passwort darf nicht mit einem Leerzeichen beginnen oder enden.';
        }

        $lower = mb_strtolower($password);

        if ($username !== '' && str_contains($lower, mb_strtolower($username))) {
            $errors[] = 'Das Passwort darf den Benutzernamen nicht enthalten.';
        }

        foreach (self::REJECTED as $bad) {
            if (str_contains($lower, $bad)) {
                $errors[] = 'Das Passwort enthält einen zu naheliegenden Bestandteil.';
                break;
            }
        }

        // Three distinct characters over twelve positions is a pattern, not a
        // passphrase — "abababababab" passes a length check otherwise.
        if ($length >= self::MIN_LENGTH && count(array_unique(mb_str_split($lower))) < 5) {
            $errors[] = 'Das Passwort besteht aus zu wenigen verschiedenen Zeichen.';
        }

        return $errors;
    }

    public static function hash(#[SensitiveParameter] string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    public static function verify(#[SensitiveParameter] string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID);
    }

    /** For the bootstrap CLI, so the first admin password is not invented by a person under time pressure. */
    public static function suggest(): string
    {
        $words = [
            'Anker', 'Birke', 'Coder', 'Delta', 'Esche', 'Falke', 'Gipfel', 'Hafen',
            'Insel', 'Kiefer', 'Lawine', 'Meile', 'Norden', 'Otter', 'Pfeil', 'Quelle',
            'Raute', 'Segel', 'Turm', 'Ufer', 'Vogel', 'Welle', 'Zirkel',
        ];

        $parts = [];
        for ($i = 0; $i < 4; $i++) {
            $parts[] = $words[random_int(0, count($words) - 1)];
        }

        return implode('-', $parts) . '-' . random_int(10, 99);
    }
}
