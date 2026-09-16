<?php

declare(strict_types=1);

namespace LogWarden\Security;

use LogWarden\Core\Db;
use RuntimeException;
use SensitiveParameter;

/**
 * Encrypted storage for ingestion credentials and webhook URLs.
 *
 * Uses libsodium's authenticated secretbox (XSalsa20-Poly1305) with a master
 * key held in a file outside the web root. Authenticated encryption matters
 * here: it makes tampering with a stored webhook URL detectable rather than
 * silently redirecting alerts somewhere else.
 */
final class SecretBox
{
    private const KEY_BYTES = SODIUM_CRYPTO_SECRETBOX_KEYBYTES;

    private function __construct(
        #[SensitiveParameter] private readonly string $key,
        private readonly Db $db,
    ) {
    }

    public static function open(string $keyFile, Db $db): self
    {
        if (!is_file($keyFile)) {
            throw new RuntimeException("Master key not found at {$keyFile}. Generate one with bin/logwarden-keygen.");
        }

        $perms = fileperms($keyFile);
        if ($perms !== false && ($perms & 0o077) !== 0) {
            throw new RuntimeException(
                "Master key {$keyFile} is group/world accessible. Run: chmod 600 {$keyFile}"
            );
        }

        $raw = trim((string) file_get_contents($keyFile));
        $key = base64_decode($raw, true);

        if ($key === false || strlen($key) !== self::KEY_BYTES) {
            throw new RuntimeException("Master key {$keyFile} is malformed; expected a base64 32-byte key.");
        }

        return new self($key, $db);
    }

    public static function generateKey(): string
    {
        return base64_encode(sodium_crypto_secretbox_keygen());
    }

    public function put(string $refName, #[SensitiveParameter] string $plaintext): void
    {
        $nonce      = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $this->key);

        // Hex plus decode() rather than binding the raw bytes: PDO's pgsql
        // driver sends a bound string as text, and PostgreSQL rejects any byte
        // sequence that is not valid UTF-8 — which ciphertext routinely is not.
        $this->db->execute(
            "INSERT INTO secrets (ref_name, ciphertext, nonce, key_version)
             VALUES (?, decode(?, 'hex'), decode(?, 'hex'), 1)
             ON CONFLICT (ref_name) DO UPDATE
                SET ciphertext = EXCLUDED.ciphertext,
                    nonce      = EXCLUDED.nonce,
                    updated_at = now()",
            [$refName, bin2hex($ciphertext), bin2hex($nonce)],
        );
    }

    public function get(string $refName): ?string
    {
        $row = $this->db->fetchRow(
            'SELECT ciphertext, nonce FROM secrets WHERE ref_name = ?',
            [$refName],
        );

        if ($row === null) {
            return null;
        }

        $ciphertext = self::toBinary($row['ciphertext']);
        $nonce      = self::toBinary($row['nonce']);

        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->key);

        if ($plaintext === false) {
            throw new RuntimeException(
                "Secret '{$refName}' failed authentication. The master key changed or the row was tampered with."
            );
        }

        return $plaintext;
    }

    public function delete(string $refName): void
    {
        $this->db->execute('DELETE FROM secrets WHERE ref_name = ?', [$refName]);
    }

    /** @return list<string> */
    public function listRefs(): array
    {
        return array_column($this->db->fetchAll('SELECT ref_name FROM secrets ORDER BY ref_name'), 'ref_name');
    }

    /**
     * PDO returns pgsql bytea either as a stream or as a hex-escaped string
     * depending on driver build, so normalise both.
     */
    private static function toBinary(mixed $value): string
    {
        if (is_resource($value)) {
            return (string) stream_get_contents($value);
        }

        $value = (string) $value;

        if (str_starts_with($value, '\\x')) {
            $decoded = hex2bin(substr($value, 2));
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return $value;
    }
}
