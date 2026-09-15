<?php

declare(strict_types=1);

namespace LogWarden\Core;

use RuntimeException;

/**
 * Configuration container.
 *
 * Values come from config/config.php. Any leaf can be overridden by an
 * environment variable named LW_ plus the dotted path in upper snake case,
 * so `db.password` is LW_DB_PASSWORD. That is what the systemd units use to
 * keep the database password out of the config file.
 */
final class Config
{
    private function __construct(private array $values)
    {
    }

    public static function load(?string $file = null): self
    {
        $file ??= LW_ROOT . '/config/config.php';

        if (!is_file($file)) {
            throw new RuntimeException(
                "Configuration not found at {$file}. Copy config/config.php.dist and adjust it."
            );
        }

        $values = require $file;
        if (!is_array($values)) {
            throw new RuntimeException("Configuration at {$file} must return an array.");
        }

        return new self($values);
    }

    public static function fromArray(array $values): self
    {
        return new self($values);
    }

    /**
     * Fetch a value by dotted path, e.g. get('db.host').
     */
    public function get(string $path, mixed $default = null): mixed
    {
        $env = getenv('LW_' . strtoupper(str_replace('.', '_', $path)));
        if ($env !== false) {
            return self::coerce($env);
        }

        $node = $this->values;
        foreach (explode('.', $path) as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return $default;
            }
            $node = $node[$segment];
        }

        return $node;
    }

    public function require(string $path): mixed
    {
        $value = $this->get($path);
        if ($value === null) {
            throw new RuntimeException("Required configuration key '{$path}' is missing.");
        }

        return $value;
    }

    public function section(string $path): array
    {
        $value = $this->get($path, []);

        return is_array($value) ? $value : [];
    }

    /**
     * Environment variables are always strings; map the obvious literals back
     * to their native types so LW_SYSLOG_UDP_PORT=514 does not arrive as text.
     */
    private static function coerce(string $raw): mixed
    {
        return match (strtolower($raw)) {
            'true'  => true,
            'false' => false,
            'null'  => null,
            default => match (true) {
                (bool) preg_match('/^-?\d+$/', $raw)          => (int) $raw,
                (bool) preg_match('/^-?\d*\.\d+$/', $raw)     => (float) $raw,
                default                                        => $raw,
            },
        };
    }
}
