<?php

declare(strict_types=1);

namespace LogWarden\Core;

use Stringable;
use Throwable;

/**
 * Minimal leveled logger. Writes line-oriented records to a file and, for the
 * daemons, to stderr so systemd/journald picks them up.
 */
final class Logger
{
    private const LEVELS = ['debug' => 10, 'info' => 20, 'warning' => 30, 'error' => 40];

    private int $threshold;

    /** @var resource|null */
    private $handle = null;

    public function __construct(
        private readonly ?string $path = null,
        string $level = 'info',
        private readonly bool $stderr = true,
        private readonly string $channel = 'logwarden',
    ) {
        $this->threshold = self::LEVELS[$level] ?? self::LEVELS['info'];
    }

    public static function fromConfig(Config $config, string $channel = 'logwarden'): self
    {
        return new self(
            $config->get('log.path'),
            (string) $config->get('log.level', 'info'),
            (bool) $config->get('log.stderr', true),
            $channel,
        );
    }

    public function withChannel(string $channel): self
    {
        return new self($this->path, array_search($this->threshold, self::LEVELS, true) ?: 'info', $this->stderr, $channel);
    }

    public function debug(string|Stringable $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    public function info(string|Stringable $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    public function warning(string|Stringable $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    public function error(string|Stringable $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    public function exception(Throwable $e, string $message = 'Unhandled exception'): void
    {
        $this->error($message, [
            'exception' => $e::class,
            'message'   => $e->getMessage(),
            'file'      => $e->getFile() . ':' . $e->getLine(),
        ]);
    }

    public function log(string $level, string|Stringable $message, array $context = []): void
    {
        if ((self::LEVELS[$level] ?? 0) < $this->threshold) {
            return;
        }

        $line = sprintf(
            "%s %-7s [%s] %s%s\n",
            gmdate('Y-m-d\TH:i:s\Z'),
            strtoupper($level),
            $this->channel,
            (string) $message,
            $context === [] ? '' : ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        );

        if ($this->stderr) {
            fwrite(STDERR, $line);
        }

        if ($this->path !== null) {
            $this->handle ??= @fopen($this->path, 'ab');
            if ($this->handle !== false && $this->handle !== null) {
                fwrite($this->handle, $line);
            }
        }
    }
}
