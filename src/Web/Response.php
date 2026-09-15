<?php

declare(strict_types=1);

namespace LogWarden\Web;

final class Response
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly string $body,
        public readonly int $status = 200,
        public readonly array $headers = [],
    ) {
    }

    public static function html(string $body, int $status = 200): self
    {
        return new self($body, $status, ['Content-Type' => 'text/html; charset=utf-8']);
    }

    /** @param array<string, string> $headers */
    public static function css(string $body, array $headers = []): self
    {
        return new self($body, 200, ['Content-Type' => 'text/css; charset=utf-8'] + $headers);
    }

    public static function redirect(string $location, int $status = 303): self
    {
        return new self('', $status, ['Location' => $location]);
    }

    public static function notFound(string $body = 'Not found'): self
    {
        return new self($body, 404, ['Content-Type' => 'text/plain; charset=utf-8']);
    }

    /** @param list<string> $allowed */
    public static function methodNotAllowed(array $allowed): self
    {
        return new self('Method not allowed', 405, [
            'Content-Type' => 'text/plain; charset=utf-8',
            'Allow'        => implode(', ', $allowed),
        ]);
    }

    public function send(bool $bodyless = false): void
    {
        http_response_code($this->status);

        foreach ($this->headers as $name => $value) {
            header("{$name}: {$value}");
        }

        if (!$bodyless) {
            echo $this->body;
        }
    }
}
