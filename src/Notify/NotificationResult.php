<?php

declare(strict_types=1);

namespace LogWarden\Notify;

final class NotificationResult
{
    private function __construct(
        public readonly bool $delivered,
        public readonly ?int $httpStatus,
        public readonly ?string $error,
        public readonly int $durationMs,
        public readonly int $payloadBytes,
        /** A transport error may succeed later; a rejected payload never will. */
        public readonly bool $retryable,
    ) {
    }

    public static function ok(int $status, int $durationMs, int $payloadBytes): self
    {
        return new self(true, $status, null, $durationMs, $payloadBytes, false);
    }

    public static function failed(
        ?int $status,
        string $error,
        int $durationMs = 0,
        int $payloadBytes = 0,
        bool $retryable = true,
    ): self {
        return new self(false, $status, $error, $durationMs, $payloadBytes, $retryable);
    }
}
