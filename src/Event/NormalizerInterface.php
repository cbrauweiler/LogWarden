<?php

declare(strict_types=1);

namespace LogWarden\Event;

/**
 * Contract every ingestion module implements: take one raw record from a
 * source and return the normalised events it represents.
 *
 * Returning a list rather than a single event lets one raw record expand into
 * several (a FortiGate line that carries both an auth and a tunnel event) or
 * into none (a record the normaliser deliberately drops).
 */
interface NormalizerInterface
{
    /**
     * @param array<string, mixed> $context Transport metadata, e.g.
     *        ['peer' => '10.0.0.1', 'received_at' => DateTimeImmutable]
     * @return list<Event>
     */
    public function normalize(string $raw, array $context = []): array;

    /**
     * Cheap pre-filter so a dispatcher can pick a normaliser without every
     * candidate doing a full parse.
     */
    public function supports(string $raw, array $context = []): bool;
}
