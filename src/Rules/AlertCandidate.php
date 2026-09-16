<?php

declare(strict_types=1);

namespace LogWarden\Rules;

/**
 * What a rule returns when it finds something: a finished alert, minus the
 * bookkeeping (id, status, timestamps) that the repository adds.
 */
final class AlertCandidate
{
    /**
     * @param string $dedupKey  Identifies the *condition*, not the occurrence.
     *                          Two evaluations of the same ongoing problem must
     *                          produce the same key so the alert grows instead
     *                          of duplicating.
     * @param array<string, mixed>        $evidence  Self-contained snapshot; it has to
     *                                               stay readable after the source
     *                                               events age out of retention.
     * @param list<array{0:string,1:int}> $eventRefs [ts, id] pairs
     */
    public function __construct(
        public readonly string $dedupKey,
        public readonly string $title,
        public readonly string $summary,
        public readonly int $eventCount = 0,
        public readonly ?string $entityUser = null,
        public readonly ?string $entityIp = null,
        public readonly ?string $entityHost = null,
        public readonly array $evidence = [],
        public readonly array $eventRefs = [],
        public readonly ?int $severity = null,
    ) {
    }
}
