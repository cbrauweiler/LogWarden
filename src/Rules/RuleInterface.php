<?php

declare(strict_types=1);

namespace LogWarden\Rules;

/**
 * Contract every detection rule implements.
 *
 * A new rule is one file in src/Rules/Builtin/ plus one row in `rules`. The
 * registry discovers it by its key; no core code changes.
 */
interface RuleInterface
{
    /**
     * Stable identifier stored in rules.rule_key. Renaming it orphans existing
     * rows, so treat it as permanent once shipped.
     */
    public static function key(): string;

    /** Shown in the admin UI. */
    public static function title(): string;

    public static function description(): string;

    /**
     * Defaults merged under the row's params, so adding a parameter in a later
     * version does not require touching existing rows.
     *
     * @return array<string, mixed>
     */
    public static function defaultParams(): array;

    /**
     * @param array<string, mixed> $params
     * @return list<AlertCandidate>
     */
    public function evaluate(RuleContext $context, array $params): array;
}
