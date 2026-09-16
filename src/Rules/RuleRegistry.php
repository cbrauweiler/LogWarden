<?php

declare(strict_types=1);

namespace LogWarden\Rules;

use RuntimeException;

/**
 * Resolves the rule key stored in the database to a class.
 *
 * Deliberately not `new $row['rule_class']`: that instantiates whatever string
 * is in the row, which turns write access to one config table into arbitrary
 * object construction. Classes are discovered from disk and matched by their
 * own declared key, so the database only ever selects from a known set.
 */
final class RuleRegistry
{
    /** @var array<string, class-string<RuleInterface>>|null */
    private ?array $map = null;

    /** @param list<string> $directories */
    public function __construct(
        private readonly array $directories = [],
        private readonly string $namespace = 'LogWarden\\Rules\\Builtin\\',
    ) {
    }

    public static function default(): self
    {
        return new self([LW_ROOT . '/src/Rules/Builtin']);
    }

    public function get(string $key): RuleInterface
    {
        $map   = $this->map();
        $class = $map[$key] ?? null;

        if ($class === null) {
            throw new RuntimeException(
                "Unknown rule key '{$key}'. Available: " . (implode(', ', array_keys($map)) ?: 'none')
            );
        }

        return new $class();
    }

    public function has(string $key): bool
    {
        return isset($this->map()[$key]);
    }

    /** @return array<string, class-string<RuleInterface>> */
    public function map(): array
    {
        if ($this->map !== null) {
            return $this->map;
        }

        $map = [];

        foreach ($this->directories as $directory) {
            foreach (glob($directory . '/*.php') ?: [] as $file) {
                $class = $this->namespace . basename($file, '.php');

                if (!class_exists($class) || !is_a($class, RuleInterface::class, true)) {
                    continue;
                }

                $map[$class::key()] = $class;
            }
        }

        ksort($map);

        return $this->map = $map;
    }

    /** @return list<array{key:string, title:string, description:string, defaults:array}> */
    public function describeAll(): array
    {
        $out = [];

        foreach ($this->map() as $key => $class) {
            $out[] = [
                'key'         => $key,
                'title'       => $class::title(),
                'description' => $class::description(),
                'defaults'    => $class::defaultParams(),
            ];
        }

        return $out;
    }
}
