<?php
/**
 * Minimal test harness.
 *
 * LogWarden has no runtime dependencies on purpose; pulling in PHPUnit just to
 * assert on parser output would be the only reason the project needed Composer
 * packages at all. This is enough for value-object and parser tests.
 */

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

final class TestRunner
{
    /** @var list<array{string, callable}> */
    public static array $tests = [];

    public static int $assertions = 0;

    /** @var list<string> */
    public static array $failures = [];

    public static string $current = '';

    public static function run(): int
    {
        $passed = 0;

        foreach (self::$tests as [$name, $fn]) {
            self::$current = $name;
            $before = count(self::$failures);

            try {
                $fn();
            } catch (Throwable $e) {
                self::$failures[] = sprintf("%s\n    threw %s: %s", $name, $e::class, $e->getMessage());
            }

            if (count(self::$failures) === $before) {
                $passed++;
                fwrite(STDOUT, ".");
            } else {
                fwrite(STDOUT, "F");
            }
        }

        fwrite(STDOUT, "\n\n");

        if (self::$failures !== []) {
            fwrite(STDOUT, "FAILURES\n");
            foreach (self::$failures as $failure) {
                fwrite(STDOUT, "  - {$failure}\n");
            }
            fwrite(STDOUT, "\n");
        }

        fwrite(STDOUT, sprintf(
            "%d test(s), %d assertion(s), %d failure(s)\n",
            count(self::$tests),
            self::$assertions,
            count(self::$failures),
        ));

        return self::$failures === [] ? 0 : 1;
    }
}

// Plugin classes live outside src/ and are not covered by the autoloader.
// Loading them here means a test can use them by name, exactly as the syslog
// daemon does after asking the registry.
foreach (array_keys(LogWarden\Plugin\PluginRegistry::default()->manifests()) as $pluginKey) {
    try {
        LogWarden\Plugin\PluginRegistry::default()->get($pluginKey);
    } catch (Throwable $e) {
        fwrite(STDERR, "Plugin {$pluginKey} nicht ladbar: " . $e->getMessage() . "\n");
    }
}

function test(string $name, callable $fn): void
{
    TestRunner::$tests[] = [$name, $fn];
}

function assertSame(mixed $expected, mixed $actual, string $message = ''): void
{
    TestRunner::$assertions++;

    if ($expected !== $actual) {
        TestRunner::$failures[] = sprintf(
            "%s%s\n    expected: %s\n    actual:   %s",
            TestRunner::$current,
            $message === '' ? '' : " ({$message})",
            var_export($expected, true),
            var_export($actual, true),
        );
    }
}

function assertTrue(bool $actual, string $message = ''): void
{
    assertSame(true, $actual, $message);
}

function assertFalse(bool $actual, string $message = ''): void
{
    assertSame(false, $actual, $message);
}

function assertNull(mixed $actual, string $message = ''): void
{
    assertSame(null, $actual, $message);
}

function assertCount(int $expected, array $actual, string $message = ''): void
{
    assertSame($expected, count($actual), $message);
}

function fixture(string $name): string
{
    $candidates = array_merge(
        [__DIR__ . '/fixtures/' . $name],
        // Plugins keep their sample data next to their code, so that deleting
        // the directory takes the fixtures with it.
        glob(LW_ROOT . '/plugins/*/fixtures/' . $name) ?: [],
    );

    foreach ($candidates as $path) {
        if (is_file($path)) {
            return (string) file_get_contents($path);
        }
    }

    throw new RuntimeException("Fixture {$name} not found");
}

/** @return list<string> */
function fixtureLines(string $name): array
{
    return array_values(array_filter(
        array_map('rtrim', explode("\n", fixture($name))),
        static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#'),
    ));
}
