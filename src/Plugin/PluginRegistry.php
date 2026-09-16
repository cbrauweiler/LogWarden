<?php

declare(strict_types=1);

namespace LogWarden\Plugin;

use LogWarden\Event\NormalizerInterface;
use RuntimeException;
use Throwable;

/**
 * Finds, loads and hands out the installed source plugins.
 *
 * Discovery is by directory, not by configuration: a plugin is installed by
 * copying its folder into `plugins/` and removed by deleting it. There is no
 * enable flag in the database, because a plugin that is present but disabled
 * is a state nobody can see from the filesystem, and "why is nothing arriving"
 * is hard enough already.
 *
 * Classes are matched by the key they declare themselves, never instantiated
 * from a name that came out of a table — the same reasoning as RuleRegistry.
 */
final class PluginRegistry
{
    /** @var array<string, PluginManifest>|null */
    private ?array $manifests = null;

    /** @var array<string, PluginInterface> */
    private array $instances = [];

    /** @var list<string> */
    private array $errors = [];

    /** @param list<string> $directories */
    public function __construct(private readonly array $directories)
    {
    }

    private static ?self $default = null;

    public static function default(): self
    {
        return self::$default ??= new self([LW_ROOT . '/plugins']);
    }

    /** Only for tests: the registry is a process-wide cache otherwise. */
    public static function reset(): void
    {
        self::$default = null;
    }

    /** @return array<string, PluginManifest> */
    public function manifests(): array
    {
        if ($this->manifests !== null) {
            return $this->manifests;
        }

        $found  = [];
        $errors = [];

        foreach ($this->directories as $root) {
            foreach (glob($root . '/*', GLOB_ONLYDIR) ?: [] as $directory) {
                if (!is_file($directory . '/plugin.json')) {
                    continue;
                }

                try {
                    $manifest = PluginManifest::load($directory);
                } catch (Throwable $e) {
                    // A broken plugin must not take the daemon down with it:
                    // the other sources keep being collected, and the problem
                    // shows up in `bin/logwarden-plugins` and in the settings
                    // page instead of in a stack trace at three in the morning.
                    $errors[] = $e->getMessage();
                    continue;
                }

                if (isset($found[$manifest->key])) {
                    $errors[] = sprintf('Plugin "%s" liegt doppelt vor, %s wird ignoriert.', $manifest->key, $directory);
                    continue;
                }

                $found[$manifest->key] = $manifest;
            }
        }

        ksort($found);
        $this->errors = $errors;

        return $this->manifests = $found;
    }

    /** @return list<string> */
    public function errors(): array
    {
        $this->manifests();

        return $this->errors;
    }

    public function has(string $key): bool
    {
        return isset($this->manifests()[$key]);
    }

    public function manifest(string $key): PluginManifest
    {
        $manifest = $this->manifests()[$key] ?? null;

        if ($manifest === null) {
            throw new RuntimeException(sprintf(
                'Unbekanntes Plugin "%s". Installiert: %s',
                $key,
                implode(', ', array_keys($this->manifests())) ?: 'keines',
            ));
        }

        return $manifest;
    }

    public function get(string $key): PluginInterface
    {
        if (isset($this->instances[$key])) {
            return $this->instances[$key];
        }

        $manifest = $this->manifest($key);
        $this->requireClasses($manifest);

        $class = $manifest->class;

        if (!class_exists($class) || !is_a($class, PluginInterface::class, true)) {
            throw new RuntimeException(sprintf(
                'Plugin "%s": %s implementiert PluginInterface nicht.',
                $key,
                $class,
            ));
        }

        if ($class::key() !== $key) {
            throw new RuntimeException(sprintf(
                'Plugin "%s": die Klasse meldet den Schlüssel "%s".',
                $key,
                $class::key(),
            ));
        }

        return $this->instances[$key] = new $class();
    }

    /** @return list<PluginInterface> */
    public function all(): array
    {
        $out = [];

        foreach (array_keys($this->manifests()) as $key) {
            try {
                $out[] = $this->get($key);
            } catch (Throwable $e) {
                $this->errors[] = $e->getMessage();
            }
        }

        return $out;
    }

    /**
     * Every normaliser that can be fed from the given transport.
     *
     * @return list<NormalizerInterface>
     */
    public function normalizersFor(string $transport): array
    {
        $out = [];

        foreach ($this->all() as $plugin) {
            if (!in_array($transport, $plugin::transports(), true)) {
                continue;
            }

            foreach ($plugin->normalizers() as $normalizer) {
                $out[] = $normalizer;
            }
        }

        return $out;
    }

    /**
     * Source types contributed by plugins, keyed by their key.
     *
     * @return array<string, SourceTypeDefinition>
     */
    public function sourceTypes(): array
    {
        $out = [];

        foreach ($this->manifests() as $key => $manifest) {
            try {
                $this->requireClasses($manifest);
                $class = $manifest->class;

                if (!class_exists($class) || !is_a($class, PluginInterface::class, true)) {
                    continue;
                }

                foreach ($class::sourceTypes() as $definition) {
                    if (isset($out[$definition->key])) {
                        $this->errors[] = sprintf(
                            'Quelltyp "%s" wird von mehreren Plugins beansprucht; "%s" wird ignoriert.',
                            $definition->key,
                            $key,
                        );
                        continue;
                    }

                    $out[$definition->key] = $definition;
                }
            } catch (Throwable $e) {
                $this->errors[] = $e->getMessage();
            }
        }

        return $out;
    }

    /** @return array<string, string> source type key => plugin key */
    public function sourceTypeOwners(): array
    {
        $out = [];

        foreach ($this->manifests() as $key => $manifest) {
            try {
                $this->requireClasses($manifest);
                $class = $manifest->class;

                if (!class_exists($class) || !is_a($class, PluginInterface::class, true)) {
                    continue;
                }

                foreach ($class::sourceTypes() as $definition) {
                    $out[$definition->key] ??= $key;
                }
            } catch (Throwable) {
                continue;
            }
        }

        return $out;
    }

    /**
     * Loads a plugin's classes.
     *
     * Plugins live outside `src/`, so the project autoloader does not see
     * them. Rather than registering one autoloader per plugin, the files of
     * the plugin directory are required directly — a plugin is a handful of
     * files, and requiring them all is cheaper than the bookkeeping.
     */
    private function requireClasses(PluginManifest $manifest): void
    {
        static $loaded = [];

        if (isset($loaded[$manifest->directory])) {
            return;
        }

        $loaded[$manifest->directory] = true;

        $files = glob($manifest->directory . '/*.php') ?: [];
        sort($files);

        foreach ($files as $file) {
            require_once $file;
        }
    }
}
