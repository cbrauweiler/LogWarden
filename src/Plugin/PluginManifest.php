<?php

declare(strict_types=1);

namespace LogWarden\Plugin;

use RuntimeException;

/** The `plugin.json` next to a plugin's classes. */
final class PluginManifest
{
    private function __construct(
        public readonly string $key,
        public readonly string $name,
        public readonly string $vendor,
        public readonly string $version,
        public readonly string $description,
        public readonly string $namespace,
        public readonly string $class,
        public readonly string $directory,
        public readonly ?string $docs,
        public readonly ?string $author,
    ) {
    }

    public static function load(string $directory): self
    {
        $file = $directory . '/plugin.json';

        if (!is_file($file)) {
            throw new RuntimeException('Kein plugin.json in ' . $directory);
        }

        $data = json_decode((string) file_get_contents($file), true);

        if (!is_array($data)) {
            throw new RuntimeException('plugin.json in ' . $directory . ' ist kein gültiges JSON');
        }

        foreach (['key', 'name', 'namespace', 'class'] as $required) {
            if (empty($data[$required]) || !is_string($data[$required])) {
                throw new RuntimeException(sprintf('plugin.json in %s: "%s" fehlt', $directory, $required));
            }
        }

        // The key has to match the directory, because the directory is what the
        // autoloader maps and the key is what the database stores. Letting them
        // drift would make "which plugin wrote this event" unanswerable.
        if ($data['key'] !== basename($directory)) {
            throw new RuntimeException(sprintf(
                'plugin.json in %s: key "%s" stimmt nicht mit dem Verzeichnisnamen überein.',
                $directory,
                $data['key'],
            ));
        }

        $namespace = rtrim((string) $data['namespace'], '\\') . '\\';

        if (!str_starts_with($namespace, 'LogWarden\\Plugin\\')) {
            throw new RuntimeException(sprintf(
                'plugin.json in %s: namespace muss mit LogWarden\\Plugin\\ beginnen, ist "%s".',
                $directory,
                $namespace,
            ));
        }

        return new self(
            key:         (string) $data['key'],
            name:        (string) $data['name'],
            vendor:      (string) ($data['vendor'] ?? ''),
            version:     (string) ($data['version'] ?? '0.0.0'),
            description: (string) ($data['description'] ?? ''),
            namespace:   $namespace,
            class:       $namespace . ltrim((string) $data['class'], '\\'),
            directory:   $directory,
            docs:        isset($data['docs']) ? (string) $data['docs'] : null,
            author:      isset($data['author']) ? (string) $data['author'] : null,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'key'         => $this->key,
            'name'        => $this->name,
            'vendor'      => $this->vendor,
            'version'     => $this->version,
            'description' => $this->description,
            'class'       => $this->class,
            'directory'   => $this->directory,
            'docs'        => $this->docs,
            'author'      => $this->author,
        ];
    }
}
