<?php

declare(strict_types=1);

namespace LogWarden\Event;

use InvalidArgumentException;
use LogWarden\Plugin\PluginRegistry;
use LogWarden\Plugin\SourceTypeDefinition;

/**
 * The kind of source an event came from.
 *
 * This used to be a PHP enum backed by a PostgreSQL enum, which meant adding a
 * vendor required editing two files and writing a migration. Since sources are
 * plugins, the set is no longer knowable at compile time: the Windows kinds
 * below are native, everything else is contributed by whatever lies in
 * `plugins/`.
 *
 * Reading and writing are validated differently on purpose. {@see of} refuses
 * a key no installed plugin claims, so a typo in a normaliser fails loudly.
 * {@see ofStored} accepts anything the database hands back, so that
 * uninstalling a plugin makes its history unlabelled rather than unreadable.
 */
final class SourceType
{
    /**
     * Windows sources are part of LogWarden itself, not a plugin.
     *
     * They are the reason the tool exists in a Windows estate, they share the
     * WinRM collector with each other, and a plugin boundary between them
     * would be a boundary nobody ever crosses.
     */
    private const CORE = [
        'ad'   => ['Active Directory', 365, 30, '--series-1', 'Sicherheitsereignisse der Domain Controller', SourceTypeDefinition::ROLE_DIRECTORY],
        'dns'  => ['DNS',               21,  7, '--series-2', 'Audit- und Serverereignisse des DNS-Dienstes',  SourceTypeDefinition::ROLE_DNS],
        'dhcp' => ['DHCP',              90, 14, '--series-3', 'Lease-Vorgänge aus den DHCP-Audit-Protokollen', SourceTypeDefinition::ROLE_DHCP],
    ];

    private function __construct(public readonly string $value)
    {
    }

    /**
     * For code that produces events. Throws when nothing declares the key.
     *
     * @throws InvalidArgumentException
     */
    public static function of(string $key): self
    {
        if (!isset(self::definitions()[$key])) {
            throw new InvalidArgumentException(sprintf(
                'Unbekannter Quelltyp "%s". Bekannt sind: %s. Ein Plugin muss ihn in sourceTypes() deklarieren.',
                $key,
                implode(', ', array_keys(self::definitions())),
            ));
        }

        return new self($key);
    }

    /** For values read back from the database, including those of removed plugins. */
    public static function ofStored(string $key): self
    {
        return new self($key);
    }

    public function label(): string
    {
        $definition = self::definitions()[$this->value] ?? null;

        // A source type whose plugin is gone keeps its raw key rather than
        // disappearing from the interface — the events are still there.
        return $definition?->label ?? $this->value;
    }

    public function color(): string
    {
        $definition = self::definitions()[$this->value] ?? null;

        if ($definition?->color !== null) {
            return $definition->color;
        }

        // Stable per key, so a source keeps its colour across restarts and
        // however the plugin set changes around it.
        $palette = SourceTypeDefinition::PALETTE;

        return $palette[crc32($this->value) % count($palette)];
    }

    public function role(): string
    {
        return (self::definitions()[$this->value] ?? null)?->role ?? SourceTypeDefinition::ROLE_OTHER;
    }

    /** @return list<string> every key carrying the given role */
    public static function withRole(string $role): array
    {
        $out = [];

        foreach (self::definitions() as $key => $definition) {
            if ($definition->role === $role) {
                $out[] = $key;
            }
        }

        return $out;
    }

    public function isKnown(): bool
    {
        return isset(self::definitions()[$this->value]);
    }

    public function is(string $key): bool
    {
        return $this->value === $key;
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    /** @return list<self> */
    public static function all(): array
    {
        return array_map(
            static fn (string $key): self => new self($key),
            array_keys(self::definitions()),
        );
    }

    /** @return array<string, string> key => label */
    public static function labels(): array
    {
        $out = [];

        foreach (self::definitions() as $key => $definition) {
            $out[$key] = $definition->label;
        }

        return $out;
    }

    /** @return array<string, string> key => CSS custom property */
    public static function colors(): array
    {
        $out = [];

        foreach (self::all() as $type) {
            $out[$type->value] = $type->color();
        }

        return $out;
    }

    /**
     * Core plus plugin definitions.
     *
     * @return array<string, SourceTypeDefinition>
     */
    public static function definitions(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }

        $out = [];

        foreach (self::CORE as $key => [$label, $keepDays, $ftsDays, $color, $description, $role]) {
            $out[$key] = new SourceTypeDefinition($key, $label, $keepDays, $ftsDays, $color, $description, $role);
        }

        // Core wins on a collision: a plugin must not be able to redefine what
        // 'ad' means and quietly change the retention of the domain
        // controllers' security log.
        foreach (PluginRegistry::default()->sourceTypes() as $key => $definition) {
            $out[$key] ??= $definition;
        }

        return self::$cache = $out;
    }

    /** @var array<string, SourceTypeDefinition>|null */
    private static ?array $cache = null;

    /** Only for tests, which install plugins into a temporary directory. */
    public static function resetDefinitions(): void
    {
        self::$cache = null;
        PluginRegistry::reset();
    }
}
