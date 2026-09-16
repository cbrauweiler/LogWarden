<?php

declare(strict_types=1);

namespace LogWarden\Plugin;

use LogWarden\Event\NormalizerInterface;

/**
 * What a source plugin has to provide.
 *
 * A plugin is a directory under `plugins/` with a `plugin.json` manifest and
 * one class implementing this interface. It contributes two things: the kinds
 * of event it produces, and the normalisers that turn raw input into them.
 *
 * It deliberately does *not* get to open sockets, run queries or register
 * routes. Transport is LogWarden's job — the plugin only ever sees a raw
 * record and says what it means. That keeps a third-party plugin from being
 * able to do much beyond producing wrong events, and it is why the interface
 * has no access to the database or the configuration.
 */
interface PluginInterface
{
    /**
     * Stable identifier, matching the directory name.
     *
     * It ends up in `source_types.plugin` and in the settings page, so it must
     * not change between versions of a plugin.
     */
    public static function key(): string;

    /**
     * Which transports can feed this plugin.
     *
     * `syslog` means the listener offers it every incoming message;
     * `file` means an importer reads records from disk. A plugin that
     * supports neither is never called.
     *
     * @return list<string>
     */
    public static function transports(): array;

    /** @return list<SourceTypeDefinition> */
    public static function sourceTypes(): array;

    /**
     * The normalisers, in the order they should be offered a record.
     *
     * Each is asked `supports()` first, so ordering only matters when two
     * could both claim the same input.
     *
     * @return list<NormalizerInterface>
     */
    public function normalizers(): array;
}
