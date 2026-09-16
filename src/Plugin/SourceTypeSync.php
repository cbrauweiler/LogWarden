<?php

declare(strict_types=1);

namespace LogWarden\Plugin;

use LogWarden\Core\Db;
use LogWarden\Event\SourceType;

/**
 * Writes the source types declared in code into `source_types`.
 *
 * The table is a mirror, not the source of truth: it exists so SQL can join a
 * label, a colour and a role without the application decorating every row, and
 * so retention stays adjustable per kind. When the two disagree, code wins —
 * except for the retention columns, which an administrator is allowed to
 * change and which are therefore never overwritten once set.
 */
final class SourceTypeSync
{
    public function __construct(private readonly Db $db)
    {
    }

    /**
     * @return array{inserted: list<string>, updated: list<string>, orphaned: list<string>, revived: list<string>}
     */
    public function run(bool $dryRun = false): array
    {
        $declared = SourceType::definitions();
        $owners   = PluginRegistry::default()->sourceTypeOwners();

        $existing = [];
        foreach ($this->db->fetchAll('SELECT key, label, plugin, color, role, description, orphaned FROM source_types') as $row) {
            $existing[$row['key']] = $row;
        }

        $result = ['inserted' => [], 'updated' => [], 'orphaned' => [], 'revived' => []];

        foreach ($declared as $key => $definition) {
            $plugin = $owners[$key] ?? null;
            $row    = $existing[$key] ?? null;

            if ($row === null) {
                $result['inserted'][] = $key;

                if (!$dryRun) {
                    $this->db->execute(
                        'INSERT INTO source_types (key, label, plugin, color, description, role, keep_days, fts_days)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        [
                            $key, $definition->label, $plugin, $definition->color,
                            $definition->description, $definition->role,
                            $definition->keepDays, $definition->ftsDays,
                        ],
                    );
                }

                continue;
            }

            $changed = $row['label'] !== $definition->label
                || $row['plugin'] !== $plugin
                || $row['color'] !== $definition->color
                || $row['role'] !== $definition->role
                || $row['description'] !== $definition->description
                || $row['orphaned'];

            if ($row['orphaned']) {
                $result['revived'][] = $key;
            }

            if (!$changed) {
                continue;
            }

            $result['updated'][] = $key;

            if (!$dryRun) {
                // keep_days and fts_days are deliberately absent: they are the
                // one part of the row an administrator owns, and a plugin
                // update must not silently reset a retention somebody chose.
                $this->db->execute(
                    'UPDATE source_types
                        SET label = ?, plugin = ?, color = ?, description = ?, role = ?,
                            orphaned = false, synced_at = now()
                      WHERE key = ?',
                    [
                        $definition->label, $plugin, $definition->color,
                        $definition->description, $definition->role, $key,
                    ],
                );
            }
        }

        // Anything in the table that nothing declares any more. The row stays,
        // because the events it labels are still in the database and deleting
        // it would leave them nameless; it is only marked so the interface can
        // say why no new ones are arriving.
        foreach ($existing as $key => $row) {
            if (isset($declared[$key]) || $row['orphaned']) {
                continue;
            }

            $result['orphaned'][] = $key;

            if (!$dryRun) {
                $this->db->execute(
                    'UPDATE source_types SET orphaned = true, synced_at = now() WHERE key = ?',
                    [$key],
                );
            }
        }

        return $result;
    }

    /**
     * Source types that carry events but are no longer declared.
     *
     * @return list<array{key: string, plugin: ?string, events: int}>
     */
    public function orphansWithData(): array
    {
        return $this->db->fetchAll(
            "SELECT s.key, s.plugin,
                    (SELECT count(*) FROM events e WHERE e.source_type = s.key) AS events
               FROM source_types s
              WHERE s.orphaned
              ORDER BY s.key",
        );
    }
}
