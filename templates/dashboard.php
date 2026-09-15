<?php
/**
 * @var int   $hours
 * @var array $headline
 * @var array $volume
 * @var array $labels
 * @var array $colors
 * @var array $topFailing
 * @var array $recent
 * @var array $ingestHealth
 */

use LogWarden\Web\Chart;
use LogWarden\Web\View;

$e   = static fn (mixed $v): string => View::e($v);
$num = static fn (int|float $v): string => View::number($v);

$ranges = [6 => '6 h', 24 => '24 h', 72 => '3 Tage', 168 => '7 Tage'];

$badge = static function (?string $result) use ($e): string {
    return match ($result) {
        'fail'    => '<span class="badge badge--fail"><span class="badge__dot"></span>Fehler</span>',
        'success' => '<span class="badge badge--success"><span class="badge__dot"></span>Erfolg</span>',
        default   => '<span class="badge badge--info"><span class="badge__dot"></span>Info</span>',
    };
};
?>

<section class="tiles">
    <div class="tile tile--accent">
        <span class="tile__label">Events</span>
        <span class="tile__value"><?= $e($num($headline['events'])) ?></span>
        <span class="tile__meta">letzte <?= $e($ranges[$hours] ?? $hours . ' h') ?></span>
    </div>
    <div class="tile <?= $headline['failures'] > 0 ? 'tile--critical' : '' ?>">
        <span class="tile__label">Fehlgeschlagen</span>
        <span class="tile__value"><?= $e($num($headline['failures'])) ?></span>
        <span class="tile__meta">
            <?= $headline['events'] > 0
                ? $e(number_format($headline['failures'] / $headline['events'] * 100, 1, ',', '.')) . ' % aller Events'
                : 'keine Events' ?>
        </span>
    </div>
    <div class="tile">
        <span class="tile__label">Betroffene Konten</span>
        <span class="tile__value"><?= $e($num($headline['users'])) ?></span>
        <span class="tile__meta">eindeutige Benutzernamen</span>
    </div>
    <div class="tile">
        <span class="tile__label">Quellsysteme</span>
        <span class="tile__value"><?= $e($num($headline['hosts'])) ?></span>
        <span class="tile__meta"><?= $e($num($headline['sources'])) ?> Quelltypen aktiv</span>
    </div>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Event-Volumen</h2>
            <p class="card__hint">Gestapelt nach Quelle, <?= $hours > 48 ? '6-Stunden' : 'Stunden' ?>-Raster</p>
        </div>
        <div class="row">
            <?php foreach ($ranges as $value => $label): ?>
                <a class="btn <?= $hours === $value ? 'btn--primary' : 'btn--ghost' ?>"
                   href="/?hours=<?= $e($value) ?>"><?= $e($label) ?></a>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="card__body">
        <?= Chart::stackedBars($volume['buckets'], $volume['series'], $labels, $colors, $volume['max']) ?>
    </div>

    <?= Chart::legend($volume['series'], $labels, $colors) ?>

    <?php /* Three of the five series colours sit below 3:1 on the light
             surface, so the numbers have to be readable without the colours. */ ?>
    <details class="tableview">
        <summary>Als Tabelle anzeigen</summary>
        <div class="card__body--flush">
            <table class="table">
                <thead>
                    <tr>
                        <th scope="col">Zeitpunkt</th>
                        <?php foreach ($labels as $label): ?>
                            <th scope="col" class="num"><?= $e($label) ?></th>
                        <?php endforeach; ?>
                        <th scope="col" class="num">Summe</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($volume['buckets'] as $index => $bucket): ?>
                    <?php $rowTotal = 0; ?>
                    <tr>
                        <td class="nowrap mono"><?= $e(str_replace('T', ' ', $bucket)) ?></td>
                        <?php foreach ($labels as $type => $label): ?>
                            <?php $value = $volume['series'][$type][$index] ?? 0; $rowTotal += $value; ?>
                            <td class="num"><?= $e($num($value)) ?></td>
                        <?php endforeach; ?>
                        <td class="num"><strong><?= $e($num($rowTotal)) ?></strong></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </details>
</section>

<div class="grid-2" style="gap:1.25rem">
    <section class="card">
        <div class="card__head">
            <div>
                <h2>Häufigste Fehlschläge</h2>
                <p class="card__hint">Konten mit den meisten fehlgeschlagenen Anmeldungen</p>
            </div>
        </div>
        <div class="card__body--flush">
            <?php if ($topFailing === []): ?>
                <p class="table__empty">Keine fehlgeschlagenen Anmeldungen im Zeitraum.</p>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th scope="col">Konto</th>
                            <th scope="col" class="num">Fehlschläge</th>
                            <th scope="col" class="num">Quellen</th>
                            <th scope="col">Zuletzt</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($topFailing as $row): ?>
                        <tr>
                            <td class="mono"><?= $e($row['username']) ?></td>
                            <td class="num"><?= $e($num((int) $row['failures'])) ?></td>
                            <td class="num"><?= $e($row['sources']) ?></td>
                            <td class="nowrap muted"><?= $e($row['last_seen']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <div class="card__head">
            <div>
                <h2>Ingestion</h2>
                <p class="card__hint">Status der konfigurierten Quellen</p>
            </div>
        </div>
        <div class="card__body--flush">
            <?php if ($ingestHealth === []): ?>
                <p class="table__empty">
                    Noch keine Quelle konfiguriert.<br>
                    Der Syslog-Listener nimmt FortiGate-Events auch ohne Eintrag entgegen.
                </p>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th scope="col">Quelle</th>
                            <th scope="col">Typ</th>
                            <th scope="col">Letzter Erfolg</th>
                            <th scope="col" class="num">Events</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($ingestHealth as $row): ?>
                        <tr>
                            <td>
                                <?= $e($row['name']) ?>
                                <?php if (!$row['enabled']): ?>
                                    <span class="badge badge--info">inaktiv</span>
                                <?php endif; ?>
                            </td>
                            <td><span class="badge badge--source"><?= $e($row['collector']) ?></span></td>
                            <td class="nowrap muted"><?= $e($row['last_success_at'] ?? 'nie') ?></td>
                            <td class="num"><?= $e($num((int) $row['events_total'])) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </section>
</div>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Letzte Events</h2>
            <p class="card__hint">Quellenübergreifend, neueste zuerst</p>
        </div>
    </div>
    <div class="card__body--flush">
        <?php if ($recent === []): ?>
            <p class="table__empty">Noch keine Events erfasst.</p>
        <?php else: ?>
            <table class="table">
                <thead>
                    <tr>
                        <th scope="col">Zeit</th>
                        <th scope="col">Quelle</th>
                        <th scope="col">Host</th>
                        <th scope="col">Event</th>
                        <th scope="col">Konto</th>
                        <th scope="col">Quell-IP</th>
                        <th scope="col">Ergebnis</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($recent as $row): ?>
                    <tr>
                        <td class="nowrap mono"><?= $e($row['ts_label']) ?></td>
                        <td><span class="badge badge--source"><?= $e($labels[$row['source_type']] ?? $row['source_type']) ?></span></td>
                        <td class="mono"><?= $e($row['source_host']) ?></td>
                        <td class="mono"><?= $e($row['event_type']) ?></td>
                        <td class="mono"><?= $e($row['username'] ?? '–') ?></td>
                        <td class="mono"><?= $e($row['src_ip'] ?? '–') ?></td>
                        <td><?= $badge($row['result']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</section>
