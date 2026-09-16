<?php
/**
 * @var array $event
 * @var array $details
 * @var array $neighbours
 * @var array $labels
 */

use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);

$resultLabels = ['success' => 'Erfolg', 'fail' => 'Fehler', 'info' => 'Info'];

$badge = static function (?string $result) use ($e, $resultLabels): string {
    $class = match ($result) { 'fail' => 'fail', 'success' => 'success', default => 'info' };

    return '<span class="badge badge--' . $class . '"><span class="badge__dot"></span>'
        . $e($resultLabels[$result] ?? 'Info') . '</span>';
};

// Links that pivot into a fresh search — the usual next move after reading one
// event is "show me everything else from this account / this address".
$pivot = static function (array $params) use ($e): string {
    return '/search?' . http_build_query($params + ['preset' => '24h']);
};

$delay = (int) ($event['delay_seconds'] ?? 0);
?>

<section class="card">
    <div class="card__head">
        <div style="min-width:0">
            <div class="row" style="margin-bottom:0.4rem">
                <?= $badge($event['result']) ?>
                <span class="badge badge--source"><?= $e($labels[$event['source_type']] ?? $event['source_type']) ?></span>
                <span class="chip"><?= $e($event['event_type']) ?></span>
            </div>
            <h2><?= $e($event['ts_label']) ?> UTC</h2>
            <p class="card__hint" style="margin-top:0.3rem">
                Gemeldet von <?= $e($event['source_host']) ?>
            </p>
        </div>
        <a class="btn btn--ghost nowrap" href="javascript:history.back()">Zurück</a>
    </div>

    <div class="card__body">
        <div class="eventgrid">
            <dl class="kv">
                <dt>Ereigniszeit</dt>
                <dd class="mono"><?= $e($event['ts_label']) ?> UTC</dd>

                <dt>Eingang</dt>
                <dd class="mono">
                    <?= $e($event['ingested_label']) ?> UTC
                    <?php if ($delay > 90): ?>
                        <br><span class="muted" style="font-size:0.78rem">
                            <?= $e(round($delay / 60)) ?> Minuten nach dem Ereignis eingetroffen
                        </span>
                    <?php endif; ?>
                </dd>

                <dt>Quelle</dt>
                <dd><?= $e($labels[$event['source_type']] ?? $event['source_type']) ?></dd>

                <dt>System</dt>
                <dd class="mono">
                    <a href="<?= $e($pivot(['host' => $event['source_host']])) ?>"><?= $e($event['source_host']) ?></a>
                </dd>

                <dt>Event-Typ</dt>
                <dd class="mono">
                    <a href="<?= $e($pivot(['event_type' => $event['event_type']])) ?>"><?= $e($event['event_type']) ?></a>
                </dd>
            </dl>

            <dl class="kv">
                <dt>Konto</dt>
                <dd class="mono">
                    <?php if (!empty($event['username'])): ?>
                        <a href="<?= $e($pivot(['username' => $event['username']])) ?>"><?= $e($event['username']) ?></a>
                    <?php else: ?>
                        –
                    <?php endif; ?>
                </dd>

                <dt>Quell-IP</dt>
                <dd class="mono">
                    <?php if (!empty($event['src_ip'])): ?>
                        <a href="<?= $e($pivot(['ip' => $event['src_ip']])) ?>"><?= $e($event['src_ip']) ?></a>
                    <?php else: ?>
                        –
                    <?php endif; ?>
                </dd>

                <dt>Ziel-IP</dt>
                <dd class="mono">
                    <?php if (!empty($event['dst_ip'])): ?>
                        <a href="<?= $e($pivot(['ip' => $event['dst_ip']])) ?>"><?= $e($event['dst_ip']) ?></a>
                    <?php else: ?>
                        –
                    <?php endif; ?>
                </dd>

                <dt>Ergebnis</dt>
                <dd><?= $badge($event['result']) ?></dd>

                <dt>Referenz</dt>
                <dd class="mono" style="font-size:0.76rem"><?= $e($event['dedup_key']) ?></dd>
            </dl>
        </div>
    </div>
</section>

<?php if ($details !== []): ?>
    <section class="card">
        <div class="card__head">
            <div>
                <h2>Quellenspezifische Felder</h2>
                <p class="card__hint">
                    Was nicht ins gemeinsame Schema passt — als <code>details</code> gespeichert und durchsuchbar.
                </p>
            </div>
        </div>
        <div class="card__body">
            <table class="jsontable">
                <tbody>
                <?php foreach ($details as $key => $value): ?>
                    <tr>
                        <th scope="row"><?= $e($key) ?></th>
                        <td><?= $e(is_scalar($value) ? (string) $value : json_encode($value, JSON_UNESCAPED_UNICODE)) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
<?php endif; ?>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Originalmeldung</h2>
            <p class="card__hint">Unverändert wie von der Quelle empfangen.</p>
        </div>
    </div>
    <div class="card__body">
        <pre class="raw"><?= $e($event['raw_message']) ?></pre>
    </div>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Umfeld</h2>
            <p class="card__hint">
                Dasselbe Konto oder dieselbe Adresse, zehn Minuten davor und danach —
                quellenübergreifend.
            </p>
        </div>
    </div>
    <div class="card__body--flush">
        <?php if ($neighbours === []): ?>
            <p class="table__empty">Keine weiteren Events im Umfeld.</p>
        <?php else: ?>
            <table class="table table--rows">
                <thead>
                    <tr>
                        <th scope="col">Zeit</th>
                        <th scope="col">Quelle</th>
                        <th scope="col">System</th>
                        <th scope="col">Event</th>
                        <th scope="col">Konto</th>
                        <th scope="col">Quell-IP</th>
                        <th scope="col">Ergebnis</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($neighbours as $row): ?>
                    <?php $href = '/event?ts=' . rawurlencode((string) $row['ts_iso']) . '&id=' . (int) $row['id']; ?>
                    <tr onclick="if(!window.getSelection().toString()){location.href=this.dataset.href}"
                        data-href="<?= $e($href) ?>">
                        <td class="nowrap mono">
                            <a class="rowlink" href="<?= $e($href) ?>"><?= $e($row['ts_label']) ?></a>
                        </td>
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
