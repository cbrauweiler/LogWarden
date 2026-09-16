<?php
/**
 * @var \LogWarden\Search\SearchCriteria $criteria
 * @var array       $rows
 * @var bool        $hasMore
 * @var array       $total
 * @var array       $facets
 * @var array       $labels
 * @var array|null  $nextCursor
 * @var string|null $ftsWarning
 */

use LogWarden\Search\SearchCriteria;
use LogWarden\Web\View;

$e   = static fn (mixed $v): string => View::e($v);
$num = static fn (int|float $v): string => View::number($v);

// Aus der Registry, damit ein neu installiertes Plugin seine eigene Farbe
// mitbringt, statt hier nachgetragen werden zu müssen.
$seriesColor = LogWarden\Event\SourceType::colors();

$resultLabels = ['success' => 'Erfolg', 'fail' => 'Fehler', 'info' => 'Info'];

$badge = static function (?string $result) use ($e, $resultLabels): string {
    $class = match ($result) {
        'fail'    => 'fail',
        'success' => 'success',
        default   => 'info',
    };

    return '<span class="badge badge--' . $class . '"><span class="badge__dot"></span>'
        . $e($resultLabels[$result] ?? 'Info') . '</span>';
};
?>

<?php if (!empty($ipWarning)): ?>
    <div class="notice notice--critical" role="alert">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
        <div><?= $e($ipWarning) ?></div>
    </div>
<?php endif; ?>

<?php if ($ftsWarning !== null): ?>
    <div class="notice notice--warning" role="status">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
        <div><?= $e($ftsWarning) ?></div>
    </div>
<?php endif; ?>

<section class="card">
    <form class="searchbar" method="get" action="/search">
        <div class="searchbar__grid">
            <div class="field" style="grid-column: span 2">
                <label class="field__label" for="q">Volltext</label>
                <input class="input" id="q" name="q" value="<?= $e($criteria->query ?? '') ?>"
                       placeholder="z. B. &quot;tunnel up&quot; oder passwd_invalid">
                <span class="field__hint">Wortweise. Anführungszeichen für Phrasen, Minus schließt aus.</span>
            </div>
            <div class="field">
                <label class="field__label" for="username">Konto</label>
                <input class="input" id="username" name="username" value="<?= $e($criteria->username ?? '') ?>"
                       placeholder="jdoe oder svc-*">
            </div>
            <div class="field">
                <label class="field__label" for="ip">IP oder Netz</label>
                <input class="input" id="ip" name="ip" value="<?= $e($criteria->ip ?? '') ?>"
                       placeholder="203.0.113.9 oder 10.0.0.0/8">
            </div>
            <div class="field">
                <label class="field__label" for="ipfield">IP-Feld</label>
                <select class="select" id="ipfield" name="ipfield">
                    <option value="any" <?= $criteria->ipField === 'any' ? 'selected' : '' ?>>Quelle oder Ziel</option>
                    <option value="src" <?= $criteria->ipField === 'src' ? 'selected' : '' ?>>nur Quelle</option>
                    <option value="dst" <?= $criteria->ipField === 'dst' ? 'selected' : '' ?>>nur Ziel</option>
                </select>
            </div>
            <div class="field">
                <label class="field__label" for="host">System</label>
                <input class="input" id="host" name="host" value="<?= $e($criteria->host ?? '') ?>"
                       placeholder="DC01.corp.local oder FGT-*">
            </div>
            <div class="field">
                <label class="field__label" for="event_type">Event-Typ</label>
                <input class="input" id="event_type" name="event_type" value="<?= $e($criteria->eventType ?? '') ?>"
                       placeholder="4625 oder ssl-login-fail">
            </div>
            <div class="field">
                <label class="field__label" for="result">Ergebnis</label>
                <select class="select" id="result" name="result">
                    <option value="">alle</option>
                    <?php foreach ($resultLabels as $value => $label): ?>
                        <option value="<?= $e($value) ?>" <?= $criteria->result === $value ? 'selected' : '' ?>>
                            <?= $e($label) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="field">
                <label class="field__label" for="preset">Zeitraum</label>
                <select class="select" id="preset" name="preset">
                    <?php foreach (SearchCriteria::PRESETS as $key => $preset): ?>
                        <option value="<?= $e($key) ?>" <?= $criteria->preset === $key ? 'selected' : '' ?>>
                            letzte <?= $e($preset['label']) ?>
                        </option>
                    <?php endforeach; ?>
                    <option value="custom" <?= $criteria->preset === 'custom' ? 'selected' : '' ?>>benutzerdefiniert</option>
                </select>
            </div>
            <div class="field">
                <label class="field__label" for="from">Von (UTC)</label>
                <input class="input" id="from" name="from" type="datetime-local"
                       value="<?= $e($criteria->from->format('Y-m-d\TH:i')) ?>">
            </div>
            <div class="field">
                <label class="field__label" for="to">Bis (UTC)</label>
                <input class="input" id="to" name="to" type="datetime-local"
                       value="<?= $e($criteria->to->format('Y-m-d\TH:i')) ?>">
            </div>
        </div>

        <div class="searchbar__row">
            <div class="sourcepicker">
                <?php foreach ($labels as $type => $label): ?>
                    <label>
                        <input type="checkbox" name="source[]" value="<?= $e($type) ?>"
                               <?= in_array($type, $criteria->sourceTypes, true) ? 'checked' : '' ?>>
                        <span class="dot" style="background:var(<?= $e($seriesColor[$type] ?? '--ink-3') ?>)"></span>
                        <span><?= $e($label) ?></span>
                    </label>
                <?php endforeach; ?>
            </div>

            <div class="grow"></div>

            <label class="visually-hidden" for="limit">Treffer pro Seite</label>
            <select class="select" id="limit" name="limit" style="width:auto">
                <?php foreach (SearchCriteria::PAGE_SIZES as $size): ?>
                    <option value="<?= $e($size) ?>" <?= $criteria->limit === $size ? 'selected' : '' ?>>
                        <?= $e($size) ?> pro Seite
                    </option>
                <?php endforeach; ?>
            </select>

            <button class="btn btn--primary" type="submit">Suchen</button>
            <a class="btn btn--ghost" href="/search">Zurücksetzen</a>
        </div>
    </form>

    <?php $active = $criteria->activeFilters(); ?>
    <?php if ($active !== []): ?>
        <div class="chipbar">
            <span class="muted" style="font-size:0.8rem">Aktive Filter:</span>
            <?php foreach ($active as $filter): ?>
                <span class="filterchip">
                    <span class="filterchip__label"><?= $e($filter['label']) ?></span>
                    <span class="filterchip__value"><?= $e($filter['value']) ?></span>
                    <a href="/search?<?= $e($criteria->toQueryString([$filter['key'] => null, 'cts' => null, 'cid' => null])) ?>"
                       title="Filter entfernen" aria-label="Filter <?= $e($filter['label']) ?> entfernen">&times;</a>
                </span>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <div class="resultbar">
        <span>
            <strong><?= $e($num($total['count'])) ?><?= $total['capped'] ? '+' : '' ?></strong>
            <?= $total['count'] === 1 ? 'Treffer' : 'Treffer' ?>
            <?php if ($total['capped']): ?>
                <span class="muted">(ab <?= $e($num(\LogWarden\Search\SearchCriteria::COUNT_CAP)) ?> nicht weiter gezählt)</span>
            <?php endif; ?>
        </span>

        <span class="muted">
            <?= $e($criteria->from->format('d.m. H:i')) ?> – <?= $e($criteria->to->format('d.m. H:i')) ?> UTC
        </span>

        <?php if ($facets['source'] !== []): ?>
            <div class="facets" <?= !empty($facets['sampled'])
                ? 'title="Verteilung der ' . $e($num(\LogWarden\Search\SearchCriteria::COUNT_CAP)) . ' neuesten Treffer"' : '' ?>>
                <?php if (!empty($facets['sampled'])): ?>
                    <span class="muted" style="font-size:0.78rem">Verteilung der neuesten <?= $e($num(\LogWarden\Search\SearchCriteria::COUNT_CAP)) ?>:</span>
                <?php endif; ?>
                <?php foreach ($facets['source'] as $type => $count): ?>
                    <span class="facet">
                        <span class="legend__swatch" style="background:var(<?= $e($seriesColor[$type] ?? '--ink-3') ?>)"></span>
                        <?= $e($labels[$type] ?? $type) ?>
                        <span class="facet__count"><?= $e($num($count)) ?></span>
                    </span>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if (($facets['result']['fail'] ?? 0) > 0): ?>
            <span class="facet" style="color:var(--status-critical)">
                Fehlgeschlagen <span class="facet__count"><?= $e($num($facets['result']['fail'])) ?></span>
            </span>
        <?php endif; ?>

        <div class="grow"></div>

        <a class="btn btn--ghost" href="/search/export.csv?<?= $e($criteria->toQueryString(['cts' => null, 'cid' => null])) ?>">
            CSV exportieren
        </a>
    </div>

    <div class="card__body--flush">
        <?php if ($rows === []): ?>
            <p class="table__empty">
                Keine Events für diese Auswahl.<br>
                <span class="muted">Zeitraum erweitern oder Filter entfernen.</span>
            </p>
        <?php else: ?>
            <table class="table table--rows">
                <thead>
                    <tr>
                        <th scope="col">Zeit (UTC)</th>
                        <th scope="col">Quelle</th>
                        <th scope="col">System</th>
                        <th scope="col">Event</th>
                        <th scope="col">Konto</th>
                        <th scope="col">Quell-IP</th>
                        <th scope="col">Ergebnis</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($rows as $row): ?>
                    <?php $href = '/event?ts=' . rawurlencode((string) $row['ts_iso']) . '&id=' . (int) $row['id']; ?>
                    <tr onclick="if(!window.getSelection().toString()){location.href=this.dataset.href}"
                        data-href="<?= $e($href) ?>">
                        <td class="nowrap mono">
                            <a class="rowlink" href="<?= $e($href) ?>"><?= $e($row['ts_label']) ?></a>
                        </td>
                        <td><span class="badge badge--source"><?= $e($labels[$row['source_type']] ?? $row['source_type']) ?></span></td>
                        <td class="mono"><?= $e($row['source_host']) ?></td>
                        <td class="mono">
                            <?= $e($row['event_type']) ?>
                            <span class="snippet"><?= $e(mb_substr((string) $row['raw_message'], 0, 110)) ?></span>
                        </td>
                        <td class="mono"><?= $e($row['username'] ?? '–') ?></td>
                        <td class="mono"><?= $e($row['src_ip'] ?? '–') ?></td>
                        <td><?= $badge($row['result']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <?php if ($hasMore && $nextCursor !== null): ?>
        <div class="pager">
            <a class="btn btn--ghost"
               href="/search?<?= $e($criteria->toQueryString($nextCursor)) ?>">Weitere Treffer</a>
            <?php if ($criteria->cursorTs !== null): ?>
                <a class="btn btn--ghost" href="/search?<?= $e($criteria->toQueryString(['cts' => null, 'cid' => null])) ?>">
                    Zurück zum Anfang
                </a>
            <?php endif; ?>
            <span class="muted" style="margin-left:auto; font-size:0.8rem">
                Seitenweise über den Zeitstempel — auch bei sehr vielen Treffern gleich schnell.
            </span>
        </div>
    <?php elseif ($criteria->cursorTs !== null): ?>
        <div class="pager">
            <a class="btn btn--ghost" href="/search?<?= $e($criteria->toQueryString(['cts' => null, 'cid' => null])) ?>">
                Zurück zum Anfang
            </a>
            <span class="muted" style="margin-left:auto; font-size:0.8rem">Ende der Treffer erreicht.</span>
        </div>
    <?php endif; ?>
</section>
