<?php
/**
 * @var string $status
 * @var int    $severity
 * @var string $search
 * @var array  $counters
 * @var array  $alerts
 * @var array  $rules
 * @var array  $flash
 */

use LogWarden\Alerting\AlertQuery;
use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e   = static fn (mixed $v): string => View::e($v);
$num = static fn (int|float $v): string => View::number($v);

$statuses = ['new' => 'Offen', 'ack' => 'Quittiert', 'closed' => 'Geschlossen', 'all' => 'Alle'];

$queryString = static function (array $overrides) use ($status, $severity, $search): string {
    $params = array_filter(
        ['status' => $status, 'severity' => $severity ?: null, 'q' => $search ?: null] + $overrides,
        static fn (mixed $v): bool => $v !== null && $v !== '',
    );

    return http_build_query(array_merge($params, $overrides));
};
?>

<?php foreach ($flash as $message): ?>
    <div class="notice notice--ok" role="status">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 12 5 5L20 6"/></svg>
        <div><?= $e($message) ?></div>
    </div>
<?php endforeach; ?>

<section class="tiles">
    <div class="tile <?= $counters['open'] > 0 ? 'tile--accent' : '' ?>">
        <span class="tile__label">Offene Alerts</span>
        <span class="tile__value"><?= $e($num($counters['open'])) ?></span>
        <span class="tile__meta">noch nicht quittiert</span>
    </div>
    <div class="tile <?= $counters['critical'] > 0 ? 'tile--critical' : '' ?>">
        <span class="tile__label">Davon kritisch</span>
        <span class="tile__value"><?= $e($num($counters['critical'])) ?></span>
        <span class="tile__meta">Schweregrad 5</span>
    </div>
    <div class="tile">
        <span class="tile__label">Heute ausgelöst</span>
        <span class="tile__value"><?= $e($num($counters['today'])) ?></span>
        <span class="tile__meta">seit Mitternacht</span>
    </div>
    <div class="tile">
        <span class="tile__label">Nicht gemeldet</span>
        <span class="tile__value"><?= $e($num($counters['unnotified'])) ?></span>
        <span class="tile__meta">
            <?= $counters['unnotified'] > 0
                ? 'Teams-Anbindung steht noch aus'
                : 'alle zugestellt' ?>
        </span>
    </div>
</section>

<section class="card">
    <form class="filterbar" method="get" action="/alerts">
        <div class="segmented">
            <?php foreach ($statuses as $key => $label): ?>
                <a href="/alerts?<?= $e($queryString(['status' => $key])) ?>"
                   aria-current="<?= $status === $key ? 'true' : 'false' ?>"><?= $e($label) ?></a>
            <?php endforeach; ?>
        </div>

        <input type="hidden" name="status" value="<?= $e($status) ?>">

        <label class="visually-hidden" for="severity">Mindest-Schweregrad</label>
        <select class="select" id="severity" name="severity" onchange="this.form.submit()">
            <option value="0">Alle Schweregrade</option>
            <?php foreach (array_reverse(AlertQuery::SEVERITY_LABELS, true) as $value => $label): ?>
                <option value="<?= $e($value) ?>" <?= $severity === $value ? 'selected' : '' ?>>
                    ab <?= $e($label) ?>
                </option>
            <?php endforeach; ?>
        </select>

        <label class="visually-hidden" for="q">Suche</label>
        <input class="input" id="q" name="q" value="<?= $e($search) ?>"
               placeholder="Konto, IP oder Titel">

        <button class="btn btn--ghost" type="submit">Filtern</button>
        <?php if ($search !== '' || $severity > 0): ?>
            <a class="btn btn--ghost" href="/alerts?status=<?= $e($status) ?>">Zurücksetzen</a>
        <?php endif; ?>
    </form>

    <div class="alertlist">
        <?php if ($alerts === []): ?>
            <p class="table__empty">
                <?= $status === 'new'
                    ? 'Keine offenen Alerts.'
                    : 'Keine Alerts für diese Auswahl.' ?>
            </p>
        <?php endif; ?>

        <?php foreach ($alerts as $alert): ?>
            <?php
            $resolved = $alert['status'] !== 'new';
            $class    = $resolved ? 'resolved' : AlertQuery::severityClass((int) $alert['severity']);
            $evidence = json_decode((string) $alert['evidence'], true) ?: [];
            ?>
            <article class="alertrow alertrow--<?= $e($class) ?>">
                <div class="alertrow__stripe" aria-hidden="true"></div>

                <div class="alertrow__main">
                    <div class="alertrow__title">
                        <a href="/alert?id=<?= $e($alert['id']) ?>"><?= $e($alert['title']) ?></a>
                    </div>
                    <p class="alertrow__summary"><?= $e($alert['summary']) ?></p>
                    <div class="alertrow__meta">
                        <span><?= $e($alert['rule_name']) ?></span>
                        <?php if (!empty($alert['entity_user'])): ?>
                            <span>Konto <strong><?= $e($alert['entity_user']) ?></strong></span>
                        <?php endif; ?>
                        <?php if (!empty($alert['entity_ip'])): ?>
                            <span>IP <strong><?= $e($alert['entity_ip']) ?></strong></span>
                        <?php endif; ?>
                        <span>Ausgelöst <strong><?= $e($alert['triggered_label']) ?></strong></span>
                        <?php if (!empty($alert['last_seen_label']) && $alert['last_seen_label'] !== $alert['triggered_label']): ?>
                            <span>Zuletzt <strong><?= $e($alert['last_seen_label']) ?></strong></span>
                        <?php endif; ?>
                        <?php if (!empty($evidence['peak_count']) && (int) $evidence['peak_count'] > (int) $alert['event_count']): ?>
                            <span>Höchststand <strong><?= $e($num((int) $evidence['peak_count'])) ?></strong></span>
                        <?php endif; ?>
                        <?php if ($resolved && !empty($alert['ack_by_name'])): ?>
                            <span><?= $e(AlertQuery::STATUS_LABELS[$alert['status']] ?? $alert['status']) ?>
                                von <strong><?= $e($alert['ack_by_name']) ?></strong>
                                <?= $e($alert['ack_label'] ?? '') ?></span>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="alertrow__side">
                    <?= $view->render('partials/severity', ['severity' => (int) $alert['severity']]) ?>
                    <div style="margin-top:0.5rem; color:var(--ink-3); font-size:0.78rem">
                        <?= $e($num((int) $alert['event_count'])) ?> Events
                    </div>
                    <?php if (!$resolved): ?>
                        <form method="post" action="/alerts/ack" style="margin-top:0.5rem">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="id" value="<?= $e($alert['id']) ?>">
                            <button class="btn btn--ghost" type="submit">Quittieren</button>
                        </form>
                    <?php endif; ?>
                </div>
            </article>
        <?php endforeach; ?>
    </div>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Regeln</h2>
            <p class="card__hint">Status der konfigurierten Erkennungsregeln</p>
        </div>
    </div>
    <div class="card__body--flush">
        <table class="table">
            <thead>
                <tr>
                    <th scope="col">Regel</th>
                    <th scope="col">Schlüssel</th>
                    <th scope="col">Fenster</th>
                    <th scope="col">Letzter Lauf</th>
                    <th scope="col" class="num">7 Tage</th>
                    <th scope="col" class="num">Offen</th>
                    <th scope="col">Status</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($rules as $rule): ?>
                <tr>
                    <td><?= $e($rule['name']) ?></td>
                    <td><span class="chip"><?= $e($rule['rule_key']) ?></span></td>
                    <td class="nowrap muted"><?= $e($rule['window_minutes']) ?> min</td>
                    <td class="nowrap muted">
                        <?= $e($rule['last_run_label'] ?? 'nie') ?>
                        <?php if ($rule['last_duration_ms'] !== null): ?>
                            <span class="muted">· <?= $e($rule['last_duration_ms']) ?> ms</span>
                        <?php endif; ?>
                    </td>
                    <td class="num"><?= $e($num((int) $rule['alerts_7d'])) ?></td>
                    <td class="num"><?= $e($num((int) $rule['open_alerts'])) ?></td>
                    <td>
                        <?php if (!$rule['enabled']): ?>
                            <span class="badge badge--info"><span class="badge__dot"></span>inaktiv</span>
                        <?php elseif (!empty($rule['last_error'])): ?>
                            <span class="badge badge--fail" title="<?= $e($rule['last_error']) ?>">
                                <span class="badge__dot"></span>Fehler
                            </span>
                        <?php else: ?>
                            <span class="badge badge--success"><span class="badge__dot"></span>aktiv</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</section>
