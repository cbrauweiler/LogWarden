<?php
/**
 * @var array $alert
 * @var array $events
 * @var array $evidence
 * @var bool  $eventsPruned
 */

use LogWarden\Alerting\AlertQuery;
use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e   = static fn (mixed $v): string => View::e($v);
$num = static fn (int|float $v): string => View::number($v);

// Keys rendered with their own label and order; whatever a rule adds beyond
// this still shows up, just after the known ones.
$labels = [
    'failures'            => 'Fehlschläge',
    'threshold'           => 'Schwellwert',
    'preceding_failures'  => 'Vorausgegangene Fehlversuche',
    'ad_failures'         => 'AD-Fehlschläge',
    'peak_count'          => 'Höchststand',
    'evaluations'         => 'Auswertungen',
    'locked_at'           => 'Gesperrt um',
    'caller_computer'     => 'Auslösender Rechner',
    'domain_controller'   => 'Domain Controller',
    'vpn_login_at'        => 'VPN-Login',
    'vpn_source_ip'       => 'VPN-Quell-IP',
    'vpn_gateway'         => 'VPN-Gateway',
    'correlation_minutes' => 'Korrelationsfenster (min)',
    'lookback_minutes'    => 'Rückblick (min)',
    'first_seen'          => 'Erstmals',
    'last_seen'           => 'Zuletzt',
    'last_failure'        => 'Letzter Fehlschlag',
    'window'              => 'Zeitfenster',
];

$hidden = ['by_origin', 'by_source', 'source_ips', 'target_hosts', 'ad_event_types', 'event_types'];

$resolved = $alert['status'] !== 'new';
$class    = $resolved ? 'resolved' : AlertQuery::severityClass((int) $alert['severity']);

$badge = static function (?string $result) : string {
    return match ($result) {
        'fail'    => '<span class="badge badge--fail"><span class="badge__dot"></span>Fehler</span>',
        'success' => '<span class="badge badge--success"><span class="badge__dot"></span>Erfolg</span>',
        default   => '<span class="badge badge--info"><span class="badge__dot"></span>Info</span>',
    };
};
?>

<section class="card">
    <div class="card__head">
        <div style="min-width:0">
            <div class="row" style="margin-bottom:0.35rem">
                <?= $view->render('partials/severity', ['severity' => (int) $alert['severity']]) ?>
                <span class="badge badge--info">
                    <span class="badge__dot"></span>
                    <?= $e(AlertQuery::STATUS_LABELS[$alert['status']] ?? $alert['status']) ?>
                </span>
                <span class="chip"><?= $e($alert['rule_key']) ?></span>
            </div>
            <h2><?= $e($alert['title']) ?></h2>
            <p class="card__hint" style="margin-top:0.35rem"><?= $e($alert['summary']) ?></p>
        </div>
        <a class="btn btn--ghost nowrap" href="/alerts">Zurück zur Liste</a>
    </div>

    <div class="card__body">
        <dl class="kv">
            <dt>Regel</dt>
            <dd><?= $e($alert['rule_name']) ?></dd>

            <dt>Ausgelöst</dt>
            <dd><?= $e($alert['triggered_label']) ?></dd>

            <?php if (!empty($alert['last_seen_label'])): ?>
                <dt>Zuletzt beobachtet</dt>
                <dd><?= $e($alert['last_seen_label']) ?></dd>
            <?php endif; ?>

            <dt>Auswertungsfenster</dt>
            <dd><?= $e($alert['window_start_label']) ?> – <?= $e($alert['window_end_label']) ?></dd>

            <?php if (!empty($alert['entity_user'])): ?>
                <dt>Konto</dt>
                <dd class="mono"><?= $e($alert['entity_user']) ?></dd>
            <?php endif; ?>

            <?php if (!empty($alert['entity_ip_text'])): ?>
                <dt>Quell-IP</dt>
                <dd class="mono"><?= $e($alert['entity_ip_text']) ?></dd>
            <?php endif; ?>

            <?php if (!empty($alert['entity_host'])): ?>
                <dt>System</dt>
                <dd class="mono"><?= $e($alert['entity_host']) ?></dd>
            <?php endif; ?>

            <dt>Betroffene Events</dt>
            <dd><?= $e($num((int) $alert['event_count'])) ?></dd>

            <?php if ($resolved): ?>
                <dt>Quittiert</dt>
                <dd>
                    <?= $e($alert['ack_label'] ?? '–') ?>
                    <?php if (!empty($alert['ack_by_name'])): ?>
                        von <?= $e($alert['ack_by_name']) ?>
                    <?php endif; ?>
                    <?php if (!empty($alert['ack_note'])): ?>
                        <br><span class="muted"><?= $e($alert['ack_note']) ?></span>
                    <?php endif; ?>
                </dd>
            <?php endif; ?>
        </dl>
    </div>

    <?php if (!$resolved): ?>
        <form class="actions" method="post" action="/alerts/ack">
            <?= Csrf::field() ?>
            <input type="hidden" name="id" value="<?= $e($alert['id']) ?>">
            <input type="hidden" name="back" value="detail">
            <label class="visually-hidden" for="note">Notiz</label>
            <input class="input" id="note" name="note" placeholder="Notiz (optional)" style="max-width:26rem">
            <button class="btn btn--primary" type="submit" name="action" value="ack">Quittieren</button>
            <button class="btn btn--ghost" type="submit" name="action" value="close">Schließen</button>
        </form>
    <?php endif; ?>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Beweislage</h2>
            <p class="card__hint">
                Von der Regel festgehalten. Bleibt lesbar, auch wenn die Quell-Events
                aus der Aufbewahrung gelaufen sind.
            </p>
        </div>
    </div>
    <div class="card__body">
        <dl class="kv">
            <?php foreach ($evidence as $key => $value): ?>
                <?php if (in_array($key, $hidden, true) || $value === null || $value === []) { continue; } ?>
                <dt><?= $e($labels[$key] ?? $key) ?></dt>
                <dd class="<?= is_string($value) && filter_var($value, FILTER_VALIDATE_IP) ? 'mono' : '' ?>">
                    <?= $e(is_scalar($value) ? (string) $value : json_encode($value, JSON_UNESCAPED_UNICODE)) ?>
                </dd>
            <?php endforeach; ?>

            <?php if (!empty($evidence['by_source'])): ?>
                <dt>Nach Quelle</dt>
                <dd class="chips">
                    <?php foreach ($evidence['by_source'] as $source => $count): ?>
                        <span class="chip"><?= $e($source) ?>: <?= $e($count) ?></span>
                    <?php endforeach; ?>
                </dd>
            <?php endif; ?>

            <?php foreach (['source_ips' => 'Quell-IPs', 'target_hosts' => 'Zielsysteme', 'ad_event_types' => 'AD-Event-IDs', 'event_types' => 'Event-Typen'] as $key => $label): ?>
                <?php if (empty($evidence[$key])) { continue; } ?>
                <dt><?= $e($label) ?></dt>
                <dd class="chips">
                    <?php foreach ((array) $evidence[$key] as $item): ?>
                        <span class="chip"><?= $e($item) ?></span>
                    <?php endforeach; ?>
                </dd>
            <?php endforeach; ?>
        </dl>

        <?php if (!empty($evidence['by_origin'])): ?>
            <h3 style="margin:1.25rem 0 0.5rem">Nach Herkunft</h3>
            <p class="card__hint" style="margin-bottom:0.6rem">
                Viele Versuche von einer Adresse deuten auf ein hinterlegtes altes Passwort,
                verteilte Versuche auf einen Angriff.
            </p>
            <div class="tablewrap">
            <table class="table">
                <thead>
                    <tr>
                        <th scope="col">Quell-IP</th>
                        <th scope="col">Ziel</th>
                        <th scope="col">Quelle</th>
                        <th scope="col" class="num">Versuche</th>
                        <th scope="col">Zuletzt</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($evidence['by_origin'] as $origin): ?>
                    <tr>
                        <td class="mono"><?= $e($origin['src_ip'] ?? '–') ?></td>
                        <td class="mono"><?= $e($origin['target_host'] ?? '–') ?></td>
                        <td><span class="badge badge--source"><?= $e($origin['source_type'] ?? '') ?></span></td>
                        <td class="num"><?= $e($num((int) ($origin['count'] ?? 0))) ?></td>
                        <td class="nowrap muted"><?= $e($origin['last_seen'] ?? '') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        <?php endif; ?>
    </div>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Auslösende Events</h2>
            <p class="card__hint"><?= $e(count($events)) ?> verknüpfte Events</p>
        </div>
    </div>
    <div class="card__body--flush">
        <?php if ($eventsPruned): ?>
            <p class="table__empty">
                Die verknüpften Events sind nicht mehr vorhanden — sie sind aus der
                Aufbewahrung gelaufen. Die Beweislage oben bleibt davon unberührt.
            </p>
        <?php elseif ($events === []): ?>
            <p class="table__empty">Keine Events verknüpft.</p>
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
                <?php foreach ($events as $event): ?>
                    <tr>
                        <td class="nowrap mono"><?= $e($event['ts_label']) ?></td>
                        <td><span class="badge badge--source"><?= $e($event['source_type']) ?></span></td>
                        <td class="mono"><?= $e($event['source_host']) ?></td>
                        <td class="mono"><?= $e($event['event_type']) ?></td>
                        <td class="mono"><?= $e($event['username'] ?? '–') ?></td>
                        <td class="mono"><?= $e($event['src_ip'] ?? '–') ?></td>
                        <td><?= $badge($event['result']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</section>
