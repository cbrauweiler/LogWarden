<?php
/**
 * @var array $channels
 * @var array $rules
 * @var array $routing
 * @var array $flash
 * @var array $errors
 */

use LogWarden\Alerting\AlertQuery;
use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e   = static fn (mixed $v): string => View::e($v);
$num = static fn (int|float $v): string => View::number($v);

$types = [
    'teams_workflow' => 'Teams Workflow (Power Automate)',
    'teams_webhook'  => 'Teams Connector (klassisch)',
];
?>

<?php foreach ($flash as $message): ?>
    <div class="notice notice--ok" role="status">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 12 5 5L20 6"/></svg>
        <div><?= $e($message) ?></div>
    </div>
<?php endforeach; ?>

<?php if ($errors !== []): ?>
    <div class="notice notice--critical" role="alert">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
        <div>
            <ul style="margin:0; padding-left:1.1rem">
                <?php foreach ($errors as $error): ?><li><?= $e($error) ?></li><?php endforeach; ?>
            </ul>
        </div>
    </div>
<?php endif; ?>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Kanäle</h2>
            <p class="card__hint">
                Microsoft Teams Incoming Webhooks. Die URL ist das Zugangsgeheimnis und wird
                verschlüsselt gespeichert — sie wird nie wieder angezeigt.
            </p>
        </div>
    </div>

    <div class="card__body--flush">
        <?php if ($channels === []): ?>
            <p class="table__empty">Noch kein Kanal angelegt.</p>
        <?php else: ?>
            <table class="table">
                <thead>
                    <tr>
                        <th scope="col">Kanal</th>
                        <th scope="col">Typ</th>
                        <th scope="col">Ab Schweregrad</th>
                        <th scope="col">Webhook</th>
                        <th scope="col">Zustellung</th>
                        <th scope="col">Regeln</th>
                        <th scope="col">Aktionen</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($channels as $channel): ?>
                    <tr>
                        <td>
                            <strong><?= $e($channel['name']) ?></strong>
                            <?php if (!$channel['enabled']): ?>
                                <br><span class="badge badge--info"><span class="badge__dot"></span>inaktiv</span>
                            <?php endif; ?>
                        </td>
                        <td class="muted"><?= $e($types[$channel['type']] ?? $channel['type']) ?></td>
                        <td><?= $e(AlertQuery::SEVERITY_LABELS[$channel['min_severity']] ?? $channel['min_severity']) ?></td>
                        <td>
                            <?php if (empty($channel['secret_ref'])): ?>
                                <span class="badge badge--fail"><span class="badge__dot"></span>fehlt</span>
                            <?php else: ?>
                                <span class="badge badge--success"><span class="badge__dot"></span>hinterlegt</span>
                                <br><span class="chip"><?= $e($channel['secret_ref']) ?></span>
                            <?php endif; ?>
                        </td>
                        <td class="muted">
                            <?= $e($num((int) $channel['sent_total'])) ?> gesendet
                            <?php if ((int) $channel['failed_total'] > 0): ?>
                                · <?= $e($num((int) $channel['failed_total'])) ?> fehlgeschlagen
                            <?php endif; ?>
                            <br>
                            <?php if (!empty($channel['last_error'])): ?>
                                <span style="color:var(--status-critical)" title="<?= $e($channel['last_error']) ?>">
                                    Fehler <?= $e($channel['last_error_label'] ?? '') ?>
                                </span>
                            <?php else: ?>
                                zuletzt: <?= $e($channel['last_success_label'] ?? 'nie') ?>
                            <?php endif; ?>
                        </td>
                        <td class="num"><?= $e($channel['rule_count']) ?></td>
                        <td>
                            <div class="row" style="gap:0.35rem">
                                <form method="post" action="/settings/notifications">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="test_channel">
                                    <input type="hidden" name="channel_id" value="<?= $e($channel['id']) ?>">
                                    <button class="btn btn--ghost" type="submit"
                                            <?= empty($channel['secret_ref']) ? 'disabled title="Erst Webhook-URL hinterlegen"' : '' ?>>
                                        Test
                                    </button>
                                </form>
                                <form method="post" action="/settings/notifications"
                                      onsubmit="return confirm('Kanal <?= $e($channel['name']) ?> und die hinterlegte Webhook-URL löschen?')">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="delete_channel">
                                    <input type="hidden" name="channel_id" value="<?= $e($channel['id']) ?>">
                                    <button class="btn btn--danger" type="submit">Löschen</button>
                                </form>
                            </div>
                        </td>
                    </tr>

                    <tr>
                        <td colspan="7" style="background:var(--surface-sunken)">
                            <div class="grid-2" style="gap:0 1.5rem">
                                <form method="post" action="/settings/notifications">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="save_channel">
                                    <input type="hidden" name="channel_id" value="<?= $e($channel['id']) ?>">
                                    <div class="row" style="gap:0.5rem; align-items:flex-end">
                                        <div class="field" style="margin:0; flex:1; min-width:140px">
                                            <label class="field__label" for="name_<?= $e($channel['id']) ?>">Name</label>
                                            <input class="input" id="name_<?= $e($channel['id']) ?>" name="name"
                                                   value="<?= $e($channel['name']) ?>" maxlength="80" required>
                                        </div>
                                        <div class="field" style="margin:0; min-width:110px">
                                            <label class="field__label" for="sev_<?= $e($channel['id']) ?>">Ab</label>
                                            <select class="select" id="sev_<?= $e($channel['id']) ?>" name="min_severity">
                                                <?php foreach (AlertQuery::SEVERITY_LABELS as $value => $label): ?>
                                                    <option value="<?= $e($value) ?>"
                                                        <?= (int) $channel['min_severity'] === $value ? 'selected' : '' ?>>
                                                        <?= $e($label) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div class="field" style="margin:0; min-width:150px">
                                            <label class="field__label" for="type_<?= $e($channel['id']) ?>">Typ</label>
                                            <select class="select" id="type_<?= $e($channel['id']) ?>" name="type">
                                                <?php foreach ($types as $value => $label): ?>
                                                    <option value="<?= $e($value) ?>"
                                                        <?= $channel['type'] === $value ? 'selected' : '' ?>>
                                                        <?= $e($label) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <label class="row" style="gap:0.4rem; margin-bottom:0.5rem">
                                            <input type="checkbox" name="enabled" value="1"
                                                   <?= $channel['enabled'] ? 'checked' : '' ?>>
                                            <span>aktiv</span>
                                        </label>
                                        <button class="btn btn--ghost" type="submit" style="margin-bottom:0.35rem">Speichern</button>
                                    </div>
                                </form>

                                <form method="post" action="/settings/notifications" autocomplete="off">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="set_webhook">
                                    <input type="hidden" name="channel_id" value="<?= $e($channel['id']) ?>">
                                    <div class="row" style="gap:0.5rem; align-items:flex-end">
                                        <div class="field" style="margin:0; flex:1; min-width:220px">
                                            <label class="field__label" for="hook_<?= $e($channel['id']) ?>">
                                                Webhook-URL <?= empty($channel['secret_ref']) ? '' : 'ersetzen' ?>
                                            </label>
                                            <input class="input" id="hook_<?= $e($channel['id']) ?>" name="webhook_url"
                                                   type="password" autocomplete="new-password"
                                                   placeholder="https://prod-01.westeurope.logic.azure.com/workflows/…">
                                        </div>
                                        <button class="btn btn--ghost" type="submit" style="margin-bottom:0.35rem">Hinterlegen</button>
                                    </div>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <form class="actions" method="post" action="/settings/notifications">
        <?= Csrf::field() ?>
        <input type="hidden" name="action" value="save_channel">
        <input type="hidden" name="channel_id" value="0">
        <input type="hidden" name="enabled" value="1">
        <label class="visually-hidden" for="new_name">Name des neuen Kanals</label>
        <input class="input" id="new_name" name="name" placeholder="Neuer Kanal, z. B. SOC-Teams"
               maxlength="80" required style="max-width:22rem">
        <label class="visually-hidden" for="new_type">Typ</label>
        <select class="select" id="new_type" name="type" style="max-width:16rem">
            <?php foreach ($types as $value => $label): ?>
                <option value="<?= $e($value) ?>"><?= $e($label) ?></option>
            <?php endforeach; ?>
        </select>
        <label class="visually-hidden" for="new_sev">Ab Schweregrad</label>
        <select class="select" id="new_sev" name="min_severity" style="max-width:10rem">
            <?php foreach (AlertQuery::SEVERITY_LABELS as $value => $label): ?>
                <option value="<?= $e($value) ?>">ab <?= $e($label) ?></option>
            <?php endforeach; ?>
        </select>
        <button class="btn btn--primary" type="submit">Kanal anlegen</button>
    </form>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Zuordnung</h2>
            <p class="card__hint">
                Welche Regel meldet an welchen Kanal. Ohne Häkchen wird ein Alert erzeugt,
                aber niemandem zugestellt.
            </p>
        </div>
    </div>

    <form method="post" action="/settings/notifications">
        <?= Csrf::field() ?>
        <input type="hidden" name="action" value="save_routing">

        <div class="card__body--flush">
            <?php if ($channels === []): ?>
                <p class="table__empty">Zuerst einen Kanal anlegen.</p>
            <?php else: ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th scope="col">Regel</th>
                            <?php foreach ($channels as $channel): ?>
                                <th scope="col" style="text-align:center">
                                    <?= $e($channel['name']) ?>
                                    <br><span class="muted" style="font-weight:400">
                                        ab <?= $e(AlertQuery::SEVERITY_LABELS[$channel['min_severity']] ?? '') ?>
                                    </span>
                                </th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($rules as $rule): ?>
                        <tr>
                            <td>
                                <?= $e($rule['name']) ?>
                                <br><span class="chip"><?= $e($rule['rule_key']) ?></span>
                                <?php if (!$rule['enabled']): ?>
                                    <span class="badge badge--info"><span class="badge__dot"></span>inaktiv</span>
                                <?php endif; ?>
                            </td>
                            <?php foreach ($channels as $channel): ?>
                                <?php $key = $rule['id'] . ':' . $channel['id']; ?>
                                <td style="text-align:center">
                                    <label class="visually-hidden" for="route_<?= $e($key) ?>">
                                        <?= $e($rule['name']) ?> an <?= $e($channel['name']) ?>
                                    </label>
                                    <input type="checkbox" id="route_<?= $e($key) ?>" name="route[]"
                                           value="<?= $e($key) ?>" <?= isset($routing[$key]) ? 'checked' : '' ?>>
                                </td>
                            <?php endforeach; ?>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>

        <?php if ($channels !== []): ?>
            <div class="actions">
                <button class="btn btn--primary" type="submit">Zuordnung speichern</button>
                <span class="muted" style="margin-left:auto">
                    Der Mindest-Schweregrad des Kanals gilt zusätzlich zur Zuordnung.
                </span>
            </div>
        <?php endif; ?>
    </form>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Einrichtung in Teams</h2>
        </div>
    </div>
    <div class="card__body">
        <ol style="margin:0; padding-left:1.2rem; line-height:1.9">
            <li>In Teams den Zielkanal öffnen → <strong>…</strong> → <strong>Workflows</strong></li>
            <li>Vorlage <em>„Post to a channel when a webhook request is received"</em> wählen</li>
            <li>Nach dem Anlegen die erzeugte HTTP-POST-URL kopieren</li>
            <li>Hier oben beim passenden Kanal unter <strong>Webhook-URL</strong> einfügen</li>
            <li><strong>Test</strong> drücken — die Testkarte muss in Teams erscheinen</li>
        </ol>
        <p class="card__hint" style="margin-top:0.9rem">
            Die klassischen Office-365-Connectors funktionieren weiterhin, werden von Microsoft
            aber abgekündigt. Für neue Kanäle ist <em>Workflow</em> die richtige Wahl.
        </p>
        <p class="card__hint">
            Die Farben der Corporate Identity greifen in Teams nicht: Adaptive Cards folgen dem
            Teams-Design des Empfängers. Übertragen wird der Produktname; der Schweregrad nutzt
            die semantischen Farben der Karte, die im Hell- wie im Dunkelmodus lesbar bleiben.
        </p>
    </div>
</section>
