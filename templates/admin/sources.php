<?php
/**
 * @var array $sources
 * @var array $channels
 * @var array $catalogue
 * @var array $defaultIds
 * @var array $runs
 * @var ?\LogWarden\Ingest\IngestSource $edit
 * @var array $flash
 * @var array $errors
 */

use LogWarden\Ingest\Windows\AdEventCatalog;
use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e   = static fn (mixed $v): string => View::e($v);
$num = static fn (int|float $v): string => View::number($v);

// Prefilled from the source being edited, or the defaults for a new one.
// Without this, changing the poll interval on an existing source would submit
// an empty event selection and silently reset it.
$selected = $edit === null ? $defaultIds : $edit->eventIds();
$on       = static fn (bool $v): string => $v ? 'checked' : '';
$val      = static function (string $key, mixed $fallback) use ($edit): mixed {
    if ($edit === null) {
        return $fallback;
    }

    return match ($key) {
        'name'        => $edit->name,
        'target_host' => $edit->targetHost,
        'username'    => $edit->username,
        'auth_mode'   => $edit->authMode,
        'interval'    => $edit->pollIntervalS,
        default       => $edit->setting($key, $fallback),
    };
};

$ago = static function (?string $timestamp): string {
    if ($timestamp === null || $timestamp === '') {
        return 'nie';
    }

    $seconds = time() - strtotime($timestamp);

    return match (true) {
        $seconds < 90    => 'gerade eben',
        $seconds < 5400  => intdiv($seconds, 60) . ' min',
        $seconds < 172800 => intdiv($seconds, 3600) . ' h',
        default          => intdiv($seconds, 86400) . ' Tage',
    };
};
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
            <h2>WinRM-Quellen</h2>
            <p class="card__hint">
                Windows-Ereignisprotokolle werden per WinRM abgeholt — kein Agent auf dem Zielsystem.
                Jede Quelle ist ein Host und ein Kanal und führt ihr eigenes Lesezeichen.
                Einrichtung auf der Windows-Seite: <code>docs/winrm.md</code>.
            </p>
        </div>
    </div>

    <div class="card__body--flush">
        <?php if ($sources === []): ?>
            <p class="table__empty">Noch keine Quelle angelegt.</p>
        <?php else: ?>
            <table class="table">
                <thead>
                    <tr>
                        <th scope="col">Quelle</th>
                        <th scope="col">Kanal</th>
                        <th scope="col">Zustand</th>
                        <th scope="col">Letzter Erfolg</th>
                        <th scope="col" class="num">Events 24 h</th>
                        <th scope="col">Aktionen</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($sources as $source): ?>
                    <tr>
                        <td>
                            <strong><?= $e($source['name']) ?></strong>
                            <br><span class="muted"><?= $e($source['target_host']) ?></span>
                        </td>
                        <td class="muted"><?= $e($channels[$source['channel']][0] ?? $source['channel']) ?></td>
                        <td>
                            <?php if (!$source['enabled']): ?>
                                <span class="badge badge--info"><span class="badge__dot"></span>aus</span>
                            <?php elseif (!empty($source['last_error'])): ?>
                                <span class="badge badge--fail"><span class="badge__dot"></span>Fehler</span>
                                <?php if ((int) $source['consecutive_failures'] > 1): ?>
                                    <br><span class="muted"><?= $e($source['consecutive_failures']) ?>× in Folge</span>
                                <?php endif; ?>
                            <?php else: ?>
                                <span class="badge badge--success"><span class="badge__dot"></span>aktiv</span>
                            <?php endif; ?>
                        </td>
                        <td class="muted">
                            vor <?= $e($ago($source['last_success_at'])) ?>
                            <?php if ((int) $source['errors_24h'] > 0): ?>
                                <br><span style="color:var(--status-warn)">
                                    <?= $e($source['errors_24h']) ?> Fehler in 24 h
                                </span>
                            <?php endif; ?>
                        </td>
                        <td class="num"><?= $e($num((int) $source['stored_24h'])) ?></td>
                        <td>
                            <div class="row" style="gap:0.35rem; flex-wrap:wrap">
                                <a class="btn btn--ghost" href="/settings/sources?edit=<?= $e($source['id']) ?>#form">
                                    Ändern
                                </a>
                                <form method="post" action="/settings/sources">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="test">
                                    <input type="hidden" name="source_id" value="<?= $e($source['id']) ?>">
                                    <button class="btn btn--ghost" type="submit">Test</button>
                                </form>
                                <form method="post" action="/settings/sources">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="toggle">
                                    <input type="hidden" name="source_id" value="<?= $e($source['id']) ?>">
                                    <button class="btn btn--ghost" type="submit">
                                        <?= $source['enabled'] ? 'Deaktivieren' : 'Aktivieren' ?>
                                    </button>
                                </form>
                                <form method="post" action="/settings/sources"
                                      onsubmit="return confirm('Lesezeichen zurücksetzen? Der nächste Lauf beginnt wieder bei der eingestellten Vorlaufzeit.')">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="reset">
                                    <input type="hidden" name="source_id" value="<?= $e($source['id']) ?>">
                                    <button class="btn btn--ghost" type="submit">Lesezeichen</button>
                                </form>
                                <form method="post" action="/settings/sources"
                                      onsubmit="return confirm('Quelle <?= $e($source['name']) ?> und das hinterlegte Passwort löschen?')">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="source_id" value="<?= $e($source['id']) ?>">
                                    <button class="btn btn--danger" type="submit">Löschen</button>
                                </form>
                            </div>
                        </td>
                    </tr>

                    <?php if (!empty($source['last_error'])): ?>
                        <tr>
                            <td colspan="6" style="background:var(--surface-sunken)">
                                <p class="muted" style="margin:0">
                                    <strong>Letzter Fehler</strong> (vor <?= $e($ago($source['last_error_at'])) ?>):
                                    <?= $e($source['last_error']) ?>
                                </p>
                            </td>
                        </tr>
                    <?php endif; ?>

                    <?php if (!empty($runs[$source['id']])): ?>
                        <tr>
                            <td colspan="6" style="background:var(--surface-sunken)">
                                <details>
                                    <summary class="muted">Letzte Läufe</summary>
                                    <table class="table table--compact" style="margin-top:0.5rem">
                                        <thead>
                                            <tr>
                                                <th scope="col">Zeit</th>
                                                <th scope="col">Status</th>
                                                <th scope="col" class="num">gelesen</th>
                                                <th scope="col" class="num">gespeichert</th>
                                                <th scope="col" class="num">verworfen</th>
                                                <th scope="col" class="num">Dauer</th>
                                                <th scope="col">Meldung</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                        <?php foreach ($runs[$source['id']] as $run): ?>
                                            <tr>
                                                <td class="muted"><?= $e(substr((string) $run['started_at'], 0, 19)) ?></td>
                                                <td><?= $e($run['status']) ?></td>
                                                <td class="num"><?= $e($num((int) $run['fetched'])) ?></td>
                                                <td class="num"><?= $e($num((int) $run['stored'])) ?></td>
                                                <td class="num"><?= $e($num((int) $run['skipped'])) ?></td>
                                                <td class="num"><?= $e($run['duration_ms']) ?> ms</td>
                                                <td class="muted"><?= $e($run['error'] ?? '') ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </details>
                            </td>
                        </tr>
                    <?php endif; ?>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</section>

<section class="card" id="form">
    <div class="card__head">
        <div>
            <h2><?= $edit === null ? 'Quelle anlegen' : $e('Quelle ändern: ' . $edit->name) ?></h2>
            <p class="card__hint">
                <?php if ($edit === null): ?>
                    Ein bereits vorhandener Name überschreibt die Quelle.
                <?php else: ?>
                    Gespeichert wird das komplette Formular — was hier steht, gilt danach.
                    <a href="/settings/sources">Abbrechen und neue Quelle anlegen</a>.
                <?php endif; ?>
                Das Passwort bleibt leer, wenn es unverändert bleiben soll — es wird
                verschlüsselt gespeichert und nie wieder angezeigt.
            </p>
        </div>
    </div>

    <div class="card__body">
        <form method="post" action="/settings/sources">
            <?= Csrf::field() ?>
            <input type="hidden" name="action" value="save">

            <div class="grid-2" style="gap:0 1.5rem">
                <div class="field">
                    <label class="field__label" for="name">Name</label>
                    <input class="input" id="name" name="name" maxlength="80" required
                           value="<?= $e($val('name', '')) ?>" placeholder="DC01 Sicherheit">
                </div>

                <div class="field">
                    <label class="field__label" for="target_host">Host</label>
                    <input class="input" id="target_host" name="target_host" maxlength="255" required
                           value="<?= $e($val('target_host', '')) ?>" placeholder="dc01.corp.local">
                    <p class="field__hint">FQDN oder IP, ohne Schema und ohne Pfad.</p>
                </div>

                <div class="field">
                    <label class="field__label" for="channel">Kanal</label>
                    <select class="select" id="channel" name="channel">
                        <?php foreach ($channels as $value => $meta): ?>
                            <option value="<?= $e($value) ?>"
                                <?= $edit !== null && $edit->channel() === $value ? 'selected' : '' ?>>
                                <?= $e($meta[0]) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="field">
                    <label class="field__label" for="username">Konto</label>
                    <input class="input" id="username" name="username" maxlength="128" required
                           value="<?= $e($val('username', '')) ?>"
                           placeholder="CORP\svc-logwarden" autocomplete="off">
                    <p class="field__hint">Für NTLM in der Form <code>DOMÄNE\benutzer</code>.</p>
                </div>

                <div class="field">
                    <label class="field__label" for="password">Passwort</label>
                    <input class="input" id="password" name="password" type="password"
                           autocomplete="new-password" placeholder="unverändert lassen">
                </div>

                <div class="field">
                    <label class="field__label" for="auth_mode">Verfahren</label>
                    <select class="select" id="auth_mode" name="auth_mode">
                        <?php foreach (['ntlm' => 'NTLM', 'kerberos' => 'Kerberos', 'basic' => 'Basic (nur mit TLS)'] as $mode => $label): ?>
                            <option value="<?= $e($mode) ?>"
                                <?= $val('auth_mode', 'ntlm') === $mode ? 'selected' : '' ?>>
                                <?= $e($label) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="field">
                    <label class="field__label" for="port">Port</label>
                    <input class="input" id="port" name="port" type="number" min="1" max="65535"
                           value="<?= $e($val('port', 5986)) ?>">
                </div>

                <div class="field">
                    <label class="field__label" for="poll_interval_s">Abrufintervall (s)</label>
                    <input class="input" id="poll_interval_s" name="poll_interval_s" type="number"
                           min="60" max="86400" value="<?= $e($val('interval', 300)) ?>">
                </div>

                <div class="field">
                    <label class="field__label" for="window_seconds">Fenstergröße (s)</label>
                    <input class="input" id="window_seconds" name="window_seconds" type="number"
                           min="60" max="86400" value="<?= $e($val('window_seconds', 900)) ?>">
                    <p class="field__hint">
                        Abgefragt wird immer ein Zeitraum, nie „die nächsten N Events" — sonst
                        entstünden Lücken, sobald der Collector in Rückstand gerät.
                    </p>
                </div>

                <div class="field">
                    <label class="field__label" for="max_events">Max. Events je Fenster</label>
                    <input class="input" id="max_events" name="max_events" type="number"
                           min="100" max="100000" value="<?= $e($val('max_events', 5000)) ?>">
                </div>

                <div class="field">
                    <label class="field__label" for="initial_lookback">Vorlaufzeit beim ersten Lauf (s)</label>
                    <input class="input" id="initial_lookback" name="initial_lookback" type="number"
                           min="60" max="2592000" value="<?= $e($val('initial_lookback', 3600)) ?>">
                </div>
            </div>

            <fieldset class="fieldset">
                <legend class="fieldset__legend">Verbindung und Filter</legend>
                <div class="row" style="gap:1.25rem; flex-wrap:wrap">
                    <label class="check">
                        <input type="checkbox" name="enabled" value="1"
                               <?= $on($edit === null ? true : $edit->enabled) ?>> Aktiv
                    </label>
                    <label class="check">
                        <input type="checkbox" name="tls" value="1"
                               <?= $on((bool) $val('tls', true)) ?>> TLS (HTTPS, Port 5986)
                    </label>
                    <label class="check">
                        <input type="checkbox" name="tls_verify" value="1"
                               <?= $on((bool) $val('tls_verify', true)) ?>> Zertifikat prüfen
                    </label>
                    <label class="check">
                        <input type="checkbox" name="include_computer_accounts" value="1"
                               <?= $on((bool) $val('include_computer_accounts', false)) ?>>
                        Maschinenkonten mitnehmen
                    </label>
                    <label class="check">
                        <input type="checkbox" name="include_system_accounts" value="1"
                               <?= $on((bool) $val('include_system_accounts', false)) ?>>
                        Systemkonten mitnehmen
                    </label>
                    <label class="check">
                        <input type="checkbox" name="include_message" value="1"
                               <?= $on((bool) $val('include_message', false)) ?>>
                        Windows-Meldungstext mitspeichern
                    </label>
                </div>
                <p class="field__hint" style="margin-top:0.6rem">
                    Maschinen- und Systemkonten stellen auf einem DC die Mehrheit des Kanals und
                    beantworten keine Frage, die jemand stellt — deshalb standardmäßig aus.
                    Der Windows-Meldungstext enthält bei 4624 rund 1,2 KB immer gleichen
                    Erklärtext; LogWarden schreibt stattdessen eine eigene Klartextzeile.
                </p>
            </fieldset>

            <fieldset class="fieldset">
                <legend class="fieldset__legend">Ereignisse</legend>
                <p class="field__hint">
                    Gefiltert wird auf dem Windows-Host, nicht hier — nicht ausgewählte Ereignisse
                    gehen gar nicht erst über das Netz.
                </p>

                <?php foreach ($catalogue as $category => $entries): ?>
                    <h3 class="fieldset__group"><?= $e(AdEventCatalog::categoryLabel($category)) ?></h3>
                    <div class="checkgrid">
                        <?php foreach ($entries as $entry): ?>
                            <label class="check" <?= $entry['note'] === null ? '' : 'title="' . $e($entry['note']) . '"' ?>>
                                <input type="checkbox" name="event_ids[]" value="<?= $e($entry['id']) ?>"
                                       <?= in_array($entry['id'], $selected, true) ? 'checked' : '' ?>>
                                <span>
                                    <code><?= $e($entry['id']) ?></code> <?= $e($entry['label']) ?>
                                    <?php if ($entry['note'] !== null): ?>
                                        <span class="badge badge--warn"><span class="badge__dot"></span>Volumen</span>
                                    <?php endif; ?>
                                </span>
                            </label>
                        <?php endforeach; ?>
                    </div>
                <?php endforeach; ?>
            </fieldset>

            <div class="row" style="justify-content:flex-end; margin-top:1rem">
                <button class="btn btn--primary" type="submit">
                    <?= $edit === null ? 'Anlegen' : 'Änderungen speichern' ?>
                </button>
            </div>
        </form>
    </div>
</section>
