<?php
/**
 * @var array $account
 * @var array $sessions
 * @var array $logins
 * @var array $permissions
 * @var array $allLabels
 * @var array $flash
 * @var array $errors
 */

use LogWarden\Security\Role;
use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);

$role     = Role::tryFromName((string) ($account['role'] ?? '')) ?? Role::Readonly;
$isLocal  = ($account['auth_provider'] ?? '') === 'local';
$initials = $user->initials();

$providerLabel = $isLocal ? 'Lokales Konto' : 'Active Directory';
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
        <div><ul style="margin:0; padding-left:1.1rem">
            <?php foreach ($errors as $error): ?><li><?= $e($error) ?></li><?php endforeach; ?>
        </ul></div>
    </div>
<?php endif; ?>

<section class="card">
    <div class="card__head">
        <div class="identity">
            <span class="identity__avatar" aria-hidden="true"><?= $e($initials) ?></span>
            <div>
                <div class="identity__name"><?= $e($account['display_name'] ?? $account['username']) ?></div>
                <div class="identity__meta">
                    <?= $e($account['username']) ?>
                    <?php if (!empty($account['email'])): ?> · <?= $e($account['email']) ?><?php endif; ?>
                </div>
            </div>
        </div>
        <?php if ($isLocal): ?>
            <a class="btn btn--ghost nowrap" href="/profile/password">Passwort ändern</a>
        <?php endif; ?>
    </div>

    <div class="card__body">
        <div class="rolecard">
            <div class="rolecard__level">Berechtigungsstufe: <?= $e($role->label()) ?></div>
            <div class="rolecard__why"><?= $e($role->description()) ?></div>
            <?php if (!empty($account['role_matched_by'])): ?>
                <div class="rolecard__why">
                    Zugewiesen über <strong><?= $e($account['role_matched_by']) ?></strong>
                    <?php if (($account['role_source'] ?? '') === 'manual'): ?>
                        — eine Änderung im Verzeichnis überschreibt das nicht.
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>

        <div class="grid-2" style="margin-top:1.25rem">
            <dl class="kv">
                <dt>Anmeldeart</dt>
                <dd><?= $e($providerLabel) ?></dd>

                <dt>Konto angelegt</dt>
                <dd><?= $e($account['created_label'] ?? '–') ?></dd>

                <dt>Letzte Anmeldung</dt>
                <dd>
                    <?= $e($account['last_login_label'] ?? '–') ?>
                    <?php if (!empty($account['last_login_ip'])): ?>
                        <br><span class="muted mono" style="font-size:0.78rem">von <?= $e($account['last_login_ip']) ?></span>
                    <?php endif; ?>
                </dd>
            </dl>

            <dl class="kv">
                <dt>Status</dt>
                <dd>
                    <?php if ($account['enabled'] ?? false): ?>
                        <span class="badge badge--success"><span class="badge__dot"></span>aktiv</span>
                    <?php else: ?>
                        <span class="badge badge--fail"><span class="badge__dot"></span>deaktiviert</span>
                    <?php endif; ?>
                </dd>

                <?php if ($isLocal): ?>
                    <dt>Passwort geändert</dt>
                    <dd>
                        <?= $e($account['password_changed_label'] ?? 'nie') ?>
                        <?php if (!empty($account['must_change_password'])): ?>
                            <br><span style="color:var(--status-critical)">Änderung erforderlich</span>
                        <?php endif; ?>
                    </dd>
                <?php endif; ?>

                <dt>Aktive Sitzungen</dt>
                <dd><?= $e(count($sessions)) ?></dd>
            </dl>
        </div>
    </div>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Was dieses Konto darf</h2>
            <p class="card__hint">Ergibt sich aus der Berechtigungsstufe — nicht einzeln einstellbar.</p>
        </div>
    </div>
    <div class="card__body">
        <ul class="permlist">
            <?php foreach ($allLabels as $permission => $label): ?>
                <?php $granted = in_array($permission, $permissions, true); ?>
                <li class="<?= $granted ? 'yes' : 'no' ?>">
                    <?php if ($granted): ?>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"
                             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 12 5 5L20 6"/></svg>
                    <?php else: ?>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                             stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>
                    <?php endif; ?>
                    <span><?= $e($label) ?></span>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
</section>

<?php if (!$isLocal): ?>
    <section class="card">
        <div class="card__head">
            <div>
                <h2>Verzeichnisgruppen</h2>
                <p class="card__hint">
                    Stand der letzten Anmeldung. Änderungen im Active Directory werden bei der
                    nächsten Anmeldung übernommen.
                </p>
            </div>
        </div>
        <div class="card__body">
            <?php if ($account['ldap_groups'] === []): ?>
                <p class="muted">Keine Gruppen übermittelt.</p>
            <?php else: ?>
                <div class="grouplist">
                    <?php foreach ($account['ldap_groups'] as $group): ?>
                        <code><?= $e($group) ?></code>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </section>
<?php endif; ?>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Aktive Sitzungen</h2>
            <p class="card__hint">Eine Sitzung hier zu beenden wirkt sofort.</p>
        </div>
    </div>
    <div class="card__body--flush">
        <table class="table">
            <thead>
                <tr>
                    <th scope="col">Adresse</th>
                    <th scope="col">Browser</th>
                    <th scope="col">Angemeldet</th>
                    <th scope="col">Zuletzt aktiv</th>
                    <th scope="col">Läuft ab</th>
                    <th scope="col"></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($sessions as $session): ?>
                <?php $current = $session['id'] === $user->sessionId; ?>
                <tr class="<?= $current ? 'session--current' : '' ?>">
                    <td class="mono">
                        <?= $e($session['ip'] ?? '–') ?>
                        <?php if ($current): ?>
                            <br><span class="badge badge--success"><span class="badge__dot"></span>diese Sitzung</span>
                        <?php endif; ?>
                    </td>
                    <td class="muted" style="max-width:24rem"><?= $e(mb_substr((string) ($session['user_agent'] ?? '–'), 0, 90)) ?></td>
                    <td class="nowrap muted"><?= $e($session['created_label']) ?></td>
                    <td class="nowrap muted"><?= $e($session['last_seen_label']) ?></td>
                    <td class="nowrap muted"><?= $e($session['expires_label']) ?></td>
                    <td>
                        <?php if (!$current): ?>
                            <form method="post" action="/profile/session/revoke">
                                <?= Csrf::field() ?>
                                <input type="hidden" name="session_id" value="<?= $e($session['id']) ?>">
                                <button class="btn btn--danger" type="submit">Beenden</button>
                            </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Letzte Anmeldeversuche</h2>
            <p class="card__hint">
                Auch die fehlgeschlagenen. Ein Versuch, den Sie nicht kennen, gehört gemeldet.
            </p>
        </div>
    </div>
    <div class="card__body--flush">
        <?php if ($logins === []): ?>
            <p class="table__empty">Keine Einträge.</p>
        <?php else: ?>
            <table class="table">
                <thead>
                    <tr>
                        <th scope="col">Zeitpunkt</th>
                        <th scope="col">Ergebnis</th>
                        <th scope="col">Verfahren</th>
                        <th scope="col">Adresse</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($logins as $attempt): ?>
                    <tr>
                        <td class="nowrap mono"><?= $e($attempt['ts_label']) ?></td>
                        <td>
                            <?php if ($attempt['success']): ?>
                                <span class="badge badge--success"><span class="badge__dot"></span>erfolgreich</span>
                            <?php else: ?>
                                <span class="badge badge--fail"><span class="badge__dot"></span>fehlgeschlagen</span>
                            <?php endif; ?>
                        </td>
                        <td class="muted"><?= $e($attempt['provider'] ?? '–') ?></td>
                        <td class="mono"><?= $e($attempt['ip'] ?? '–') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</section>
