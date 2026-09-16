<?php
/**
 * @var array $users
 * @var array $mappings
 * @var array $roles
 * @var array $directory
 * @var string $suggestion
 * @var int   $minimum
 * @var array $flash
 * @var array $errors
 */

use LogWarden\Security\Role;
use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);

$roleBadge = static function (string $value) use ($e): string {
    $role = Role::tryFromName($value);
    $cls  = match ($role) {
        Role::Admin   => 'fail',
        Role::Analyst => 'success',
        default       => 'info',
    };

    return '<span class="badge badge--' . $cls . '"><span class="badge__dot"></span>'
        . $e($role?->label() ?? $value) . '</span>';
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
        <div><ul style="margin:0; padding-left:1.1rem">
            <?php foreach ($errors as $error): ?><li><?= $e($error) ?></li><?php endforeach; ?>
        </ul></div>
    </div>
<?php endif; ?>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Berechtigungszuordnung</h2>
            <p class="card__hint">
                Welche AD-Gruppe oder welches Konto welche Berechtigungsstufe erhält. Ohne
                passenden Eintrag wird eine Anmeldung abgelehnt — auch bei korrektem Passwort.
            </p>
        </div>
        <div class="row">
            <?php foreach ($directory as $name => $health): ?>
                <span class="badge badge--<?= $health['ok'] ? 'success' : 'fail' ?>"
                      title="<?= $e($health['message']) ?>">
                    <span class="badge__dot"></span><?= $e($name) ?>: <?= $e($health['message']) ?>
                </span>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="card__body--flush">
        <?php if ($mappings === []): ?>
            <p class="table__empty">
                Noch keine Zuordnung. Ohne mindestens einen Eintrag kann sich kein Verzeichniskonto anmelden.
            </p>
        <?php else: ?>
            <table class="table">
                <thead>
                    <tr>
                        <th scope="col">Typ</th>
                        <th scope="col">Gruppe oder Konto</th>
                        <th scope="col">Berechtigungsstufe</th>
                        <th scope="col" class="num">Priorität</th>
                        <th scope="col" class="num">Konten</th>
                        <th scope="col">Notiz</th>
                        <th scope="col">Status</th>
                        <th scope="col"></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($mappings as $mapping): ?>
                    <tr>
                        <td>
                            <span class="badge badge--source">
                                <?= $mapping['subject_type'] === 'user' ? 'Konto' : 'Gruppe' ?>
                            </span>
                        </td>
                        <td class="mono" style="word-break:break-all"><?= $e($mapping['subject']) ?></td>
                        <td><?= $roleBadge((string) $mapping['role']) ?></td>
                        <td class="num"><?= $e($mapping['priority']) ?></td>
                        <td class="num"><?= $e($mapping['matched_users']) ?></td>
                        <td class="muted"><?= $e($mapping['description'] ?? '') ?></td>
                        <td>
                            <?php if ($mapping['enabled']): ?>
                                <span class="badge badge--success"><span class="badge__dot"></span>aktiv</span>
                            <?php else: ?>
                                <span class="badge badge--info"><span class="badge__dot"></span>inaktiv</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div class="row" style="gap:0.35rem">
                                <form method="post" action="/settings/users">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="toggle_mapping">
                                    <input type="hidden" name="mapping_id" value="<?= $e($mapping['id']) ?>">
                                    <button class="btn btn--ghost" type="submit">
                                        <?= $mapping['enabled'] ? 'Deaktivieren' : 'Aktivieren' ?>
                                    </button>
                                </form>
                                <form method="post" action="/settings/users"
                                      onsubmit="return confirm('Zuordnung für <?= $e($mapping['subject']) ?> löschen?')">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="delete_mapping">
                                    <input type="hidden" name="mapping_id" value="<?= $e($mapping['id']) ?>">
                                    <button class="btn btn--danger" type="submit">Löschen</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <form method="post" action="/settings/users">
        <?= Csrf::field() ?>
        <input type="hidden" name="action" value="add_mapping">
        <div class="card__body">
            <h3 style="margin-bottom:0.75rem">Zuordnung hinzufügen</h3>
            <div class="searchbar__grid">
                <div class="field">
                    <label class="field__label" for="subject_type">Typ</label>
                    <select class="select" id="subject_type" name="subject_type">
                        <option value="group">AD-Gruppe</option>
                        <option value="user">Einzelnes Konto</option>
                    </select>
                </div>
                <div class="field" style="grid-column: span 2">
                    <label class="field__label" for="subject">Gruppe oder Kontoname</label>
                    <input class="input" id="subject" name="subject" required maxlength="500"
                           placeholder="SOC-Admins oder CN=SOC-Admins,OU=Groups,DC=corp,DC=local">
                    <span class="field__hint">
                        Kurzer Gruppenname oder vollständiger DN — beides wird erkannt. Bei „Einzelnes
                        Konto“ der Anmeldename ohne Domäne.
                    </span>
                </div>
                <div class="field">
                    <label class="field__label" for="map_role">Berechtigungsstufe</label>
                    <select class="select" id="map_role" name="role">
                        <?php foreach ($roles as $role): ?>
                            <option value="<?= $e($role->value) ?>"><?= $e($role->label()) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="field">
                    <label class="field__label" for="priority">Priorität</label>
                    <input class="input" id="priority" name="priority" type="number" value="100" min="0" max="999">
                    <span class="field__hint">Höher gewinnt bei mehreren Treffern.</span>
                </div>
                <div class="field">
                    <label class="field__label" for="description">Notiz</label>
                    <input class="input" id="description" name="description" maxlength="200" placeholder="optional">
                </div>
            </div>
            <div class="row" style="margin-top:0.9rem">
                <button class="btn btn--primary" type="submit">Zuordnung hinzufügen</button>
            </div>
        </div>
    </form>
</section>

<section class="card">
    <div class="card__head">
        <div>
            <h2>Konten</h2>
            <p class="card__hint">
                Verzeichniskonten entstehen bei der ersten erfolgreichen Anmeldung. Lokale Konten
                werden hier angelegt.
            </p>
        </div>
    </div>

    <div class="card__body--flush">
        <table class="table">
            <thead>
                <tr>
                    <th scope="col">Konto</th>
                    <th scope="col">Anmeldeart</th>
                    <th scope="col">Stufe</th>
                    <th scope="col">Zugewiesen über</th>
                    <th scope="col">Letzte Anmeldung</th>
                    <th scope="col">Status</th>
                    <th scope="col">Aktionen</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $account): ?>
                <tr>
                    <td>
                        <strong><?= $e($account['username']) ?></strong>
                        <?php if (!empty($account['display_name'])): ?>
                            <br><span class="muted" style="font-size:0.8rem"><?= $e($account['display_name']) ?></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="badge badge--source">
                            <?= $account['auth_provider'] === 'local' ? 'lokal' : 'AD' ?>
                        </span>
                    </td>
                    <td>
                        <form method="post" action="/settings/users" class="row" style="gap:0.35rem">
                            <?= Csrf::field() ?>
                            <input type="hidden" name="action" value="set_role">
                            <input type="hidden" name="user_id" value="<?= $e($account['id']) ?>">
                            <label class="visually-hidden" for="role_<?= $e($account['id']) ?>">Stufe</label>
                            <select class="select" id="role_<?= $e($account['id']) ?>" name="role"
                                    style="width:auto; min-width:9rem" onchange="this.form.submit()">
                                <?php foreach ($roles as $role): ?>
                                    <option value="<?= $e($role->value) ?>"
                                        <?= $account['role'] === $role->value ? 'selected' : '' ?>>
                                        <?= $e($role->label()) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </form>
                    </td>
                    <td class="muted" style="font-size:0.8rem"><?= $e($account['role_matched_by'] ?? '–') ?></td>
                    <td class="nowrap muted"><?= $e($account['last_login_label'] ?? 'nie') ?></td>
                    <td>
                        <?php if (!$account['enabled']): ?>
                            <span class="badge badge--fail"><span class="badge__dot"></span>deaktiviert</span>
                        <?php elseif ($account['locked']): ?>
                            <span class="badge badge--fail"><span class="badge__dot"></span>gesperrt</span>
                        <?php else: ?>
                            <span class="badge badge--success"><span class="badge__dot"></span>aktiv</span>
                        <?php endif; ?>
                        <?php if ((int) $account['sessions'] > 0): ?>
                            <br><span class="muted" style="font-size:0.78rem"><?= $e($account['sessions']) ?> Sitzung(en)</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <div class="row" style="gap:0.35rem">
                            <form method="post" action="/settings/users">
                                <?= Csrf::field() ?>
                                <input type="hidden" name="action" value="toggle_enabled">
                                <input type="hidden" name="user_id" value="<?= $e($account['id']) ?>">
                                <button class="btn btn--ghost" type="submit">
                                    <?= $account['enabled'] ? 'Deaktivieren' : 'Aktivieren' ?>
                                </button>
                            </form>
                            <?php if ($account['locked'] || (int) $account['failed_logins'] > 0): ?>
                                <form method="post" action="/settings/users">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="reset_lockout">
                                    <input type="hidden" name="user_id" value="<?= $e($account['id']) ?>">
                                    <button class="btn btn--ghost" type="submit">Entsperren</button>
                                </form>
                            <?php endif; ?>
                            <?php if ((int) $account['sessions'] > 0): ?>
                                <form method="post" action="/settings/users">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="action" value="revoke_sessions">
                                    <input type="hidden" name="user_id" value="<?= $e($account['id']) ?>">
                                    <button class="btn btn--ghost" type="submit">Abmelden</button>
                                </form>
                            <?php endif; ?>
                            <form method="post" action="/settings/users"
                                  onsubmit="return confirm('Konto <?= $e($account['username']) ?> löschen?')">
                                <?= Csrf::field() ?>
                                <input type="hidden" name="action" value="delete_user">
                                <input type="hidden" name="user_id" value="<?= $e($account['id']) ?>">
                                <button class="btn btn--danger" type="submit">Löschen</button>
                            </form>
                        </div>

                        <?php if ($account['auth_provider'] === 'local'): ?>
                            <form method="post" action="/settings/users" class="row"
                                  style="gap:0.35rem; margin-top:0.4rem" autocomplete="off">
                                <?= Csrf::field() ?>
                                <input type="hidden" name="action" value="reset_password">
                                <input type="hidden" name="user_id" value="<?= $e($account['id']) ?>">
                                <label class="visually-hidden" for="pw_<?= $e($account['id']) ?>">Neues Passwort</label>
                                <input class="input" id="pw_<?= $e($account['id']) ?>" name="password"
                                       type="password" autocomplete="new-password"
                                       placeholder="Neues Passwort setzen" style="width:14rem">
                                <button class="btn btn--ghost" type="submit">Setzen</button>
                            </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <form method="post" action="/settings/users" autocomplete="off">
        <?= Csrf::field() ?>
        <input type="hidden" name="action" value="create_local">
        <div class="card__body">
            <h3 style="margin-bottom:0.35rem">Lokales Konto anlegen</h3>
            <p class="card__hint" style="margin-bottom:0.75rem">
                Für den Notfallzugang, wenn der Domain Controller nicht erreichbar ist — also für
                genau die Störung, die man mit diesem System untersuchen würde.
            </p>
            <div class="searchbar__grid">
                <div class="field">
                    <label class="field__label" for="new_username">Benutzername</label>
                    <input class="input" id="new_username" name="username" required
                           pattern="[a-z0-9._-]{3,64}" placeholder="notfall">
                </div>
                <div class="field">
                    <label class="field__label" for="new_display">Anzeigename</label>
                    <input class="input" id="new_display" name="display_name" maxlength="120" placeholder="optional">
                </div>
                <div class="field">
                    <label class="field__label" for="new_email">E-Mail</label>
                    <input class="input" id="new_email" name="email" type="email" placeholder="optional">
                </div>
                <div class="field">
                    <label class="field__label" for="new_role">Berechtigungsstufe</label>
                    <select class="select" id="new_role" name="role">
                        <?php foreach ($roles as $role): ?>
                            <option value="<?= $e($role->value) ?>"><?= $e($role->label()) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="field" style="grid-column: span 2">
                    <label class="field__label" for="new_password">Startpasswort</label>
                    <input class="input" id="new_password" name="password" type="password"
                           required minlength="<?= $e($minimum) ?>" autocomplete="new-password"
                           value="<?= $e($suggestion) ?>">
                    <span class="field__hint">
                        Vorschlag bereits eingetragen. Das Konto muss das Passwort bei der ersten
                        Anmeldung ändern.
                    </span>
                </div>
            </div>
            <div class="row" style="margin-top:0.9rem">
                <button class="btn btn--primary" type="submit">Konto anlegen</button>
            </div>
        </div>
    </form>
</section>
