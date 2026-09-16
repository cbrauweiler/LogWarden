<?php
/**
 * @var bool  $forced
 * @var int   $minimum
 * @var array $errors
 */

use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);
?>

<?php if ($forced): ?>
    <div class="notice notice--warning" role="alert">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
        <div>
            <strong>Passwortänderung erforderlich.</strong>
            Dieses Konto wurde mit einem vergebenen Passwort angelegt. Bitte vergeben Sie ein eigenes.
        </div>
    </div>
<?php endif; ?>

<?php if ($errors !== []): ?>
    <div class="notice notice--critical" role="alert">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
        <div><ul style="margin:0; padding-left:1.1rem">
            <?php foreach ($errors as $error): ?><li><?= $e($error) ?></li><?php endforeach; ?>
        </ul></div>
    </div>
<?php endif; ?>

<section class="card" style="max-width:32rem">
    <div class="card__head">
        <div>
            <h2>Passwort ändern</h2>
            <p class="card__hint">
                Gilt nur für dieses lokale Konto. Alle anderen Sitzungen werden danach beendet.
            </p>
        </div>
    </div>

    <form method="post" action="/profile/password" autocomplete="off">
        <?= Csrf::field() ?>
        <div class="card__body">
            <div class="field">
                <label class="field__label" for="current_password">Aktuelles Passwort</label>
                <input class="input" id="current_password" name="current_password" type="password"
                       required autocomplete="current-password" autofocus>
            </div>

            <div class="field">
                <label class="field__label" for="new_password">Neues Passwort</label>
                <input class="input" id="new_password" name="new_password" type="password"
                       required autocomplete="new-password" minlength="<?= $e($minimum) ?>">
                <span class="field__hint">
                    Mindestens <?= $e($minimum) ?> Zeichen. Eine Folge aus mehreren Wörtern ist sicherer
                    und leichter zu merken als ein kurzes Passwort mit Sonderzeichen.
                </span>
            </div>

            <div class="field" style="margin-bottom:0">
                <label class="field__label" for="repeat_password">Neues Passwort wiederholen</label>
                <input class="input" id="repeat_password" name="repeat_password" type="password"
                       required autocomplete="new-password">
            </div>
        </div>

        <div class="actions">
            <button class="btn btn--primary" type="submit">Passwort ändern</button>
            <?php if (!$forced): ?>
                <a class="btn btn--ghost" href="/profile">Abbrechen</a>
            <?php endif; ?>
        </div>
    </form>
</section>
