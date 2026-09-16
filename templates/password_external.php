<?php
/** @var \LogWarden\Security\CurrentUser $user */

use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);
?>
<section class="card" style="max-width:34rem">
    <div class="card__head">
        <div><h2>Passwort ändern</h2></div>
    </div>
    <div class="card__body">
        <p>
            Das Konto <strong><?= $e($user->username) ?></strong> wird über das Active Directory
            angemeldet. Das Passwort liegt dort und wird auch dort geändert — an einem
            Windows-Arbeitsplatz mit <kbd>Strg</kbd> + <kbd>Alt</kbd> + <kbd>Entf</kbd> →
            „Kennwort ändern“.
        </p>
        <p class="card__hint">
            LogWarden speichert für Verzeichniskonten kein Passwort. Eine Änderung hier würde eine
            zweite, abweichende Wahrheit erzeugen.
        </p>
        <div class="row" style="margin-top:1rem">
            <a class="btn btn--primary" href="/profile">Zurück zum Profil</a>
        </div>
    </div>
</section>
