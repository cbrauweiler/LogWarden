<?php
/**
 * @var string $ts
 * @var int    $id
 */

use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);
?>
<section class="card">
    <div class="card__head">
        <div>
            <h2>Event nicht gefunden</h2>
        </div>
    </div>
    <div class="card__body">
        <p>
            Zu <code><?= $e($ts) ?></code> / <code><?= $e($id) ?></code> existiert kein Event.
        </p>
        <p class="card__hint">
            Am wahrscheinlichsten ist es aus der Aufbewahrung gelaufen. Verknüpfte Alerts bleiben
            trotzdem lesbar — die Beweislage wird beim Auslösen als Momentaufnahme gespeichert.
        </p>
        <div class="row" style="margin-top:1rem">
            <a class="btn btn--primary" href="/search">Zur Suche</a>
            <a class="btn btn--ghost" href="/alerts">Zu den Alerts</a>
        </div>
    </div>
</section>
