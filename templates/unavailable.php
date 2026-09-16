<?php
/**
 * @var string $reason
 * @var string $remedy
 */

use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);
?>
<section class="card" style="max-width:36rem">
    <div class="card__head"><div><h2>Diese Seite ist derzeit nicht verfügbar</h2></div></div>
    <div class="card__body">
        <p><?= $e($reason) ?></p>
        <p class="card__hint"><?= $e($remedy) ?></p>
        <div class="row" style="margin-top:1rem"><a class="btn btn--primary" href="/">Zum Dashboard</a></div>
    </div>
</section>
