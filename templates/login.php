<?php
/**
 * Standalone page: no navigation, because there is nothing to navigate to yet.
 *
 * @var array       $branding
 * @var array       $assets
 * @var string      $csrf
 * @var string|null $message
 * @var bool        $isError
 * @var string      $username
 * @var bool        $ldapEnabled
 * @var string      $next
 * @var bool        $loggedOut
 * @var bool        $sessionEnded
 */

use LogWarden\Web\View;

$e        = static fn (mixed $v): string => View::e($v);
$product  = (string) ($branding['product_name'] ?? 'LogWarden');
$revision = (int) ($branding['revision'] ?? 1);
$theme    = (string) ($branding['default_theme'] ?? 'auto');
?>
<!doctype html>
<html lang="de"<?= $theme !== 'auto' ? ' data-theme="' . $e($theme) . '"' : '' ?>>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Anmeldung · <?= $e($product) ?></title>
    <link rel="stylesheet" href="/assets/css/app.css?v=<?= $e($revision) ?>">
    <link rel="stylesheet" href="/theme.css?v=<?= $e($revision) ?>">
    <?php if (isset($assets['favicon'])): ?>
        <link rel="icon" href="/branding/logo?slot=favicon&amp;v=<?= $e($revision) ?>">
    <?php endif; ?>
    <meta name="color-scheme" content="light dark">
    <meta name="robots" content="noindex, nofollow">
</head>
<body>
<main class="loginpage">
    <div class="loginbox">
        <div class="loginbox__brand">
            <?php if (isset($assets['logo_dark'])): ?>
                <img src="/branding/logo?slot=logo_dark&amp;v=<?= $e($revision) ?>" alt="<?= $e($product) ?>">
            <?php else: ?>
                <span class="loginbox__mark" aria-hidden="true"><?= $e(mb_strtoupper(mb_substr($product, 0, 2))) ?></span>
                <span>
                    <span class="loginbox__name"><?= $e($product) ?></span>
                    <?php if (!empty($branding['org_name'])): ?>
                        <br><span class="loginbox__org"><?= $e($branding['org_name']) ?></span>
                    <?php endif; ?>
                </span>
            <?php endif; ?>
        </div>

        <?php if ($loggedOut): ?>
            <div class="notice notice--ok" role="status" style="margin-bottom:1rem">
                <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 12 5 5L20 6"/></svg>
                <div>Sie wurden abgemeldet.</div>
            </div>
        <?php elseif ($sessionEnded): ?>
            <div class="notice notice--warning" role="status" style="margin-bottom:1rem">
                <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
                     stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
                <div>Die Sitzung ist abgelaufen. Bitte erneut anmelden.</div>
            </div>
        <?php endif; ?>

        <?php if ($message !== null): ?>
            <div class="notice notice--<?= $isError ? 'critical' : 'ok' ?>" role="alert" style="margin-bottom:1rem">
                <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
                     stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
                <div><?= $e($message) ?></div>
            </div>
        <?php endif; ?>

        <section class="card">
            <form method="post" action="/login" autocomplete="on">
                <input type="hidden" name="_csrf" value="<?= $e($csrf) ?>">
                <input type="hidden" name="next" value="<?= $e($next) ?>">

                <div class="card__body">
                    <?php if (!empty($branding['login_subtitle'])): ?>
                        <p class="card__hint" style="margin-bottom:1rem"><?= $e($branding['login_subtitle']) ?></p>
                    <?php endif; ?>

                    <div class="field">
                        <label class="field__label" for="username">Benutzername</label>
                        <input class="input" id="username" name="username" required autofocus
                               autocomplete="username" autocapitalize="none" spellcheck="false"
                               value="<?= $e($username) ?>">
                    </div>

                    <div class="field" style="margin-bottom:0.5rem">
                        <label class="field__label" for="password">Passwort</label>
                        <input class="input" id="password" name="password" type="password" required
                               autocomplete="current-password">
                    </div>

                    <button class="btn btn--primary" type="submit" style="width:100%; justify-content:center">
                        Anmelden
                    </button>

                    <p class="loginbox__hint">
                        <?= $ldapEnabled
                            ? 'Anmeldung mit dem Windows-Konto. Lokale Konten funktionieren ebenfalls.'
                            : 'Anmeldung mit einem lokalen Konto.' ?>
                    </p>
                </div>
            </form>
        </section>

        <p class="loginbox__foot">
            <?= $e($branding['footer_text'] ?? '') ?: $e($product) ?>
        </p>
    </div>
</main>
</body>
</html>
