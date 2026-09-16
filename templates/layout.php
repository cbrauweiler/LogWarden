<?php
/**
 * @var string $content
 * @var string $title
 * @var string $active
 * @var array  $branding
 * @var array  $user
 */

use LogWarden\Web\View;

$e        = static fn (mixed $v): string => View::e($v);
$revision = (int) ($branding['revision'] ?? 1);
$theme    = (string) ($branding['default_theme'] ?? 'auto');
$product  = (string) ($branding['product_name'] ?? 'LogWarden');
$assets   = $assets ?? [];   // shared globally; defaulted for safety

use LogWarden\Security\Permission;

// Only what this account may actually open. A link to a page that answers 403
// is worse than no link.
$nav = array_values(array_filter([
    ['id' => 'dashboard', 'href' => '/',       'label' => 'Dashboard', 'icon' => 'grid',   'need' => Permission::DASHBOARD_VIEW],
    ['id' => 'search',    'href' => '/search', 'label' => 'Suche',     'icon' => 'search', 'need' => Permission::SEARCH_VIEW],
    ['id' => 'alerts',    'href' => '/alerts', 'label' => 'Alerts',    'icon' => 'bell',   'need' => Permission::ALERT_VIEW],
], static fn (array $item): bool => $user !== null && $user->can($item['need'])));

$adminNav = array_values(array_filter([
    ['id' => 'notifications', 'href' => '/settings/notifications', 'label' => 'Benachrichtigungen', 'icon' => 'send',    'need' => Permission::NOTIFY_MANAGE],
    ['id' => 'branding',      'href' => '/settings/branding',      'label' => 'Corporate Identity', 'icon' => 'palette', 'need' => Permission::BRANDING_MANAGE],
    ['id' => 'users',         'href' => '/settings/users',         'label' => 'Benutzer',           'icon' => 'users',   'need' => Permission::USER_MANAGE],
], static fn (array $item): bool => $user !== null && $user->can($item['need'])));

$icons = [
    'grid'    => '<path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/>',
    'search'  => '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    'bell'    => '<path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0"/>',
    'plug'    => '<path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0zM12 17v5"/>',
    'shield'  => '<path d="M12 2 4 6v6c0 5 3.4 8.9 8 10 4.6-1.1 8-5 8-10V6z"/>',
    'send'    => '<path d="m21 3-9.5 9.5M21 3l-6.5 18-4-8-8-4z"/>',
    'users'   => '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9"/><path d="M16 3.1a4 4 0 0 1 0 7.8"/>',
    'user'    => '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    'palette' => '<circle cx="12" cy="12" r="9"/><circle cx="8.5" cy="10" r="1.2"/><circle cx="12" cy="7.5" r="1.2"/><circle cx="15.5" cy="10" r="1.2"/>',
];

$renderLink = static function (array $item) use ($active, $e, $icons): string {
    return sprintf(
        '<a class="navlink" href="%s"%s><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        . 'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">%s</svg>%s</a>',
        $e($item['href']),
        $active === $item['id'] ? ' aria-current="page"' : '',
        $icons[$item['icon']] ?? '',
        $e($item['label']),
    );
};
?>
<!doctype html>
<html lang="de"<?= $theme !== 'auto' ? ' data-theme="' . $e($theme) . '"' : '' ?>>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $e($title) ?> · <?= $e($product) ?></title>
    <link rel="stylesheet" href="/assets/css/app.css?v=<?= $e($revision) ?>">
    <!-- Generated from the branding settings; loaded after app.css so it can
         override the brand tokens. -->
    <link rel="stylesheet" href="/theme.css?v=<?= $e($revision) ?>">
    <?php if (isset($assets['favicon'])): ?>
        <link rel="icon" href="/branding/logo?slot=favicon&amp;v=<?= $e($revision) ?>">
    <?php endif; ?>
    <meta name="color-scheme" content="light dark">
</head>
<body>
<div class="app">
    <aside class="sidebar">
        <div class="sidebar__brand">
            <?php if (isset($assets['logo_light'])): ?>
                <img class="sidebar__logo" src="/branding/logo?slot=logo_light&amp;v=<?= $e($revision) ?>"
                     alt="<?= $e($product) ?>">
            <?php else: ?>
                <span class="sidebar__mark" aria-hidden="true"><?= $e(mb_strtoupper(mb_substr($product, 0, 2))) ?></span>
                <span>
                    <span class="sidebar__name"><?= $e($product) ?></span>
                    <?php if (!empty($branding['org_name'])): ?>
                        <br><span class="sidebar__org"><?= $e($branding['org_name']) ?></span>
                    <?php endif; ?>
                </span>
            <?php endif; ?>
        </div>

        <nav class="sidebar__nav" aria-label="Hauptnavigation">
            <?php foreach ($nav as $item) { echo $renderLink($item); } ?>
            <div class="sidebar__section">Verwaltung</div>
            <?php foreach ($adminNav as $item) { echo $renderLink($item); } ?>
        </nav>

        <div class="sidebar__nav" style="padding-top:0">
            <?= $renderLink(['id' => 'profile', 'href' => '/profile', 'label' => 'Mein Profil', 'icon' => 'user']) ?>
        </div>

        <div class="sidebar__foot">
            <?= $e($branding['footer_text'] ?? '') ?>
        </div>
    </aside>

    <div class="main">
        <header class="topbar">
            <h1><?= $e($title) ?></h1>
            <div class="row">
                <?php if (!empty($branding['allow_user_theme'])): ?>
                    <button class="btn btn--ghost" type="button" data-theme-toggle
                            aria-label="Hell/Dunkel umschalten" title="Hell/Dunkel umschalten">
                        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                             stroke-width="1.7" stroke-linecap="round" aria-hidden="true">
                            <circle cx="12" cy="12" r="4"/>
                            <path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/>
                        </svg>
                    </button>
                <?php endif; ?>
                <?php if ($user !== null): ?>
                    <a class="topbar__meta" href="/profile" style="color:inherit; text-decoration:none">
                        <?= $e($user->name()) ?> · <?= $e($user->role->label()) ?>
                    </a>
                    <form method="post" action="/logout" style="display:inline">
                        <?= \LogWarden\Web\Csrf::field() ?>
                        <button class="btn btn--ghost" type="submit" title="Abmelden">Abmelden</button>
                    </form>
                <?php endif; ?>
            </div>
        </header>

        <main class="content stack">
            <?= $content ?>
        </main>
    </div>
</div>
<script src="/assets/js/app.js?v=<?= $e($revision) ?>" defer></script>
</body>
</html>
