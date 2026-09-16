<?php
/**
 * Web front controller. This directory is the only one served over HTTP.
 */

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use LogWarden\Core\Config;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Alerting\AlertQuery;
use LogWarden\Alerting\AlertRepository;
use LogWarden\Notify\ChannelFactory;
use LogWarden\Notify\Dispatcher;
use LogWarden\Search\EventQuery;
use LogWarden\Search\EventStats;
use LogWarden\Security\SecretBox;
use LogWarden\Web\Branding;
use LogWarden\Web\Controller\AlertController;
use LogWarden\Web\Controller\AssetController;
use LogWarden\Web\Controller\BrandingController;
use LogWarden\Web\Controller\DashboardController;
use LogWarden\Web\Controller\NotificationController;
use LogWarden\Web\Controller\SearchController;
use LogWarden\Web\Response;
use LogWarden\Web\Router;
use LogWarden\Web\View;

$config = Config::load(getenv('LW_CONFIG') ?: null);
$logger = Logger::fromConfig($config, 'web');

$authMode = (string) $config->get('web.auth_mode', 'ldap');

/*
 * Authentication is the last milestone on the roadmap (LDAP bind against the
 * domain controller, with a local break-glass account). Until it exists the
 * frontend only runs with auth_mode = 'none', and refuses otherwise.
 *
 * Failing closed is the point: nobody should be able to bring a SIEM online
 * that serves every security event in the estate to anyone who can reach
 * port 443.
 */
if ($authMode !== 'none') {
    header('Content-Type: text/html; charset=utf-8');
    http_response_code(503);
    echo '<!doctype html><meta charset="utf-8"><title>LogWarden</title>'
        . '<body style="font:14px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem">'
        . '<h1>Authentifizierung noch nicht implementiert</h1>'
        . '<p>Das Web-Frontend ist so konfiguriert, dass es eine Anmeldung verlangt '
        . '(<code>web.auth_mode = ' . htmlspecialchars($authMode, ENT_QUOTES) . '</code>), '
        . 'der LDAP-Login-Layer ist aber noch nicht gebaut.</p>'
        . '<p>Zum lokalen Ausprobieren <code>web.auth_mode</code> auf <code>none</code> setzen '
        . '<strong>und den Listener ausschließlich an 127.0.0.1 binden</strong>.</p>'
        . '</body>';
    exit;
}

session_start([
    'name'            => 'lw_session',
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure'   => (bool) $config->get('web.behind_tls', true),
    'use_strict_mode' => true,
]);

$db       = Db::fromConfig($config, $logger);
$branding = new Branding($db);
$view     = new View(LW_ROOT . '/templates');

// Development identity; replaced by the session user once LDAP auth lands.
$actor = 'dev@localhost';
$secretError = null;

$view->share('branding', $branding->load());
$view->share('assets', $branding->assetIndex());
$view->share('user', ['username' => $actor, 'role' => 'admin']);
$view->share('devMode', true);
$view->share('active', '');
$view->share('title', 'LogWarden');

$alertQuery = new AlertQuery($db);

$dashboard = new DashboardController(new EventStats($db), $alertQuery, $view);
$alertsC   = new AlertController($alertQuery, new AlertRepository($db), $view, $actor);
$searchC   = new SearchController(new EventQuery($db), $db, $view);
$brandingC = new BrandingController($branding, $view, $actor);
$assets    = new AssetController($branding);

/*
 * The secret store needs the master key. A missing or unreadable key must not
 * take the whole UI down — everything except the notification settings works
 * without it, so the failure is confined to the page that needs it.
 */
$notifications = null;

try {
    $secrets = SecretBox::open((string) $config->require('secret_key_file'), $db);

    $brandingData = $branding->load();
    $brandingData['base_url'] = (string) $config->get('web.base_url', '');

    $channelFactory = ChannelFactory::fromConfig($config);

    $notifications = new NotificationController(
        $db,
        $secrets,
        new Dispatcher(
            $db,
            $secrets,
            $channelFactory,
            new LogWarden\Alerting\AlertRepository($db),
            $logger,
            $brandingData,
        ),
        $channelFactory,
        $view,
        $actor,
    );
} catch (Throwable $e) {
    $logger->warning('Secret store unavailable; notification settings disabled', [
        'error' => $e->getMessage(),
    ]);
    $secretError = $e->getMessage();
}

$router = new Router();
$router->get('/',                   fn (): Response => $dashboard->show());
$router->get('/dashboard',          fn (): Response => Response::redirect('/'));
$router->get('/settings/branding',  fn (): Response => $brandingC->show(
    isset($_GET['saved']) ? ['Corporate Identity gespeichert.'] : [],
));
$router->post('/settings/branding', fn (): Response => $brandingC->save());
$router->get('/search',             fn (): Response => $searchC->search());
$router->get('/search/export.csv',  fn (): Response => $searchC->export());
$router->get('/event',              fn (): Response => $searchC->event());
$router->get('/alerts',             fn (): Response => $alertsC->index());
$router->post('/alerts/ack',        fn (): Response => $alertsC->acknowledge());
$router->get('/alert',              fn (): Response => $alertsC->show());
$router->get('/settings/notifications', function () use ($notifications, $secretError): Response {
    if ($notifications === null) {
        return Response::html(
            '<!doctype html><meta charset="utf-8"><title>Schlüsselspeicher</title>'
            . '<body style="font:14px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem">'
            . '<h1>Schlüsselspeicher nicht verfügbar</h1><p>'
            . htmlspecialchars($secretError ?? 'Unbekannter Fehler', ENT_QUOTES)
            . '</p><p>Erzeugen mit <code>bin/logwarden-keygen</code>.</p></body>',
            503,
        );
    }

    $flash = [];
    if (isset($_GET['saved']))   { $flash[] = 'Kanal gespeichert.'; }
    if (isset($_GET['created'])) { $flash[] = 'Kanal angelegt. Jetzt die Webhook-URL hinterlegen.'; }
    if (isset($_GET['deleted'])) { $flash[] = 'Kanal gelöscht.'; }
    if (isset($_GET['webhook'])) { $flash[] = 'Webhook-URL verschlüsselt gespeichert.'; }
    if (isset($_GET['routing'])) { $flash[] = 'Zuordnung gespeichert.'; }

    return $notifications->show($flash);
});
$router->post('/settings/notifications', fn (): Response => $notifications === null
    ? Response::redirect('/settings/notifications')
    : $notifications->save());
$router->get('/theme.css',   fn (): Response => $assets->themeCss());
$router->get('/branding/logo',      fn (): Response => $assets->logo());

try {
    $response = $router->dispatch(
        $_SERVER['REQUEST_METHOD'] ?? 'GET',
        $_SERVER['REQUEST_URI'] ?? '/',
    );
} catch (Throwable $e) {
    $logger->exception($e, 'Request failed');

    $response = Response::html(
        '<!doctype html><meta charset="utf-8"><title>Fehler</title>'
        . '<body style="font:14px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem">'
        . '<h1>Interner Fehler</h1><p>Details stehen im Server-Log.</p></body>',
        500,
    );
}

// Baseline headers. The nginx example sets these too; a direct php -S run and
// a misconfigured proxy should not silently lose them.
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');

// Inline styles are used by the live branding preview; scripts are file-only so
// the script-src stays free of 'unsafe-inline'.
header(
    "Content-Security-Policy: default-src 'self'; img-src 'self' data:; "
    . "style-src 'self' 'unsafe-inline'; script-src 'self'; "
    . "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
);

$response->send(($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD');
