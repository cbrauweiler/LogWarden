<?php
/**
 * Web front controller. This directory is the only one served over HTTP.
 *
 * Every route is listed with the permission it needs. A route with no entry is
 * refused rather than allowed: forgetting to add one closes the page instead of
 * opening it.
 */

declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use LogWarden\Alerting\AlertQuery;
use LogWarden\Alerting\AlertRepository;
use LogWarden\Core\Config;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Notify\ChannelFactory;
use LogWarden\Notify\Dispatcher;
use LogWarden\Search\EventQuery;
use LogWarden\Search\EventStats;
use LogWarden\Security\Authenticator;
use LogWarden\Security\CurrentUser;
use LogWarden\Security\LdapAuthProvider;
use LogWarden\Security\LocalAuthProvider;
use LogWarden\Security\Permission;
use LogWarden\Security\Role;
use LogWarden\Security\RoleResolver;
use LogWarden\Ingest\SourceRepository;
use LogWarden\Security\SecretBox;
use LogWarden\Security\SessionStore;
use LogWarden\Web\Branding;
use LogWarden\Web\Controller\AlertController;
use LogWarden\Web\Controller\AssetController;
use LogWarden\Web\Controller\AuthController;
use LogWarden\Web\Controller\BrandingController;
use LogWarden\Web\Controller\DashboardController;
use LogWarden\Web\Controller\NotificationController;
use LogWarden\Web\Controller\SourceController;
use LogWarden\Web\Controller\ProfileController;
use LogWarden\Web\Controller\SearchController;
use LogWarden\Web\Controller\UserAdminController;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\Router;
use LogWarden\Web\View;

$config = Config::load(getenv('LW_CONFIG') ?: null);
$logger = Logger::fromConfig($config, 'web');
$db     = Db::fromConfig($config, $logger);

$secureCookies = (bool) $config->get('web.behind_tls', true);
$authMode      = (string) $config->get('web.auth_mode', 'ldap');
$ldapEnabled   = in_array($authMode, ['ldap', 'both'], true);

$sessions = new SessionStore(
    $db,
    (int) $config->get('web.session_idle_ttl', 3600),
    (int) $config->get('web.session_ttl', 28800),
);

// --- Who is asking -----------------------------------------------------------

$cookie      = $_COOKIE[SessionStore::COOKIE] ?? null;
$currentUser = $sessions->resolve(is_string($cookie) ? $cookie : null);

Csrf::use($currentUser?->csrfToken);

// --- Providers ---------------------------------------------------------------

/** @var array<string, \LogWarden\Security\AuthProviderInterface> $providers */
$providers = [];

if ($ldapEnabled) {
    $serviceSecret = null;
    $serviceRef    = $config->get('ldap.service_secret_ref');

    if (is_string($serviceRef) && $serviceRef !== '') {
        try {
            $serviceSecret = SecretBox::open((string) $config->require('secret_key_file'), $db)->get($serviceRef);
        } catch (Throwable $e) {
            $logger->warning('LDAP service credential unavailable', ['error' => $e->getMessage()]);
        }
    }

    $providers['ldap'] = new LdapAuthProvider($config->section('ldap'), $logger, $serviceSecret);
}

// The local provider is always present. It is the way back in when the domain
// controller is the thing that broke.
$providers['local'] = new LocalAuthProvider($db);

$auth = new Authenticator(
    $db,
    array_values($providers),
    new RoleResolver($db),
    $sessions,
    $logger,
    Role::tryFromName((string) $config->get('web.default_role', '')),
);

// --- Shared view state -------------------------------------------------------

$branding = new Branding($db);
$view     = new View(LW_ROOT . '/templates');

$view->share('branding', $branding->load());
$view->share('assets', $branding->assetIndex());
$view->share('user', $currentUser);
$view->share('active', '');
$view->share('title', 'LogWarden');

$authController = new AuthController($auth, $sessions, $db, $view, $secureCookies, $ldapEnabled);

// --- Routing -----------------------------------------------------------------

$router = new Router();

/**
 * Permission required per route. `null` means the route is public.
 * Anything absent from this table is refused.
 *
 * @var array<string, string|null> $routePermissions
 */
$routePermissions = [
    '/login'                    => null,
    '/logout'                   => null,
    '/theme.css'                => null,
    '/branding/logo'            => null,

    '/'                         => Permission::DASHBOARD_VIEW,
    '/dashboard'                => Permission::DASHBOARD_VIEW,
    '/search'                   => Permission::SEARCH_VIEW,
    '/search/export.csv'        => Permission::EXPORT_EVENTS,
    '/event'                    => Permission::EVENT_VIEW,
    '/alerts'                   => Permission::ALERT_VIEW,
    '/alert'                    => Permission::ALERT_VIEW,
    '/alerts/ack'               => Permission::ALERT_ACK,

    '/profile'                  => Permission::PROFILE_SELF,
    '/profile/password'         => Permission::PROFILE_SELF,
    '/profile/session/revoke'   => Permission::PROFILE_SELF,

    '/settings/branding'        => Permission::BRANDING_MANAGE,
    '/settings/notifications'   => Permission::NOTIFY_MANAGE,
    '/settings/users'           => Permission::USER_MANAGE,
    '/settings/sources'         => Permission::SOURCE_MANAGE,
];

$router->get('/login',  fn (): Response => $authController->showLogin());
$router->post('/login', fn (): Response => $authController->login());
$router->post('/logout', fn (): Response => $authController->logout());
$router->get('/theme.css', fn (): Response => (new AssetController($branding))->themeCss());
$router->get('/branding/logo', fn (): Response => (new AssetController($branding))->logo());

if ($currentUser !== null) {
    $alertQuery = new AlertQuery($db);
    $dashboard  = new DashboardController(new EventStats($db), $alertQuery, $view);
    $alertsC    = new AlertController($alertQuery, new AlertRepository($db), $view, $currentUser->username);
    $searchC    = new SearchController(new EventQuery($db), $db, $view);
    $brandingC  = new BrandingController($branding, $view, $currentUser->username);
    $profileC   = new ProfileController($db, $sessions, $view, $currentUser);

    $router->get('/',                  fn (): Response => $dashboard->show());
    $router->get('/dashboard',         fn (): Response => Response::redirect('/'));
    $router->get('/search',            fn (): Response => $searchC->search());
    $router->get('/search/export.csv', fn (): Response => $searchC->export());
    $router->get('/event',             fn (): Response => $searchC->event());
    $router->get('/alerts',            fn (): Response => $alertsC->index());
    $router->post('/alerts/ack',       fn (): Response => $alertsC->acknowledge());
    $router->get('/alert',             fn (): Response => $alertsC->show());

    $router->get('/profile', fn (): Response => $profileC->show(array_filter([
        isset($_GET['passwort']) ? 'Passwort geändert. ' . (int) ($_GET['beendet'] ?? 0) . ' weitere Sitzung(en) beendet.' : null,
        isset($_GET['sitzung'])  ? 'Sitzung beendet.' : null,
    ])));
    $router->get('/profile/password',        fn (): Response => $profileC->showPasswordForm());
    $router->post('/profile/password',       fn (): Response => $profileC->changePassword());
    $router->post('/profile/session/revoke', fn (): Response => $profileC->revokeSession());

    $router->get('/settings/branding', fn (): Response => $brandingC->show(
        isset($_GET['saved']) ? ['Corporate Identity gespeichert.'] : [],
    ));
    $router->post('/settings/branding', fn (): Response => $brandingC->save());

    $userAdmin = new UserAdminController($db, $sessions, $view, $currentUser, $providers);

    $router->get('/settings/users', fn (): Response => $userAdmin->show(array_filter([
        isset($_GET['zuordnung'])           ? 'Zuordnung gespeichert.' : null,
        isset($_GET['zuordnung_geloescht']) ? 'Zuordnung gelöscht.' : null,
        isset($_GET['angelegt'])            ? 'Konto angelegt: ' . (string) $_GET['angelegt'] : null,
        isset($_GET['rolle'])               ? 'Berechtigungsstufe geändert.' : null,
        isset($_GET['konto'])               ? 'Kontostatus geändert.' : null,
        isset($_GET['passwort'])            ? 'Passwort gesetzt. Das Konto muss es bei der nächsten Anmeldung ändern.' : null,
        isset($_GET['entsperrt'])           ? 'Konto entsperrt.' : null,
        isset($_GET['geloescht'])           ? 'Konto gelöscht.' : null,
        isset($_GET['sitzungen'])           ? (int) $_GET['sitzungen'] . ' Sitzung(en) beendet.' : null,
    ])));
    $router->post('/settings/users', fn (): Response => $userAdmin->save());

    // Registered only when the secret store opens, so a missing master key
    // disables one page instead of the whole application.
    try {
        $secrets       = SecretBox::open((string) $config->require('secret_key_file'), $db);
        $brandingData  = $branding->load();
        $brandingData['base_url'] = (string) $config->get('web.base_url', '');
        $channelFactory = ChannelFactory::fromConfig($config);

        $notifications = new NotificationController(
            $db,
            $secrets,
            new Dispatcher($db, $secrets, $channelFactory, new AlertRepository($db), $logger, $brandingData),
            $channelFactory,
            $view,
            $currentUser->username,
        );

        $router->get('/settings/notifications', fn (): Response => $notifications->show(array_filter([
            isset($_GET['saved'])   ? 'Kanal gespeichert.' : null,
            isset($_GET['created']) ? 'Kanal angelegt. Jetzt die Webhook-URL hinterlegen.' : null,
            isset($_GET['deleted']) ? 'Kanal gelöscht.' : null,
            isset($_GET['webhook']) ? 'Webhook-URL verschlüsselt gespeichert.' : null,
            isset($_GET['routing']) ? 'Zuordnung gespeichert.' : null,
        ])));
        $router->post('/settings/notifications', fn (): Response => $notifications->save());

        $sourcesC = new SourceController(
            $db,
            new SourceRepository($db),
            $secrets,
            $config,
            $logger,
            $view,
            $currentUser->username,
        );

        $router->get('/settings/sources', fn (): Response => isset($_GET['edit'])
            ? $sourcesC->edit((int) $_GET['edit'])
            : $sourcesC->show());
        $router->post('/settings/sources', fn (): Response => $sourcesC->save());
    } catch (Throwable $e) {
        $secretError = $e->getMessage();
        $logger->warning('Secret store unavailable; notification settings disabled', ['error' => $secretError]);

        $notificationsUnavailable = fn (): Response => Response::html(
            $view->page('unavailable', [
                'title'   => 'Schlüsselspeicher nicht verfügbar',
                'active'  => 'notifications',
                'reason'  => $secretError,
                'remedy'  => 'Erzeugen mit bin/logwarden-keygen, danach die Berechtigungen prüfen.',
            ]),
            503,
        );

        $router->get('/settings/notifications', $notificationsUnavailable);
        $router->post('/settings/notifications', $notificationsUnavailable);

        // The source page stores the collection password in the same vault,
        // so it shares the fate of the key file rather than pretending to work.
        $router->get('/settings/sources', $notificationsUnavailable);
        $router->post('/settings/sources', $notificationsUnavailable);
    }
}

// --- Dispatch ----------------------------------------------------------------

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri    = $_SERVER['REQUEST_URI'] ?? '/';
$path   = '/' . trim((string) (parse_url($uri, PHP_URL_PATH) ?: '/'), '/');
$path   = $path === '/' ? '/' : rtrim($path, '/');

try {
    $response = guard($path, $method, $uri, $currentUser, $routePermissions, $authController)
        ?? $router->dispatch($method, $uri);
} catch (Throwable $e) {
    $logger->exception($e, 'Request failed');

    $response = Response::html(
        '<!doctype html><meta charset="utf-8"><title>Fehler</title>'
        . '<body style="font:14px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem">'
        . '<h1>Interner Fehler</h1><p>Details stehen im Server-Log.</p></body>',
        500,
    );
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header(
    "Content-Security-Policy: default-src 'self'; img-src 'self' data:; "
    . "style-src 'self' 'unsafe-inline'; script-src 'self'; "
    . "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
);

if ($secureCookies) {
    header('Strict-Transport-Security: max-age=31536000');
}

$response->send($method === 'HEAD');

/**
 * Returns a response when the request must not reach its handler, and null
 * when it may proceed.
 *
 * @param array<string, string|null> $permissions
 */
function guard(
    string $path,
    string $method,
    string $uri,
    ?CurrentUser $user,
    array $permissions,
    AuthController $authController,
): ?Response {
    // Static files under /assets are served by the web server; anything else
    // that is not in the table is unknown, and unknown means refused.
    if (!array_key_exists($path, $permissions)) {
        return Response::notFound();
    }

    $required = $permissions[$path];

    if ($required === null) {
        return null;
    }

    if ($user === null) {
        if ($method !== 'GET') {
            // A POST from an expired session must not be silently replayed
            // after logging back in.
            return Response::redirect('/login?abgelaufen=1');
        }

        return Response::redirect('/login?abgelaufen=1&next=' . rawurlencode($uri));
    }

    // A pending forced password change blocks everything except changing it
    // and logging out — otherwise the requirement is a suggestion.
    if ($user->mustChangePassword
        && !str_starts_with($path, '/profile/password')
        && $path !== '/logout'
    ) {
        return Response::redirect('/profile/password?forced=1');
    }

    if (!$user->can($required)) {
        return Response::html(
            '<!doctype html><meta charset="utf-8"><title>Kein Zugriff</title>'
            . '<body style="font:14px system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem">'
            . '<h1>Kein Zugriff</h1>'
            . '<p>Die Berechtigungsstufe dieses Kontos deckt diese Seite nicht ab.</p>'
            . '<p><a href="/">Zum Dashboard</a> · <a href="/profile">Eigene Berechtigungen ansehen</a></p>'
            . '</body>',
            403,
        );
    }

    return null;
}
