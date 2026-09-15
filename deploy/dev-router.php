<?php
/**
 * Router for PHP's built-in server (development only).
 *
 * `php -S` serves existing files directly and 404s everything else; this hands
 * unknown paths to the front controller the way nginx's try_files does.
 * Not used in production — see deploy/nginx/logwarden.conf.
 */

declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$file = __DIR__ . '/../public' . $path;

if ($path !== '/' && is_file($file)) {
    return false;   // let the built-in server serve the static file
}

require __DIR__ . '/../public/index.php';
