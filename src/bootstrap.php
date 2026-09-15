<?php
/**
 * Common bootstrap for every entrypoint (CLI daemons and the web front controller).
 *
 * Uses Composer's autoloader when the project was installed with `composer install`,
 * and otherwise falls back to a plain PSR-4 autoloader so LogWarden stays deployable
 * by copying the directory onto a server.
 */

declare(strict_types=1);

define('LW_ROOT', dirname(__DIR__));

if (is_file(LW_ROOT . '/vendor/autoload.php')) {
    require LW_ROOT . '/vendor/autoload.php';
} else {
    spl_autoload_register(static function (string $class): void {
        if (!str_starts_with($class, 'LogWarden\\')) {
            return;
        }
        $path = LW_ROOT . '/src/' . str_replace('\\', '/', substr($class, 10)) . '.php';
        if (is_file($path)) {
            require $path;
        }
    });
}

date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');
