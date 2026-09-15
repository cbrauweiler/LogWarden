<?php
/**
 * Runs every test file in tests/Unit. Usage: php tests/run.php
 */

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

foreach (glob(__DIR__ . '/Unit/*.php') ?: [] as $file) {
    require $file;
}

exit(TestRunner::run());
