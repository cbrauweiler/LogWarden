<?php

declare(strict_types=1);

use LogWarden\Core\Db;

/**
 * These exercise a live PostgreSQL. They are skipped unless LW_TEST_DSN names
 * a throwaway database, e.g.
 *   LW_TEST_DSN='host=/var/run/postgresql;dbname=logwarden_test;user=lw;password=x'
 */
function testDbSettings(): ?array
{
    $dsn = getenv('LW_TEST_DSN');
    if ($dsn === false || $dsn === '') {
        return null;
    }

    $settings = [];
    foreach (explode(';', $dsn) as $pair) {
        [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
        $settings[trim($key)] = trim($value);
    }

    return [
        'host'     => $settings['host'] ?? '127.0.0.1',
        'port'     => (int) ($settings['port'] ?? 5432),
        'name'     => $settings['dbname'] ?? 'logwarden',
        'user'     => $settings['user'] ?? 'logwarden',
        'password' => $settings['password'] ?? '',
    ];
}

test('a dropped connection is transparently re-established', function (): void {
    $settings = testDbSettings();
    if ($settings === null) {
        assertTrue(true, 'skipped: set LW_TEST_DSN to run');

        return;
    }

    $db = new Db($settings);
    assertSame(1, (int) $db->fetchValue('SELECT 1'));

    // Kill this session's backend from a second connection. PDO reports the
    // resulting failure as SQLSTATE HY000, and PDO::inTransaction() starts
    // returning true on the corpse — the reason Db tracks that state itself.
    $pid   = (int) $db->fetchValue('SELECT pg_backend_pid()');
    $admin = new Db($settings);
    $admin->execute('SELECT pg_terminate_backend(?)', [$pid]);

    assertSame(1, (int) $db->fetchValue('SELECT 1'), 'query after connection loss must succeed');
});

test('a connection lost mid-transaction is reported, never silently retried', function (): void {
    $settings = testDbSettings();
    if ($settings === null) {
        assertTrue(true, 'skipped: set LW_TEST_DSN to run');

        return;
    }

    $db     = new Db($settings);
    $admin  = new Db($settings);
    $thrown = false;

    try {
        $db->transaction(function (Db $inner) use ($admin): void {
            $inner->execute('CREATE TEMP TABLE lw_tx_probe (id int)');
            $pid = (int) $inner->fetchValue('SELECT pg_backend_pid()');
            $admin->execute('SELECT pg_terminate_backend(?)', [$pid]);
            $inner->execute('INSERT INTO lw_tx_probe VALUES (1)');
        });
    } catch (PDOException) {
        $thrown = true;
    }

    assertTrue($thrown, 'the caller must learn the unit of work was lost');
    assertSame(1, (int) $db->fetchValue('SELECT 1'), 'the connection recovers for subsequent work');
});
