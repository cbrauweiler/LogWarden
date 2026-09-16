<?php

declare(strict_types=1);

use LogWarden\Event\SourceType;
use LogWarden\Plugin\PluginInterface;
use LogWarden\Plugin\PluginManifest;
use LogWarden\Plugin\PluginRegistry;
use LogWarden\Plugin\SourceTypeDefinition;

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

test('a manifest is rejected when it disagrees with its directory', function (): void {
    // The directory name is what the loader maps and the key is what the
    // database stores. If the two drift apart, "which plugin wrote this event"
    // stops being answerable.
    $dir = makePluginDir('acme', ['key' => 'something-else']);

    try {
        PluginManifest::load($dir);
        assertTrue(false, 'should have thrown');
    } catch (RuntimeException $e) {
        assertTrue(str_contains($e->getMessage(), 'Verzeichnisnamen'));
    }
});

test('a manifest must claim a namespace under LogWarden\\Plugin', function (): void {
    $dir = makePluginDir('acme', ['namespace' => 'Evil\\Injected']);

    try {
        PluginManifest::load($dir);
        assertTrue(false, 'should have thrown');
    } catch (RuntimeException $e) {
        assertTrue(str_contains($e->getMessage(), 'LogWarden\\Plugin'));
    }
});

test('a missing required field names itself', function (): void {
    $dir = makePluginDir('acme', ['class' => null]);

    try {
        PluginManifest::load($dir);
        assertTrue(false, 'should have thrown');
    } catch (RuntimeException $e) {
        assertTrue(str_contains($e->getMessage(), '"class"'));
    }
});

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

test('a broken plugin is reported without taking the others down', function (): void {
    $root = makeTempRoot();
    makePluginDir('broken', ['key' => 'wrong'], $root);
    $good = makeWorkingPlugin('working', $root);

    $registry = new PluginRegistry([$root]);

    // The daemon has to keep collecting from the sources that do work; the
    // problem belongs in the plugin list, not in a stack trace at 03:00.
    assertTrue($registry->has('working'), 'the good one still loads');
    assertFalse($registry->has('broken'));
    assertCount(1, $registry->errors());
    assertSame($good, $registry->get('working')::key());
});

test('the registry finds the shipped plugins and their transports', function (): void {
    $registry = PluginRegistry::default();

    assertTrue($registry->has('fortigate'));
    assertTrue($registry->has('cisco-asa'));
    assertCount(0, $registry->errors(), 'the shipped plugins load cleanly');

    $normalizers = $registry->normalizersFor('syslog');
    assertTrue(count($normalizers) >= 2, 'both vendors offer a syslog normaliser');

    assertCount(0, $registry->normalizersFor('carrier-pigeon'));
});

test('a class that does not implement the interface is refused', function (): void {
    $root = makeTempRoot();
    $dir  = $root . '/notaplugin';
    mkdir($dir, 0700, true);

    file_put_contents($dir . '/plugin.json', json_encode([
        'key'       => 'notaplugin',
        'name'      => 'Not a plugin',
        'namespace' => 'LogWarden\\Plugin\\NotAPlugin',
        'class'     => 'JustAClass',
    ]));

    file_put_contents($dir . '/JustAClass.php', <<<'PHP'
        <?php
        namespace LogWarden\Plugin\NotAPlugin;
        final class JustAClass {}
        PHP);

    try {
        (new PluginRegistry([$root]))->get('notaplugin');
        assertTrue(false, 'should have thrown');
    } catch (RuntimeException $e) {
        assertTrue(str_contains($e->getMessage(), 'PluginInterface'));
    }
});

test('a plugin whose class reports a different key is refused', function (): void {
    // Otherwise renaming a directory would let one plugin silently take over
    // another's source types.
    $root = makeTempRoot();
    makeWorkingPlugin('claimsother', $root, declaredKey: 'somethingelse');

    try {
        (new PluginRegistry([$root]))->get('claimsother');
        assertTrue(false, 'should have thrown');
    } catch (RuntimeException $e) {
        assertTrue(str_contains($e->getMessage(), 'somethingelse'));
    }
});

// ---------------------------------------------------------------------------
// Source types
// ---------------------------------------------------------------------------

test('plugins contribute source types that the core does not know', function (): void {
    $keys = array_keys(SourceType::definitions());

    foreach (['ad', 'dns', 'dhcp'] as $core) {
        assertTrue(in_array($core, $keys, true), $core . ' is built in');
    }

    foreach (['fortigate_vpn', 'fortigate_auth', 'cisco_asa_vpn', 'cisco_asa_auth'] as $fromPlugin) {
        assertTrue(in_array($fromPlugin, $keys, true), $fromPlugin . ' comes from a plugin');
    }
});

test('a source type the core defines cannot be redefined by a plugin', function (): void {
    // Otherwise a plugin could quietly change what 'ad' means, and with it the
    // retention of the domain controllers' security log.
    assertSame('Active Directory', SourceType::of('ad')->label());
    assertSame(365, SourceType::definitions()['ad']->keepDays);
});

test('writing validates the key, reading does not', function (): void {
    try {
        SourceType::of('definitely_not_installed');
        assertTrue(false, 'should have thrown');
    } catch (InvalidArgumentException $e) {
        assertTrue(str_contains($e->getMessage(), 'Plugin'));
    }

    // History outlives the plugin that produced it.
    $stored = SourceType::ofStored('removed_vendor_vpn');
    assertSame('removed_vendor_vpn', $stored->label(), 'falls back to the key');
    assertFalse($stored->isKnown());
    assertTrue($stored->color() !== '', 'still gets a colour so charts do not break');
});

test('roles let a rule name a capability instead of a vendor', function (): void {
    $vpn = SourceType::withRole(SourceTypeDefinition::ROLE_VPN);

    // This is the whole point of roles: two vendors, one role, and the
    // correlation rule never mentions either of them.
    assertTrue(in_array('fortigate_vpn', $vpn, true));
    assertTrue(in_array('cisco_asa_vpn', $vpn, true));

    assertSame('directory', SourceType::of('ad')->role());
    assertSame('auth', SourceType::of('cisco_asa_auth')->role());
});

test('an invalid source type key is refused at declaration time', function (): void {
    foreach (['Nope', '1st', 'a', 'has-dash', 'way_too_long_' . str_repeat('x', 40), ''] as $bad) {
        try {
            new SourceTypeDefinition($bad, 'Test');
            assertTrue(false, 'accepted ' . var_export($bad, true));
        } catch (InvalidArgumentException) {
            assertTrue(true);
        }
    }
});

test('an unknown role is refused', function (): void {
    try {
        new SourceTypeDefinition('valid_key', 'Test', role: 'nonsense');
        assertTrue(false, 'should have thrown');
    } catch (InvalidArgumentException $e) {
        assertTrue(str_contains($e->getMessage(), 'Rolle'));
    }
});

test('every declared colour is a real palette entry', function (): void {
    foreach (SourceType::definitions() as $key => $definition) {
        if ($definition->color === null) {
            continue;
        }

        assertTrue(
            in_array($definition->color, SourceTypeDefinition::PALETTE, true),
            $key . ' uses ' . $definition->color . ', which is not in the palette',
        );
    }
});

test('no two source types share a colour', function (): void {
    // They are drawn next to each other in every chart.
    $used = [];

    foreach (SourceType::definitions() as $key => $definition) {
        if ($definition->color === null) {
            continue;
        }

        assertFalse(isset($used[$definition->color]), $definition->color . ' used by both ' . ($used[$definition->color] ?? '') . ' and ' . $key);
        $used[$definition->color] = $key;
    }
});

// ---------------------------------------------------------------------------
// The shipped plugins honour the contract
// ---------------------------------------------------------------------------

test('every shipped plugin satisfies the contract it declares', function (): void {
    $registry = PluginRegistry::default();

    foreach ($registry->manifests() as $key => $manifest) {
        $plugin = $registry->get($key);

        assertTrue($plugin instanceof PluginInterface, $key);
        assertSame($key, $plugin::key(), 'key matches the directory');
        assertTrue($plugin::transports() !== [], $key . ' declares a transport');
        assertTrue($plugin::sourceTypes() !== [], $key . ' declares a source type');
        assertTrue($plugin->normalizers() !== [], $key . ' provides a normaliser');

        foreach ($plugin->normalizers() as $normalizer) {
            // A normaliser that claims everything would swallow the other
            // vendors' traffic on a shared listener.
            assertFalse(
                $normalizer->supports('völlig belangloser Text ohne Struktur'),
                $key . ' must not claim arbitrary input',
            );
        }
    }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTempRoot(): string
{
    $root = sys_get_temp_dir() . '/lw-plugins-' . bin2hex(random_bytes(6));
    mkdir($root, 0700, true);
    registerTempDir($root);

    return $root;
}

/** @param array<string, mixed> $overrides */
function makePluginDir(string $name, array $overrides = [], ?string $root = null): string
{
    $root ??= makeTempRoot();
    $dir    = $root . '/' . $name;
    mkdir($dir, 0700, true);

    $manifest = [
        'key'       => $name,
        'name'      => ucfirst($name),
        'namespace' => 'LogWarden\\Plugin\\Acme',
        'class'     => 'AcmePlugin',
    ];

    foreach ($overrides as $field => $value) {
        if ($value === null) {
            unset($manifest[$field]);
            continue;
        }
        $manifest[$field] = $value;
    }

    file_put_contents($dir . '/plugin.json', json_encode($manifest));

    return $dir;
}

/**
 * Writes a minimal but real plugin into a temporary directory.
 *
 * Deliberately generated rather than copied from plugins/: the shipped classes
 * are already loaded by the time a test runs, and requiring the same class
 * from a second path is a fatal redeclaration.
 *
 * @return string the key the generated class reports
 */
function makeWorkingPlugin(string $name, string $root, ?string $declaredKey = null): string
{
    $dir       = $root . '/' . $name;
    $namespace = 'LogWarden\\Plugin\\Tmp' . str_replace('-', '', ucfirst($name)) . bin2hex(random_bytes(3));
    $class     = 'GeneratedPlugin';
    $key       = $declaredKey ?? $name;

    mkdir($dir, 0700, true);

    file_put_contents($dir . '/plugin.json', json_encode([
        'key'       => $name,
        'name'      => ucfirst($name),
        'version'   => '1.0.0',
        'namespace' => $namespace,
        'class'     => $class,
    ]));

    file_put_contents($dir . '/' . $class . '.php', sprintf(<<<'PHP'
        <?php
        namespace %s;

        use LogWarden\Plugin\PluginInterface;
        use LogWarden\Plugin\SourceTypeDefinition;

        final class %s implements PluginInterface
        {
            public static function key(): string { return '%s'; }
            public static function transports(): array { return ['syslog']; }
            public static function sourceTypes(): array
            {
                return [new SourceTypeDefinition('tmp_%s', 'Temporär')];
            }
            public function normalizers(): array { return []; }
        }
        PHP, $namespace, $class, $key, bin2hex(random_bytes(3))));

    return $key;
}

/** Temporary plugin roots are removed when the process ends. */
function registerTempDir(string $dir): void
{
    static $registered = false;
    static $dirs = [];

    $dirs[] = $dir;

    if ($registered) {
        return;
    }

    $registered = true;

    register_shutdown_function(static function () use (&$dirs): void {
        foreach ($dirs as $d) {
            foreach (glob($d . '/*/*') ?: [] as $file) {
                @unlink($file);
            }
            foreach (glob($d . '/*', GLOB_ONLYDIR) ?: [] as $sub) {
                @rmdir($sub);
            }
            @rmdir($d);
        }
    });
}
