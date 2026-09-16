<?php

declare(strict_types=1);

use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Security\AuthProviderInterface;
use LogWarden\Security\AuthResult;
use LogWarden\Security\Authenticator;
use LogWarden\Security\LdapAuthProvider;
use LogWarden\Security\LocalAuthProvider;
use LogWarden\Security\PasswordPolicy;
use LogWarden\Security\Permission;
use LogWarden\Security\Role;
use LogWarden\Security\RoleResolver;
use LogWarden\Security\SessionStore;

// ---------------------------------------------------------------------------
// Roles and permissions
// ---------------------------------------------------------------------------

test('each role grants exactly what it should', function (): void {
    assertTrue(Role::Readonly->can(Permission::SEARCH_VIEW));
    assertFalse(Role::Readonly->can(Permission::ALERT_ACK), 'read-only must not change anything');
    assertFalse(Role::Readonly->can(Permission::USER_MANAGE));

    assertTrue(Role::Analyst->can(Permission::ALERT_ACK));
    assertTrue(Role::Analyst->can(Permission::RULE_TEST));
    assertFalse(Role::Analyst->can(Permission::RULE_EDIT), 'analysts test rules, they do not change them');
    assertFalse(Role::Analyst->can(Permission::USER_MANAGE));
    assertFalse(Role::Analyst->can(Permission::BRANDING_MANAGE));

    assertTrue(Role::Admin->can(Permission::USER_MANAGE));
    assertTrue(Role::Admin->can(Permission::RULE_EDIT));
});

test('every permission a role grants also grants the weaker roles nothing extra', function (): void {
    // Each level is a superset of the one below it, so an analyst can never do
    // something a read-only account can but an admin cannot.
    foreach (Role::Readonly->permissions() as $permission) {
        assertTrue(Role::Analyst->can($permission), "analyst is missing {$permission}");
        assertTrue(Role::Admin->can($permission), "admin is missing {$permission}");
    }

    foreach (Role::Analyst->permissions() as $permission) {
        assertTrue(Role::Admin->can($permission), "admin is missing {$permission}");
    }
});

test('the stronger role wins when an account matches several mappings', function (): void {
    assertTrue(Role::Admin->rank() > Role::Analyst->rank());
    assertTrue(Role::Analyst->rank() > Role::Readonly->rank());
});

test('every permission has a label for the profile page', function (): void {
    foreach (Role::Admin->permissions() as $permission) {
        assertTrue(isset(Permission::LABELS[$permission]), "no label for {$permission}");
    }
});

// ---------------------------------------------------------------------------
// Password policy
// ---------------------------------------------------------------------------

test('weak passwords are rejected with a reason', function (): void {
    assertTrue(PasswordPolicy::check('kurz') !== []);
    assertTrue(PasswordPolicy::check('passwort1234') !== [], 'a rejected substring');
    assertTrue(PasswordPolicy::check('Sommer-LogWarden-1') !== [], 'the product name');
    assertTrue(PasswordPolicy::check('abababababab') !== [], 'too few distinct characters');
    assertTrue(PasswordPolicy::check('jdoe-ist-hier-1234', 'jdoe') !== [], 'contains the username');
    assertTrue(PasswordPolicy::check(' Anker-Birke-Turm ') !== [], 'surrounding whitespace');
});

test('a passphrase is accepted', function (): void {
    assertCount(0, PasswordPolicy::check('Anker-Birke-Turm-Segel-42', 'notfall'));
    assertCount(0, PasswordPolicy::check('Der Hafen liegt im Norden 7'));
});

test('hashing uses Argon2id and verifies', function (): void {
    $hash = PasswordPolicy::hash('Anker-Birke-Turm-Segel-42');

    assertTrue(str_starts_with($hash, '$argon2id$'));
    assertTrue(PasswordPolicy::verify('Anker-Birke-Turm-Segel-42', $hash));
    assertFalse(PasswordPolicy::verify('Anker-Birke-Turm-Segel-43', $hash));
    assertFalse(PasswordPolicy::needsRehash($hash));
});

test('the suggested password satisfies the policy', function (): void {
    for ($i = 0; $i < 20; $i++) {
        assertCount(0, PasswordPolicy::check(PasswordPolicy::suggest()));
    }
});

// ---------------------------------------------------------------------------
// Distinguished names
// ---------------------------------------------------------------------------

test('the group name is read out of a distinguished name', function (): void {
    assertSame('SOC-Admins', RoleResolver::commonName('CN=SOC-Admins,OU=Groups,DC=corp,DC=local'));
    assertSame('SOC-Admins', RoleResolver::commonName('cn=SOC-Admins,ou=Groups,dc=corp,dc=local'));
    assertSame('SOC-Admins', RoleResolver::commonName('SOC-Admins'), 'a bare name passes through');
    // An escaped comma inside the name must not end it.
    assertSame('Weber, Petra', RoleResolver::commonName('CN=Weber\\, Petra,OU=Users,DC=corp,DC=local'));
    assertNull(RoleResolver::commonName(''));
});

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

final class FakeAuthProvider implements AuthProviderInterface
{
    public int $calls = 0;

    public function __construct(
        private readonly string $name,
        private readonly ?AuthResult $result = null,
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function authenticate(string $username, string $password): AuthResult
    {
        $this->calls++;

        return $this->result ?? AuthResult::fail('invalid_credentials', $this->name);
    }

    public function healthCheck(): AuthResult
    {
        return AuthResult::ok('health', $this->name);
    }
}

const AU_PREFIX = 'authtest-';

function authCleanup(Db $db): void
{
    $db->execute('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username LIKE ?)', [AU_PREFIX . '%']);
    $db->execute('DELETE FROM login_attempts WHERE username LIKE ?', [AU_PREFIX . '%']);
    $db->execute('DELETE FROM users WHERE username LIKE ?', [AU_PREFIX . '%']);
    // Matches anywhere, not just at the start: a mapping written as a full DN
    // begins with "CN=", so a prefix match would leave it behind to collide
    // with the next run.
    $db->execute('DELETE FROM ldap_role_map WHERE subject LIKE ?', ['%' . AU_PREFIX . '%']);
}

function authSkip(): bool
{
    if (ruleDb() === null) {
        assertTrue(true, 'skipped: set LW_TEST_DSN to run');

        return true;
    }

    return false;
}

function makeAuth(Db $db, array $providers): Authenticator
{
    return new Authenticator(
        $db,
        $providers,
        new RoleResolver($db),
        new SessionStore($db, 3600, 28800),
        new Logger(null, 'error', false),
    );
}

// ---------------------------------------------------------------------------
// Role resolution
// ---------------------------------------------------------------------------

test('a mapping matches a group by short name and by full DN alike', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO ldap_role_map (subject_type, subject, role, priority) VALUES
         ('group', ?, 'admin', 100), ('group', ?, 'analyst', 100)",
        [AU_PREFIX . 'Admins', 'CN=' . AU_PREFIX . 'Analysten,OU=Groups,DC=corp,DC=local'],
    );

    $resolver = new RoleResolver($db);

    // Administrators think in terms of "SOC-Admins", not the full DN.
    $byShort = $resolver->resolve('x', ['CN=' . AU_PREFIX . 'Admins,OU=Groups,DC=corp,DC=local']);
    assertSame(Role::Admin, $byShort['role']);

    $byDn = $resolver->resolve('x', ['CN=' . AU_PREFIX . 'Analysten,OU=Groups,DC=corp,DC=local']);
    assertSame(Role::Analyst, $byDn['role']);

    authCleanup($db);
});

test('a mapping can address a single account', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO ldap_role_map (subject_type, subject, role, priority) VALUES ('user', ?, 'readonly', 100)",
        [AU_PREFIX . 'pruefer'],
    );

    $resolved = (new RoleResolver($db))->resolve(AU_PREFIX . 'PRUEFER', []);

    assertSame(Role::Readonly, $resolved['role'], 'account names match case-insensitively');
    assertTrue(str_starts_with((string) $resolved['matched_by'], 'Konto:'));

    authCleanup($db);
});

test('membership in several groups grants the stronger role', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO ldap_role_map (subject_type, subject, role, priority) VALUES
         ('group', ?, 'analyst', 100), ('group', ?, 'admin', 100)",
        [AU_PREFIX . 'Analysten', AU_PREFIX . 'Admins'],
    );

    $resolved = (new RoleResolver($db))->resolve('x', [
        'CN=' . AU_PREFIX . 'Analysten,OU=G,DC=c',
        'CN=' . AU_PREFIX . 'Admins,OU=G,DC=c',
    ]);

    assertSame(Role::Admin, $resolved['role']);

    authCleanup($db);
});

test('priority beats role strength when it is set higher', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    // A deliberately higher priority is how an administrator overrides the
    // usual "strongest wins" behaviour.
    $db->execute(
        "INSERT INTO ldap_role_map (subject_type, subject, role, priority) VALUES
         ('group', ?, 'admin', 10), ('group', ?, 'readonly', 900)",
        [AU_PREFIX . 'Admins', AU_PREFIX . 'Gesperrt'],
    );

    $resolved = (new RoleResolver($db))->resolve('x', [
        'CN=' . AU_PREFIX . 'Admins,OU=G,DC=c',
        'CN=' . AU_PREFIX . 'Gesperrt,OU=G,DC=c',
    ]);

    assertSame(Role::Readonly, $resolved['role']);

    authCleanup($db);
});

test('a disabled mapping stops granting anything', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO ldap_role_map (subject_type, subject, role, priority, enabled)
         VALUES ('group', ?, 'admin', 100, false)",
        [AU_PREFIX . 'Admins'],
    );

    assertNull((new RoleResolver($db))->resolve('x', ['CN=' . AU_PREFIX . 'Admins,OU=G,DC=c'])['role']);

    authCleanup($db);
});

// ---------------------------------------------------------------------------
// Authenticator
// ---------------------------------------------------------------------------

test('an authenticated account with no mapping is refused', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    // A new directory account must not silently gain access just by existing.
    $provider = new FakeAuthProvider('ldap', AuthResult::ok(AU_PREFIX . 'fremd', 'ldap', groups: ['CN=Irgendwas,DC=c']));
    $result   = makeAuth($db, [$provider])->login(AU_PREFIX . 'fremd', 'x', '10.0.0.1', 'test');

    assertFalse($result['ok']);
    assertTrue(str_contains($result['message'], 'keine Berechtigungsstufe'));
    assertNull($db->fetchValue('SELECT 1 FROM users WHERE username = ?', [AU_PREFIX . 'fremd']));

    authCleanup($db);
});

test('a directory outage does not count against the account lockout', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO users (username, auth_provider, password_hash, role, role_source, enabled)
         VALUES (?, 'local', ?, 'admin', 'manual', true)",
        [AU_PREFIX . 'lokal', PasswordPolicy::hash('Anker-Birke-Turm-Segel-42')],
    );

    // Directory down, local provider simply does not know this account. That
    // looks exactly like a wrong password, and counting it would lock people
    // out of the system they need to diagnose the outage with.
    $auth = makeAuth($db, [
        new FakeAuthProvider('ldap', AuthResult::unavailable('down', 'ldap')),
        new LocalAuthProvider($db),
    ]);

    for ($i = 0; $i < 12; $i++) {
        $auth->login(AU_PREFIX . 'adkonto', 'irgendwas', '10.0.0.1', 'test');
    }

    // And the local break-glass account still works during that outage.
    $result = $auth->login(AU_PREFIX . 'lokal', 'Anker-Birke-Turm-Segel-42', '10.0.0.1', 'test');
    assertTrue($result['ok'], 'the local account is the way back in');
    assertSame(Role::Admin, $result['user']->role);

    authCleanup($db);
});

test('repeated wrong passwords lock the account', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO users (username, auth_provider, password_hash, role, role_source, enabled)
         VALUES (?, 'local', ?, 'analyst', 'manual', true)",
        [AU_PREFIX . 'opfer', PasswordPolicy::hash('Falke-Quelle-Raute-Welle-31')],
    );

    $auth = makeAuth($db, [new LocalAuthProvider($db)]);

    for ($i = 0; $i < 9; $i++) {
        $auth->login(AU_PREFIX . 'opfer', 'falsch', '10.0.0.2', 'test');
    }

    $result = $auth->login(AU_PREFIX . 'opfer', 'Falke-Quelle-Raute-Welle-31', '10.0.0.2', 'test');

    assertFalse($result['ok'], 'the correct password must not open a locked account');
    assertTrue(str_contains($result['message'], 'gesperrt'));

    authCleanup($db);
});

test('a disabled account cannot sign in', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO users (username, auth_provider, password_hash, role, role_source, enabled)
         VALUES (?, 'local', ?, 'admin', 'manual', false)",
        [AU_PREFIX . 'gesperrt', PasswordPolicy::hash('Anker-Birke-Turm-Segel-42')],
    );

    $result = makeAuth($db, [new LocalAuthProvider($db)])
        ->login(AU_PREFIX . 'gesperrt', 'Anker-Birke-Turm-Segel-42', '10.0.0.3', 'test');

    assertFalse($result['ok']);

    authCleanup($db);
});

test('a manually assigned role survives the next directory login', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $db->execute(
        "INSERT INTO ldap_role_map (subject_type, subject, role, priority) VALUES ('group', ?, 'admin', 100)",
        [AU_PREFIX . 'Admins'],
    );
    $db->execute(
        "INSERT INTO users (username, auth_provider, role, role_source, enabled)
         VALUES (?, 'ldap', 'readonly', 'manual', true)",
        [AU_PREFIX . 'sonder'],
    );

    // The account is in the admin group, but an administrator decided
    // otherwise. Editing AD should not be required to make that stick.
    $provider = new FakeAuthProvider('ldap', AuthResult::ok(
        AU_PREFIX . 'sonder', 'ldap', groups: ['CN=' . AU_PREFIX . 'Admins,OU=G,DC=c'],
    ));

    $result = makeAuth($db, [$provider])->login(AU_PREFIX . 'sonder', 'x', '10.0.0.4', 'test');

    assertTrue($result['ok']);
    assertSame(Role::Readonly, $result['user']->role);

    authCleanup($db);
});

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

test('the session cookie value is never stored as given', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $id = (int) $db->fetchValue(
        "INSERT INTO users (username, auth_provider, password_hash, role, role_source, enabled)
         VALUES (?, 'local', ?, 'analyst', 'manual', true) RETURNING id",
        [AU_PREFIX . 'sitzung', PasswordPolicy::hash('Anker-Birke-Turm-Segel-42')],
    );

    $store   = new SessionStore($db, 3600, 28800);
    $session = $store->create($id, '10.0.0.5', 'Firefox');

    // A database dump must not hand out live sessions.
    assertNull($db->fetchValue('SELECT 1 FROM sessions WHERE id = ?', [$session['token']]));
    assertSame(1, (int) $db->fetchValue('SELECT count(*) FROM sessions WHERE id = ?', [hash('sha256', $session['token'])]));

    $user = $store->resolve($session['token']);
    assertFalse($user === null);
    assertSame(AU_PREFIX . 'sitzung', $user->username);

    assertNull($store->resolve(str_repeat('a', 64)), 'an unknown token resolves to nobody');
    assertNull($store->resolve('zu-kurz'));
    assertNull($store->resolve(null));

    authCleanup($db);
});

test('disabling an account ends its sessions immediately', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $id = (int) $db->fetchValue(
        "INSERT INTO users (username, auth_provider, password_hash, role, role_source, enabled)
         VALUES (?, 'local', ?, 'admin', 'manual', true) RETURNING id",
        [AU_PREFIX . 'weg', PasswordPolicy::hash('Anker-Birke-Turm-Segel-42')],
    );

    $store   = new SessionStore($db, 3600, 28800);
    $session = $store->create($id, '10.0.0.6', 'Firefox');
    assertFalse($store->resolve($session['token']) === null);

    $db->execute('UPDATE users SET enabled = false WHERE id = ?', [$id]);

    // Not at the next expiry — now. That is the point of disabling it.
    assertNull($store->resolve($session['token']));
    assertSame(0, (int) $db->fetchValue('SELECT count(*) FROM sessions WHERE user_id = ?', [$id]));

    authCleanup($db);
});

test('the absolute lifetime is not extended by using the session', function (): void {
    if (authSkip()) { return; }
    $db = ruleDb();
    authCleanup($db);

    $id = (int) $db->fetchValue(
        "INSERT INTO users (username, auth_provider, password_hash, role, role_source, enabled)
         VALUES (?, 'local', ?, 'analyst', 'manual', true) RETURNING id",
        [AU_PREFIX . 'alt', PasswordPolicy::hash('Anker-Birke-Turm-Segel-42')],
    );

    $store   = new SessionStore($db, 3600, 28800);
    $session = $store->create($id, '10.0.0.7', 'Firefox');

    // A stolen session must not be keepable alive indefinitely by using it.
    $db->execute(
        "UPDATE sessions SET absolute_expires_at = now() - interval '1 minute' WHERE user_id = ?",
        [$id],
    );

    assertNull($store->resolve($session['token']));

    authCleanup($db);
});

// ---------------------------------------------------------------------------
// LDAP, against a real directory
// ---------------------------------------------------------------------------

function ldapSettings(): ?array
{
    $dsn = getenv('LW_TEST_LDAP');

    if ($dsn === false || $dsn === '' || !extension_loaded('ldap')) {
        return null;
    }

    return [
        'hosts'           => [$dsn],
        'base_dn'         => 'dc=corp,dc=local',
        'bind_format'     => 'uid=%s,ou=Users,dc=corp,dc=local',
        'login_attribute' => 'uid',
        'tls_verify'      => false,
        'timeout'         => 3,
    ];
}

function ldapSkip(): bool
{
    if (ldapSettings() === null) {
        assertTrue(true, 'skipped: needs ext-ldap and LW_TEST_LDAP');

        return true;
    }

    return false;
}

test('a directory bind succeeds and returns the group memberships', function (): void {
    if (ldapSkip()) { return; }

    $result = (new LdapAuthProvider(ldapSettings(), new Logger(null, 'error', false)))
        ->authenticate('jdoe', 'Sommer2026!');

    assertTrue($result->success);
    assertSame('Jana Doerr', $result->displayName);
    assertSame('jana.doerr@corp.local', $result->email);
    assertCount(2, $result->groups);
});

test('a wrong password is rejected by the directory', function (): void {
    if (ldapSkip()) { return; }

    $result = (new LdapAuthProvider(ldapSettings(), new Logger(null, 'error', false)))
        ->authenticate('jdoe', 'falsch');

    assertFalse($result->success);
    assertSame('invalid_credentials', $result->reason);
});

test('an empty password is never sent to the directory', function (): void {
    if (ldapSkip()) { return; }

    // A bind with a DN and an empty password is an unauthenticated bind
    // (RFC 4513 §5.1.2). Servers should reject it, but not all do, and one
    // that accepts it would authenticate any account that exists.
    $result = (new LdapAuthProvider(ldapSettings(), new Logger(null, 'error', false)))
        ->authenticate('jdoe', '');

    assertFalse($result->success);
    assertSame('empty_credentials', $result->reason, 'rejected before the bind, not by it');
});

test('filter metacharacters in a username are refused', function (): void {
    if (ldapSkip()) { return; }

    $provider = new LdapAuthProvider(ldapSettings(), new Logger(null, 'error', false));

    foreach (['jdoe*)(uid=*', "jdoe\\", 'jdoe)(cn=*', "jdoe\x00admin"] as $hostile) {
        $result = $provider->authenticate($hostile, 'x');
        assertFalse($result->success);
        assertSame('invalid_username', $result->reason, "'{$hostile}' must not reach the directory");
    }
});

test('an unreachable directory is reported as unavailable, not as a bad password', function (): void {
    if (ldapSkip()) { return; }

    $settings = ldapSettings();
    $settings['hosts'] = ['ldap://127.0.0.1:3390'];   // nothing listens there

    $result = (new LdapAuthProvider($settings, new Logger(null, 'error', false)))
        ->authenticate('jdoe', 'Sommer2026!');

    assertFalse($result->success);
    assertTrue($result->providerUnavailable, 'an outage must not be treated as a failed login');
});
