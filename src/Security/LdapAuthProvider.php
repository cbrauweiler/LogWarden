<?php

declare(strict_types=1);

namespace LogWarden\Security;

use LogWarden\Core\Logger;
use SensitiveParameter;

/**
 * Authenticates against Active Directory (or any LDAPv3 directory) by binding
 * as the user and then reading their entry.
 *
 * Binding as the user is deliberate: it proves the password against the
 * directory's own policy, including expiry, disabled accounts and lockout,
 * without LogWarden having to replicate any of it.
 */
final class LdapAuthProvider implements AuthProviderInterface
{
    /**
     * AD's "member of, transitively" matching rule. Without it a user in
     * SOC-Admins via a nested group looks like a member of nothing.
     */
    private const MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941';

    public function __construct(
        private readonly array $settings,
        private readonly Logger $logger,
        private readonly ?string $serviceSecret = null,
    ) {
    }

    public function name(): string
    {
        return 'ldap';
    }

    public function authenticate(string $username, #[SensitiveParameter] string $password): AuthResult
    {
        $username = trim($username);

        // A bind with a DN and an empty password is an "unauthenticated bind"
        // (RFC 4513 §5.1.2). Servers SHOULD reject it, but not all do, and a
        // directory that accepts it would authenticate any account that exists
        // to anyone who submits a blank password. Never send it.
        if ($username === '' || $password === '') {
            return AuthResult::fail('empty_credentials', 'ldap');
        }

        if (!extension_loaded('ldap')) {
            return AuthResult::unavailable('ext-ldap ist nicht installiert', 'ldap');
        }

        // Control characters in a bind DN are how LDAP injection starts.
        if (preg_match('/[\x00-\x1f\\\\()*]/', $username) === 1) {
            return AuthResult::fail('invalid_username', 'ldap');
        }

        $lastError = null;

        foreach ($this->hosts() as $host) {
            $connection = $this->connect($host);

            if ($connection === null) {
                $lastError = "Verbindung zu {$host} fehlgeschlagen";
                continue;
            }

            $bindDn = $this->bindName($username);

            if (!@ldap_bind($connection, $bindDn, $password)) {
                $code = ldap_errno($connection);
                @ldap_unbind($connection);

                // Only a credential rejection is a failed login. Anything else
                // is the directory having a problem, and must not count toward
                // the account's lockout counter.
                if (in_array($code, [49, 50], true)) {
                    return AuthResult::fail('invalid_credentials', 'ldap');
                }

                $lastError = 'LDAP-Fehler ' . $code . ': ' . ldap_err2str($code);
                continue;
            }

            $entry = $this->readEntry($connection, $username);
            @ldap_unbind($connection);

            if ($entry === null) {
                // The bind worked, so the password is right — the account just
                // is not under the configured base DN.
                $this->logger->warning('LDAP bind succeeded but the account is not under base_dn', [
                    'username' => $username,
                    'base_dn'  => $this->settings['base_dn'] ?? null,
                ]);

                return AuthResult::fail('not_in_scope', 'ldap');
            }

            return AuthResult::ok(
                username:    $username,
                provider:    'ldap',
                displayName: $entry['display_name'],
                email:       $entry['email'],
                groups:      $entry['groups'],
            );
        }

        $this->logger->error('No directory host could be reached', ['error' => $lastError]);

        return AuthResult::unavailable($lastError ?? 'Kein Verzeichnisserver erreichbar', 'ldap');
    }

    public function healthCheck(): AuthResult
    {
        if (!extension_loaded('ldap')) {
            return AuthResult::unavailable('ext-ldap ist nicht installiert', 'ldap');
        }

        foreach ($this->hosts() as $host) {
            $connection = $this->connect($host);

            if ($connection === null) {
                continue;
            }

            // With a service account, prove it can actually read; without one,
            // reaching the port is all that can be checked.
            if ($this->serviceSecret !== null && !empty($this->settings['service_bind_dn'])) {
                $ok = @ldap_bind($connection, (string) $this->settings['service_bind_dn'], $this->serviceSecret);
                @ldap_unbind($connection);

                if (!$ok) {
                    return AuthResult::unavailable("Dienstkonto-Bind gegen {$host} abgelehnt", 'ldap');
                }

                return AuthResult::ok('service', 'ldap');
            }

            @ldap_unbind($connection);

            return AuthResult::ok('anonymous', 'ldap');
        }

        return AuthResult::unavailable('Kein Verzeichnisserver erreichbar', 'ldap');
    }

    // -----------------------------------------------------------------------

    /** @return list<string> */
    private function hosts(): array
    {
        $hosts = $this->settings['hosts'] ?? [];

        return array_values(array_filter(is_array($hosts) ? $hosts : [$hosts]));
    }

    /**
     * How the login name becomes something the directory will bind as.
     * AD accepts the user principal name, which is why `%s@corp.local` is the
     * default rather than assembling a distinguished name.
     */
    private function bindName(string $username): string
    {
        $format = (string) ($this->settings['bind_format'] ?? '%s');

        return str_contains($format, '%s')
            ? str_replace('%s', $username, $format)
            : $username;
    }

    /** @return resource|\LDAP\Connection|null */
    private function connect(string $host)
    {
        $timeout = (int) ($this->settings['timeout'] ?? 5);

        if (!empty($this->settings['tls_ca_file'])) {
            ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, (string) $this->settings['tls_ca_file']);
        }

        ldap_set_option(
            null,
            LDAP_OPT_X_TLS_REQUIRE_CERT,
            ($this->settings['tls_verify'] ?? true) ? LDAP_OPT_X_TLS_DEMAND : LDAP_OPT_X_TLS_NEVER,
        );

        $connection = @ldap_connect($host);

        if ($connection === false) {
            return null;
        }

        ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        // AD answers searches with referrals that PHP will chase and fail on.
        ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($connection, LDAP_OPT_NETWORK_TIMEOUT, $timeout);
        ldap_set_option($connection, LDAP_OPT_TIMELIMIT, $timeout);

        if (!empty($this->settings['start_tls']) && !@ldap_start_tls($connection)) {
            $this->logger->error('STARTTLS failed', ['host' => $host, 'error' => ldap_error($connection)]);
            @ldap_unbind($connection);

            return null;
        }

        return $connection;
    }

    /**
     * @param resource|\LDAP\Connection $connection
     * @return array{display_name:?string, email:?string, groups:list<string>}|null
     */
    private function readEntry($connection, string $username): ?array
    {
        $attribute = (string) ($this->settings['login_attribute'] ?? 'sAMAccountName');
        $baseDn    = (string) ($this->settings['base_dn'] ?? '');

        if ($baseDn === '') {
            return null;
        }

        $filter = sprintf('(%s=%s)', $attribute, ldap_escape($username, '', LDAP_ESCAPE_FILTER));

        $search = @ldap_search(
            $connection,
            $baseDn,
            $filter,
            ['dn', 'displayName', 'cn', 'mail', 'memberOf'],
            0,
            2,
            (int) ($this->settings['timeout'] ?? 5),
        );

        if ($search === false) {
            $this->logger->error('Directory search failed', [
                'filter' => $filter,
                'error'  => ldap_error($connection),
            ]);

            return null;
        }

        $entries = @ldap_get_entries($connection, $search);

        if (!is_array($entries) || ($entries['count'] ?? 0) < 1) {
            return null;
        }

        $entry  = $entries[0];
        $groups = $this->groupsOf($entry);

        if (!empty($this->settings['nested_groups'])) {
            $groups = array_values(array_unique(array_merge(
                $groups,
                $this->nestedGroups($connection, (string) $entry['dn'], $baseDn),
            )));
        }

        return [
            'display_name' => $entry['displayname'][0] ?? $entry['cn'][0] ?? null,
            'email'        => $entry['mail'][0] ?? null,
            'groups'       => $groups,
        ];
    }

    /**
     * @param array<string, mixed> $entry
     * @return list<string>
     */
    private function groupsOf(array $entry): array
    {
        $memberOf = $entry['memberof'] ?? null;

        if (!is_array($memberOf)) {
            return [];
        }

        unset($memberOf['count']);

        return array_values(array_map('strval', $memberOf));
    }

    /**
     * @param resource|\LDAP\Connection $connection
     * @return list<string>
     */
    private function nestedGroups($connection, string $userDn, string $baseDn): array
    {
        $filter = sprintf(
            '(member:%s:=%s)',
            self::MATCHING_RULE_IN_CHAIN,
            ldap_escape($userDn, '', LDAP_ESCAPE_FILTER),
        );

        $search = @ldap_search($connection, $baseDn, $filter, ['dn'], 0, 500, (int) ($this->settings['timeout'] ?? 5));

        if ($search === false) {
            // Non-AD directories do not implement the matching rule. The direct
            // memberOf list still stands, so this is a note, not a failure.
            $this->logger->debug('Nested group lookup unsupported by this directory');

            return [];
        }

        $entries = @ldap_get_entries($connection, $search);
        $groups  = [];

        for ($i = 0; $i < ($entries['count'] ?? 0); $i++) {
            $groups[] = (string) $entries[$i]['dn'];
        }

        return $groups;
    }
}
