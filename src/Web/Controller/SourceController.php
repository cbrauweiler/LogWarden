<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Core\Config;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Event\SourceType;
use LogWarden\Ingest\IngestSource;
use LogWarden\Ingest\SourceRepository;
use LogWarden\Ingest\Windows\AdEventCatalog;
use LogWarden\Ingest\Dhcp\DhcpEventCatalog;
use LogWarden\Ingest\Windows\DnsEventCatalog;
use LogWarden\Ingest\Winrm\DhcpLogQuery;
use LogWarden\Ingest\Winrm\EventLogQuery;
use LogWarden\Ingest\Winrm\WinrmClient;
use LogWarden\Ingest\Winrm\WinrmShell;
use LogWarden\Plugin\PluginRegistry;
use LogWarden\Plugin\SourceTypeSync;
use LogWarden\Security\SecretBox;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\View;
use Throwable;

/** Manages the WinRM collection sources. */
final class SourceController
{
    /** Channels worth offering by name, with the source type each maps to. */
    private const CHANNELS = [
        'Security' => ['Active Directory — Sicherheit', 'ad'],
        'Microsoft-Windows-DNSServer/Audit' => ['DNS — Audit (Zonen- und Record-Änderungen)', 'dns'],
        'DNS Server' => ['DNS — Server-Eventlog', 'dns'],
        'System' => ['System', 'ad'],
    ];

    public function __construct(
        private readonly Db $db,
        private readonly SourceRepository $sources,
        private readonly SecretBox $secrets,
        private readonly Config $config,
        private readonly Logger $logger,
        private readonly View $view,
        private readonly string $actor,
    ) {
    }

    public function show(array $flash = [], array $errors = [], ?int $editId = null): Response
    {
        $edit = $editId === null ? null : $this->sources->find($editId);

        return Response::html($this->view->page('admin/sources', [
            'title'      => 'Quellen',
            'active'     => 'sources',
            'sources'    => $this->sources->health(),
            'channels'   => self::CHANNELS,
            'catalogue'  => AdEventCatalog::grouped(),
            'dnsAudit'   => DnsEventCatalog::grouped('Microsoft-Windows-DNSServer/Audit'),
            'dnsServer'  => DnsEventCatalog::grouped('DNS Server'),
            'dhcpCat'    => DhcpEventCatalog::grouped(),
            'dhcpIds'    => DhcpEventCatalog::defaultIds(),
            'dhcpPath'   => DhcpLogQuery::DEFAULT_PATH,
            'defaultIds' => AdEventCatalog::defaultIds(),
            'runs'       => $this->recentRuns(),
            'plugins'    => $this->plugins(),
            'orphans'    => (new SourceTypeSync($this->db))->orphansWithData(),
            'edit'       => $edit,
            'flash'      => $flash,
            'errors'     => $errors,
        ]));
    }

    public function save(): Response
    {
        if (!Csrf::check($_POST['_csrf'] ?? null)) {
            return $this->show([], ['Sicherheits-Token abgelaufen. Bitte erneut absenden.']);
        }

        try {
            return match ((string) ($_POST['action'] ?? '')) {
                'save'     => $this->saveSource(),
                'delete'   => $this->deleteSource(),
                'toggle'   => $this->toggleSource(),
                'test'     => $this->testSource(),
                'reset'    => $this->resetSource(),
                'password' => $this->setPassword(),
                default    => $this->show([], ['Unbekannte Aktion.']),
            };
        } catch (Throwable $e) {
            $this->logger->error('Quellenverwaltung fehlgeschlagen', ['error' => $e->getMessage()]);

            return $this->show([], [$e->getMessage()]);
        }
    }

    /** The edit form is a GET so the filled-in state survives a reload. */
    public function edit(int $id): Response
    {
        return $this->show([], [], $id);
    }

    // -----------------------------------------------------------------------

    private function saveSource(): Response
    {
        $name    = trim((string) ($_POST['name'] ?? ''));
        $host    = trim((string) ($_POST['target_host'] ?? ''));
        $channel = (string) ($_POST['channel'] ?? 'Security');
        $user    = trim((string) ($_POST['username'] ?? ''));
        $kind    = ($_POST['kind'] ?? 'winrm') === 'dhcp_csv' ? 'dhcp_csv' : 'winrm';

        if ($name === '' || $host === '' || $user === '') {
            return $this->show([], ['Name, Host und Konto sind Pflichtfelder.']);
        }

        if ($kind === 'winrm' && !isset(self::CHANNELS[$channel])) {
            return $this->show([], ['Unbekannter Kanal.']);
        }

        // A hostname, not a URL: the endpoint is assembled from host, port and
        // TLS setting, and accepting a URL here would let a pasted
        // "https://dc01/wsman?x=" change the path silently.
        if (preg_match('/^[A-Za-z0-9._-]+$/', $host) !== 1) {
            return $this->show([], ['Der Host darf nur Buchstaben, Ziffern, Punkt, Bindestrich und Unterstrich enthalten.']);
        }

        // DHCP ids are two-character strings ('00'..'64') and must stay that
        // way: casting them to int would turn '00' into 0 and lose the
        // "log started" event entirely.
        $ids = $kind === 'dhcp_csv'
            ? array_values(array_unique(array_filter(
                array_map(
                    static fn (mixed $v): string => str_pad(trim((string) $v), 2, '0', STR_PAD_LEFT),
                    (array) ($_POST['event_ids'] ?? []),
                ),
                static fn (string $id): bool => preg_match('/^\d{2}$/', $id) === 1,
            )))
            : array_values(array_filter(
                array_map('intval', (array) ($_POST['event_ids'] ?? [])),
                static fn (int $id): bool => $id > 0,
            ));

        // An empty selection means "collect the whole channel". On Security
        // that is the one outcome nobody wants by accident — it is the busiest
        // log on the machine. On the DNS channels it is the sensible default:
        // the audit channel writes nothing on a quiet day, and an unrecognised
        // change is exactly what one wants to keep.
        if ($ids === [] && $kind === 'winrm' && !DnsEventCatalog::isDnsChannel($channel)) {
            return $this->show([], ['Mindestens ein Ereignis auswählen.']);
        }

        if ($kind === 'dhcp_csv') {
            return $this->saveDhcpSource($name, $host, $user, $ids);
        }

        $sourceType = self::CHANNELS[$channel][1];

        $config = [
            'channel'                   => $channel,
            'event_ids'                 => $ids,
            'tls'                       => !empty($_POST['tls']),
            'tls_verify'                => !empty($_POST['tls_verify']),
            'window_seconds'            => $this->clamp($_POST['window_seconds'] ?? null, 60, 86400, EventLogQuery::DEFAULT_WINDOW_SECONDS),
            'max_events'                => $this->clamp($_POST['max_events'] ?? null, 100, 100000, 5000),
            'initial_lookback'          => $this->clamp($_POST['initial_lookback'] ?? null, 60, 86400 * 30, 3600),
            'include_message'           => !empty($_POST['include_message']),
            'include_computer_accounts' => !empty($_POST['include_computer_accounts']),
            'include_system_accounts'   => !empty($_POST['include_system_accounts']),
        ];

        if (!empty($_POST['port'])) {
            $config['port'] = $this->clamp($_POST['port'], 1, 65535, 5986);
        }

        $id = $this->sources->upsert([
            'name'            => $name,
            'collector'       => 'winrm',
            'source_type'     => SourceType::of($sourceType)->value,
            'target_host'     => $host,
            'enabled'         => !empty($_POST['enabled']),
            'config'          => $config,
            'username'        => $user,
            'auth_mode'       => in_array($_POST['auth_mode'] ?? '', ['ntlm', 'kerberos', 'basic'], true)
                ? (string) $_POST['auth_mode'] : 'ntlm',
            'poll_interval_s' => $this->clamp($_POST['poll_interval_s'] ?? null, 60, 86400, 300),
        ]);

        $password = (string) ($_POST['password'] ?? '');
        if ($password !== '') {
            $this->storePassword($id, $name, $password);
        }

        $this->audit('source.save', $name);

        return $this->show(['Quelle ' . $name . ' gespeichert.']);
    }

    /**
     * A DHCP source reads a file, not a channel.
     *
     * @param list<string> $ids
     */
    private function saveDhcpSource(string $name, string $host, string $user, array $ids): Response
    {
        $path = trim((string) ($_POST['log_path'] ?? DhcpLogQuery::DEFAULT_PATH));

        // A directory, not a file: the server writes one per weekday and names
        // them in its own locale, so the collector enumerates rather than
        // guesses. Rejecting anything with a wildcard or a quote keeps the
        // value from turning into something else inside the PowerShell literal.
        // Vier Backslashes: zwei kommen im einfach gequoteten PHP-String an,
        // und die braucht die Regex-Engine, um einen literalen zu treffen.
        // Mit zweien stand hier \[ — eine Escape-Sequenz für eine eckige
        // Klammer, die jeden gültigen Pfad abgelehnt hat.
        // Das Apostroph ist mit ausgeschlossen, obwohl DhcpLogQuery es ohnehin
        // verdoppelt: eine Prüfung, die sich allein darauf verlässt, dass die
        // Stelle weiter unten korrekt bleibt, ist eine Prüfung weniger.
        if ($path === '' || preg_match('/^[A-Za-z]:\\\\[^*?"\'<>|\r\n\x00]*$/', $path) !== 1) {
            return $this->show([], [
                'Der Pfad muss ein lokales Verzeichnis auf dem Server sein, z. B. '
                . 'C:\\Windows\\System32\\dhcp.',
            ]);
        }

        $id = $this->sources->upsert([
            'name'            => $name,
            'collector'       => 'dhcp_csv',
            'source_type'     => 'dhcp',
            'target_host'     => $host,
            'enabled'         => !empty($_POST['enabled']),
            'config'          => [
                'log_path'         => rtrim($path, '\\'),
                'event_ids'        => $ids,
                'ipv6'             => !empty($_POST['ipv6']),
                'tls'              => !empty($_POST['tls']),
                'tls_verify'       => !empty($_POST['tls_verify']),
                'window_seconds'   => $this->clamp($_POST['window_seconds'] ?? null, 300, 86400, 3600),
                'max_events'       => $this->clamp($_POST['max_events'] ?? null, 100, 500000, 200000),
                'initial_lookback' => $this->clamp($_POST['initial_lookback'] ?? null, 300, 86400 * 7, 86400),
            ] + (empty($_POST['port']) ? [] : ['port' => $this->clamp($_POST['port'], 1, 65535, 5986)]),
            'username'        => $user,
            'auth_mode'       => in_array($_POST['auth_mode'] ?? '', ['ntlm', 'kerberos', 'basic'], true)
                ? (string) $_POST['auth_mode'] : 'ntlm',
            'poll_interval_s' => $this->clamp($_POST['poll_interval_s'] ?? null, 60, 86400, 900),
        ]);

        $password = (string) ($_POST['password'] ?? '');
        if ($password !== '') {
            $this->storePassword($id, $name, $password);
        }

        $this->audit('source.save', $name);

        return $this->show(['DHCP-Quelle ' . $name . ' gespeichert.']);
    }

    /**
     * The password is written through SecretBox and never read back into the
     * page. The form therefore shows an empty field on every edit and an empty
     * submission leaves the stored password alone — otherwise saving an
     * unrelated setting would silently clear the credentials.
     */
    private function storePassword(int $sourceId, string $name, string $password): void
    {
        $ref = 'winrm/' . $sourceId;
        $this->secrets->put($ref, $password);
        $this->db->execute('UPDATE ingest_sources SET secret_ref = ? WHERE id = ?', [$ref, $sourceId]);
        $this->audit('source.password', $name);
    }

    private function setPassword(): Response
    {
        $source = $this->requireSource();
        $value  = (string) ($_POST['password'] ?? '');

        if ($value === '') {
            return $this->show([], ['Kein Passwort angegeben.']);
        }

        $this->storePassword($source->id, $source->name, $value);

        return $this->show(['Passwort für ' . $source->name . ' hinterlegt.']);
    }

    private function toggleSource(): Response
    {
        $source = $this->requireSource();
        $this->sources->setEnabled($source->id, !$source->enabled);
        $this->audit($source->enabled ? 'source.disable' : 'source.enable', $source->name);

        return $this->show([$source->name . ($source->enabled ? ' deaktiviert.' : ' aktiviert.')]);
    }

    private function resetSource(): Response
    {
        $source = $this->requireSource();
        $this->sources->resetBookmark($source->id);
        $this->audit('source.reset', $source->name);

        return $this->show([
            'Lesezeichen von ' . $source->name . ' zurückgesetzt — der nächste Lauf beginnt '
            . 'wieder bei der eingestellten Vorlaufzeit.',
        ]);
    }

    private function deleteSource(): Response
    {
        $source = $this->requireSource();

        if ($source->secretRef !== null) {
            $this->secrets->delete($source->secretRef);
        }

        $this->sources->delete($source->id);
        $this->audit('source.delete', $source->name);

        return $this->show(['Quelle ' . $source->name . ' gelöscht.']);
    }

    /**
     * Reachability, credentials and channel access, reported separately.
     *
     * Three different fixes hide behind "it does not work": a closed port, a
     * rejected account and a channel the account may not read. Testing them in
     * order and naming which step failed is the difference between a useful
     * button and a red cross.
     */
    private function testSource(): Response
    {
        $source = $this->requireSource();

        if ($source->targetHost === null || $source->username === null) {
            return $this->show([], ['Für ' . $source->name . ' fehlt Host oder Konto.']);
        }

        $password = $source->secretRef === null ? null : $this->secrets->get($source->secretRef);
        if ($password === null) {
            return $this->show([], ['Für ' . $source->name . ' ist kein Passwort hinterlegt.']);
        }

        $defaults = $this->config->section('winrm');
        $client   = new WinrmClient(
            $source->targetHost,
            $source->username,
            $password,
            [
                'auth'            => $source->authMode,
                'tls'             => (bool) $source->setting('tls', $defaults['tls'] ?? true),
                'port'            => $source->setting('port', $defaults['port'] ?? null),
                'tls_verify'      => (bool) $source->setting('tls_verify', $defaults['tls_verify'] ?? true),
                'ca_file'         => $source->setting('ca_file', $defaults['ca_file'] ?? null),
                'connect_timeout' => (int) ($defaults['connect_timeout'] ?? 10),
                'read_timeout'    => (int) ($defaults['read_timeout'] ?? 60),
            ],
            $this->logger,
        );

        $steps = [];

        try {
            $identity = $client->identify();
            $steps[]  = 'WS-Management erreichbar (' . ($identity['vendor'] ?? 'unbekannt') . ').';
        } catch (Throwable $e) {
            return $this->show([], ['Schritt 1 — Erreichbarkeit: ' . $e->getMessage()]);
        }

        try {
            $shell = new WinrmShell($client, $this->logger, 30);
            $probe = $shell->run('powershell.exe', EventLogQuery::powershellArguments(
                '$ErrorActionPreference = \'Stop\''
                . "\n" . '(Get-WinEvent -ListLog ' . self::psLiteral($source->channel()) . ').RecordCount',
            ), 60);

            if ($probe['exit_code'] !== 0) {
                return $this->show($steps, [
                    'Schritt 2 — Kanalzugriff: ' . (trim($probe['stderr']) ?: 'Exit-Code ' . $probe['exit_code']),
                ]);
            }

            // Whatever the host sent back is treated as untrusted text: the
            // probe asks for a record count, so anything that is not a number
            // is reported as "unbekannt" rather than pasted into the page.
            $count = trim($probe['stdout']);

            $steps[] = sprintf(
                'Kanal %s lesbar, %s Einträge vorhanden.',
                $source->channel(),
                ctype_digit($count) ? number_format((int) $count, 0, ',', '.') : 'unbekannt viele',
            );
        } catch (Throwable $e) {
            return $this->show($steps, ['Schritt 2 — Kanalzugriff: ' . $e->getMessage()]);
        } finally {
            $client->close();
        }

        $this->audit('source.test', $source->name);

        return $this->show($steps);
    }

    // -----------------------------------------------------------------------

    private function requireSource(): IngestSource
    {
        $source = $this->sources->find((int) ($_POST['source_id'] ?? 0));

        if ($source === null) {
            throw new \RuntimeException('Unbekannte Quelle.');
        }

        return $source;
    }

    /**
     * The installed plugins, with what each contributes.
     *
     * @return array{plugins: list<array<string, mixed>>, errors: list<string>}
     */
    private function plugins(): array
    {
        $registry = PluginRegistry::default();
        $counts   = [];

        foreach ($this->db->fetchAll(
            "SELECT source_type, count(*) AS c
               FROM events
              WHERE ts > now() - interval '30 days'
              GROUP BY source_type",
        ) as $row) {
            $counts[$row['source_type']] = (int) $row['c'];
        }

        $out = [];

        foreach ($registry->manifests() as $key => $manifest) {
            $entry = $manifest->toArray();
            $entry['sourceTypes'] = [];
            $entry['error']       = null;

            try {
                $plugin = $registry->get($key);
                $entry['transports'] = $plugin::transports();

                foreach ($plugin::sourceTypes() as $definition) {
                    $entry['sourceTypes'][] = [
                        'key'    => $definition->key,
                        'label'  => $definition->label,
                        'role'   => $definition->role,
                        'color'  => $definition->color,
                        'events' => $counts[$definition->key] ?? 0,
                    ];
                }
            } catch (Throwable $e) {
                $entry['error']      = $e->getMessage();
                $entry['transports'] = [];
            }

            $out[] = $entry;
        }

        return ['plugins' => $out, 'errors' => $registry->errors()];
    }

    /** @return array<int, list<array<string, mixed>>> */
    private function recentRuns(): array
    {
        $runs = [];

        foreach ($this->sources->all('winrm') as $source) {
            $runs[$source->id] = $this->sources->recentRuns($source->id, 8);
        }

        return $runs;
    }

    private function clamp(mixed $value, int $min, int $max, int $default): int
    {
        if (!is_numeric($value)) {
            return $default;
        }

        return max($min, min($max, (int) $value));
    }

    private static function psLiteral(string $value): string
    {
        return "'" . str_replace("'", "''", $value) . "'";
    }

    private function audit(string $action, string $target): void
    {
        $this->db->execute(
            'INSERT INTO audit_log (user_id, username, action, target)
             VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?)',
            [$this->actor, $this->actor, $action, $target],
        );
    }
}
