<?php

declare(strict_types=1);

use LogWarden\Alerting\AlertRepository;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Notify\AdaptiveCardBuilder;
use LogWarden\Notify\ChannelFactory;
use LogWarden\Notify\ChannelInterface;
use LogWarden\Notify\Dispatcher;
use LogWarden\Notify\NotificationResult;
use LogWarden\Notify\TeamsWebhookChannel;
use LogWarden\Security\SecretBox;

// ---------------------------------------------------------------------------
// Adaptive Card
// ---------------------------------------------------------------------------

function sampleAlert(array $overrides = []): array
{
    return $overrides + [
        'id'              => 42,
        'severity'        => 5,
        'title'           => '11 fehlgeschlagene Anmeldungen für pweber',
        'summary'         => '11 fehlgeschlagene Anmeldungen zwischen 05:27 und 05:34.',
        'rule_name'       => 'Fehlgeschlagene Anmeldungen (Burst)',
        'entity_user'     => 'pweber',
        'entity_ip'       => '10.20.30.44',
        'entity_host'     => 'DC01.corp.local',
        'event_count'     => 11,
        'triggered_label' => '16.09.2026 05:37',
        'evidence'        => json_encode([
            'peak_count' => 14,
            'by_source'  => ['ad' => 8, 'fortigate_vpn' => 3],
            'by_origin'  => [
                ['src_ip' => '10.20.30.44', 'target_host' => 'DC01', 'count' => 8],
                ['src_ip' => '203.0.113.77', 'target_host' => 'FGT-60F-HQ', 'count' => 3],
            ],
        ]),
    ];
}

test('the card carries the severity as a word, not only as a colour', function (): void {
    $card = (new AdaptiveCardBuilder())->alertCard(sampleAlert(), ['product_name' => 'SOC Console']);
    $json = json_encode($card);

    assertTrue(str_contains($json, 'Kritisch'), 'the severity label must be present as text');
    assertTrue(str_contains($json, 'attention'), 'and paired with the card colour keyword');
    assertTrue(str_contains($json, 'SOC Console'), 'the configured product name travels with the card');
});

test('the card summarises the facts an on-call person needs first', function (): void {
    $card  = (new AdaptiveCardBuilder())->alertCard(sampleAlert(), []);
    $facts = [];

    foreach ($card['body'] as $block) {
        if (($block['type'] ?? '') === 'FactSet') {
            foreach ($block['facts'] as $fact) {
                $facts[$fact['title']] = $fact['value'];
            }
        }
    }

    assertSame('pweber', $facts['Konto'] ?? null);
    assertSame('10.20.30.44', $facts['Quell-IP'] ?? null);
    assertSame('11', $facts['Events'] ?? null);
    assertSame('14', $facts['Höchststand'] ?? null, 'the peak is shown when it exceeds the current window');
    assertSame('ad: 8 · fortigate_vpn: 3', $facts['Quellen'] ?? null);
});

test('the origin breakdown reaches the card', function (): void {
    $json = json_encode((new AdaptiveCardBuilder())->alertCard(sampleAlert(), []));

    assertTrue(str_contains($json, 'Herkunft'));
    assertTrue(str_contains($json, '10.20.30.44'));
    assertTrue(str_contains($json, '203.0.113.77'));
});

test('the deep link is only added for a usable base URL', function (): void {
    $builder = new AdaptiveCardBuilder();

    $withUrl = $builder->alertCard(sampleAlert(), ['base_url' => 'https://logwarden.corp.local/']);
    assertSame('https://logwarden.corp.local/alert?id=42', $withUrl['actions'][0]['url'] ?? null);

    assertFalse(isset($builder->alertCard(sampleAlert(), [])['actions']), 'no base URL means no action');
    assertFalse(
        isset($builder->alertCard(sampleAlert(), ['base_url' => 'javascript:alert(1)'])['actions']),
        'a non-http scheme must never become a card action',
    );
});

test('the envelope is the shape Teams accepts', function (): void {
    $builder  = new AdaptiveCardBuilder();
    $envelope = $builder->envelope($builder->alertCard(sampleAlert(), []));

    assertSame('message', $envelope['type']);
    assertSame('application/vnd.microsoft.card.adaptive', $envelope['attachments'][0]['contentType']);
    assertSame('AdaptiveCard', $envelope['attachments'][0]['content']['type']);
    assertSame('1.4', $envelope['attachments'][0]['content']['version']);
});

// ---------------------------------------------------------------------------
// Webhook URL validation
// ---------------------------------------------------------------------------

function urlRejected(TeamsWebhookChannel $channel, string $url): bool
{
    try {
        $channel->assertUsableUrl($url);

        return false;
    } catch (RuntimeException) {
        return true;
    }
}

test('the webhook URL must be https', function (): void {
    $channel = new TeamsWebhookChannel(allowPrivateTargets: true);

    assertTrue(urlRejected($channel, 'http://prod-01.westeurope.logic.azure.com/workflows/x'));
    assertTrue(urlRejected($channel, 'file:///etc/passwd'));
    assertTrue(urlRejected($channel, 'not a url'));
    assertFalse(urlRejected($channel, 'https://prod-01.westeurope.logic.azure.com/workflows/x'));
});

test('a URL pointing into the internal network is refused', function (): void {
    // The webhook URL is admin-supplied and this process can reach the whole
    // internal network; without this check LogWarden is a request proxy into it.
    $channel = new TeamsWebhookChannel();

    assertTrue(urlRejected($channel, 'https://127.0.0.1/hook'));
    assertTrue(urlRejected($channel, 'https://10.1.2.3/hook'));
    assertTrue(urlRejected($channel, 'https://192.168.1.50/hook'));
    assertTrue(urlRejected($channel, 'https://169.254.169.254/latest/meta-data'));
    assertTrue(urlRejected($channel, 'https://[::1]/hook'));
});

test('an internal relay is allowed once explicitly enabled', function (): void {
    assertFalse(urlRejected(new TeamsWebhookChannel(allowPrivateTargets: true), 'https://10.1.2.3/hook'));
});

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Stands in for the Teams transport so the dispatcher's decisions can be
 * tested without a network.
 */
final class FakeChannel implements ChannelInterface
{
    /** @var list<array{alert:int, channel:int}> */
    public array $sent = [];

    /** @param list<NotificationResult> $script */
    public function __construct(private array $script = [])
    {
    }

    public static function type(): string
    {
        return 'teams_workflow';
    }

    public function send(array $alert, array $channel, array $branding, string $secret): NotificationResult
    {
        $this->sent[] = ['alert' => (int) $alert['id'], 'channel' => (int) $channel['id']];

        return array_shift($this->script) ?? NotificationResult::ok(202, 12, 900);
    }

    public function sendTest(array $channel, array $branding, string $secret): NotificationResult
    {
        return NotificationResult::ok(202, 5, 400);
    }
}

const NT_PREFIX = 'notifytest-';

function notifyCleanup(Db $db): void
{
    $db->execute('DELETE FROM notification_log WHERE channel_id IN (SELECT id FROM notification_channels WHERE name LIKE ?)', [NT_PREFIX . '%']);
    $db->execute('DELETE FROM rule_channels WHERE channel_id IN (SELECT id FROM notification_channels WHERE name LIKE ?)', [NT_PREFIX . '%']);
    $db->execute('DELETE FROM notification_channels WHERE name LIKE ?', [NT_PREFIX . '%']);
    $db->execute('DELETE FROM alert_events WHERE alert_id IN (SELECT id FROM alerts WHERE dedup_key LIKE ?)', [NT_PREFIX . '%']);
    $db->execute('DELETE FROM alerts WHERE dedup_key LIKE ?', [NT_PREFIX . '%']);
    $db->execute('DELETE FROM rules WHERE name LIKE ?', [NT_PREFIX . '%']);
    $db->execute('DELETE FROM secrets WHERE ref_name LIKE ?', [NT_PREFIX . '%']);
}

/** How many of a channel's sends were for this alert. */
function sentFor(FakeChannel $channel, int $alertId): int
{
    return count(array_filter($channel->sent, static fn (array $s): bool => $s['alert'] === $alertId));
}

/** Delivery log rows recorded for this alert. */
function logRowsFor(Db $db, int $alertId): int
{
    return (int) $db->fetchValue('SELECT count(*) FROM notification_log WHERE alert_id = ?', [$alertId]);
}

/** @return array{alert:int, channel:int, rule:int} */
function notifyFixture(Db $db, SecretBox $secrets, int $severity = 5, int $minSeverity = 1, int $cooldown = 900): array
{
    // Its own rule, so pre-existing alerts in the database do not route
    // through the test channel. A production database is never empty either.
    $ruleId = (int) $db->fetchValue(
        "INSERT INTO rules (name, rule_key, severity, window_minutes, cooldown_s, enabled)
         VALUES (?, 'failed_login_burst', 3, 10, ?, false) RETURNING id",
        [NT_PREFIX . 'rule', $cooldown],
    );

    $secrets->put(NT_PREFIX . 'hook', 'https://prod-01.westeurope.logic.azure.com/workflows/test');

    $channelId = (int) $db->fetchValue(
        "INSERT INTO notification_channels (name, type, secret_ref, enabled, min_severity)
         VALUES (?, 'teams_workflow', ?, true, ?) RETURNING id",
        [NT_PREFIX . 'soc', NT_PREFIX . 'hook', $minSeverity],
    );

    $db->execute('INSERT INTO rule_channels (rule_id, channel_id) VALUES (?, ?)', [$ruleId, $channelId]);

    $alertId = (int) $db->fetchValue(
        "INSERT INTO alerts (rule_id, window_start, window_end, severity, dedup_key,
                             title, summary, event_count, evidence)
         VALUES (?, now() - interval '10 minutes', now(), ?, ?, 'Test-Alert', 'Zusammenfassung', 5, '{}'::jsonb)
         RETURNING id",
        [$ruleId, $severity, NT_PREFIX . 'alert'],
    );

    return ['alert' => $alertId, 'channel' => $channelId, 'rule' => $ruleId];
}

function makeDispatcher(Db $db, SecretBox $secrets, FakeChannel $channel): Dispatcher
{
    return new Dispatcher(
        $db,
        $secrets,
        ChannelFactory::withChannels(['teams_workflow' => $channel]),
        new AlertRepository($db),
        new Logger(null, 'error', false),
        ['product_name' => 'LogWarden'],
    );
}

function notifySkip(): bool
{
    if (ruleDb() === null || !is_file(LW_ROOT . '/config/test-secret.key')) {
        assertTrue(true, 'skipped: needs LW_TEST_DSN and config/test-secret.key');

        return true;
    }

    return false;
}

function notifySecrets(Db $db): SecretBox
{
    return SecretBox::open(LW_ROOT . '/config/test-secret.key', $db);
}

test('an open alert is delivered to its routed channel exactly once per cooldown', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $ids     = notifyFixture($db, $secrets);
    $channel = new FakeChannel();

    makeDispatcher($db, $secrets, $channel)->run();
    makeDispatcher($db, $secrets, $channel)->run();

    assertSame(1, sentFor($channel, $ids['alert']), 'the cooldown suppresses the second run');
    assertSame(1, logRowsFor($db, $ids['alert']));

    assertFalse(
        null === $db->fetchValue('SELECT notified_at FROM alerts WHERE id = ?', [$ids['alert']]),
        'the alert records that it was delivered',
    );

    notifyCleanup($db);
});

test('a channel below the severity threshold is not used', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $ids     = notifyFixture($db, $secrets, severity: 3, minSeverity: 5);
    $channel = new FakeChannel();

    $stats = makeDispatcher($db, $secrets, $channel)->run();

    assertSame(0, sentFor($channel, $ids['alert']));
    assertSame(0, logRowsFor($db, $ids['alert']));
    assertTrue($stats['unrouted'] >= 1, 'an alert with no matching channel is counted, not silently ignored');

    notifyCleanup($db);
});

test('a failed delivery is retried only after its backoff', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $ids     = notifyFixture($db, $secrets);

    $channel = new FakeChannel([NotificationResult::failed(503, 'HTTP 503')]);
    makeDispatcher($db, $secrets, $channel)->run();

    assertSame(1, sentFor($channel, $ids['alert']));
    assertSame(1, (int) $db->fetchValue(
        'SELECT attempt FROM notification_log WHERE alert_id = ? ORDER BY sent_at DESC LIMIT 1',
        [$ids['alert']],
    ));

    // Immediately afterwards the pair is still inside its 60-second backoff.
    $tooSoon = new FakeChannel();
    makeDispatcher($db, $secrets, $tooSoon)->run();
    assertSame(0, sentFor($tooSoon, $ids['alert']));

    // Backdate the attempt past the backoff and it goes out.
    $db->execute("UPDATE notification_log SET sent_at = now() - interval '5 minutes' WHERE alert_id = ?", [$ids['alert']]);

    $retry = new FakeChannel();
    makeDispatcher($db, $secrets, $retry)->run();
    assertSame(1, sentFor($retry, $ids['alert']));

    notifyCleanup($db);
});

test('a rejected payload is not retried at all', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $ids     = notifyFixture($db, $secrets);

    // HTTP 400 means Teams will reject it again the same way; burning five
    // attempts on it only delays the alerts behind it.
    $channel = new FakeChannel([NotificationResult::failed(400, 'HTTP 400: Bad payload', retryable: false)]);
    makeDispatcher($db, $secrets, $channel)->run();

    assertSame(5, (int) $db->fetchValue(
        'SELECT attempt FROM notification_log WHERE alert_id = ? ORDER BY sent_at DESC LIMIT 1',
        [$ids['alert']],
    ), 'a non-retryable failure is stored at the attempt ceiling');

    $db->execute("UPDATE notification_log SET sent_at = now() - interval '2 hours' WHERE alert_id = ?", [$ids['alert']]);

    $later = new FakeChannel();
    makeDispatcher($db, $secrets, $later)->run();
    assertCount(0, $later->sent, 'even long afterwards it is not retried');

    notifyCleanup($db);
});

test('channel health reflects the last delivery', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $ids     = notifyFixture($db, $secrets);

    makeDispatcher($db, $secrets, new FakeChannel([NotificationResult::failed(500, 'HTTP 500')]))->run();

    $row = $db->fetchRow('SELECT sent_total, failed_total, last_error FROM notification_channels WHERE id = ?', [$ids['channel']]);
    assertSame(1, (int) $row['failed_total']);
    assertSame('HTTP 500', $row['last_error']);

    $db->execute("UPDATE notification_log SET sent_at = now() - interval '5 minutes' WHERE alert_id = ?", [$ids['alert']]);
    makeDispatcher($db, $secrets, new FakeChannel())->run();

    $row = $db->fetchRow('SELECT sent_total, failed_total, last_error FROM notification_channels WHERE id = ?', [$ids['channel']]);
    assertSame(1, (int) $row['sent_total']);
    assertNull($row['last_error'], 'a success clears the error so the UI does not show a stale one');

    notifyCleanup($db);
});

test('an acknowledged alert is no longer delivered', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $ids     = notifyFixture($db, $secrets);
    $db->execute("UPDATE alerts SET status = 'ack' WHERE id = ?", [$ids['alert']]);

    $channel = new FakeChannel();
    makeDispatcher($db, $secrets, $channel)->run();

    assertSame(0, sentFor($channel, $ids['alert']));
    assertSame(0, logRowsFor($db, $ids['alert']));

    notifyCleanup($db);
});

test('a channel without a stored webhook fails loudly instead of silently', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $ids     = notifyFixture($db, $secrets);
    $db->execute('UPDATE notification_channels SET secret_ref = NULL WHERE id = ?', [$ids['channel']]);

    makeDispatcher($db, $secrets, new FakeChannel())->run();

    assertSame(1, logRowsFor($db, $ids['alert']));
    assertTrue(str_contains(
        (string) $db->fetchValue('SELECT error FROM notification_log WHERE alert_id = ?', [$ids['alert']]),
        'keine Webhook-URL',
    ));

    notifyCleanup($db);
});

// ---------------------------------------------------------------------------
// Binary round-trip
// ---------------------------------------------------------------------------

test('secrets survive a round trip through bytea', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    // Regression: ciphertext is not valid UTF-8, and PDO sends a bound string
    // as text, so PostgreSQL rejected the insert outright. Every secret in the
    // system goes through this path.
    $secrets = notifySecrets($db);
    $url     = 'https://prod-01.westeurope.logic.azure.com/workflows/abc?sig=' . str_repeat('x', 40);

    $secrets->put(NT_PREFIX . 'roundtrip', $url);
    assertSame($url, $secrets->get(NT_PREFIX . 'roundtrip'));

    // Repeat: a fresh nonce each time means a different byte pattern, and one
    // lucky run proves nothing.
    for ($i = 0; $i < 20; $i++) {
        $value = random_bytes(64);
        $secrets->put(NT_PREFIX . 'bin', $value);
        assertSame(bin2hex($value), bin2hex((string) $secrets->get(NT_PREFIX . 'bin')));
    }

    assertNull($secrets->get(NT_PREFIX . 'missing'));

    notifyCleanup($db);
});

test('a tampered secret is rejected rather than returned', function (): void {
    if (notifySkip()) { return; }
    $db = ruleDb();
    notifyCleanup($db);

    $secrets = notifySecrets($db);
    $secrets->put(NT_PREFIX . 'tamper', 'https://example.invalid/original');

    // Authenticated encryption earns its keep here: someone with write access
    // to the table must not be able to redirect alerts silently.
    $db->execute(
        "UPDATE secrets SET ciphertext = decode(?, 'hex') WHERE ref_name = ?",
        [bin2hex(random_bytes(64)), NT_PREFIX . 'tamper'],
    );

    $thrown = false;
    try {
        $secrets->get(NT_PREFIX . 'tamper');
    } catch (RuntimeException) {
        $thrown = true;
    }

    assertTrue($thrown);

    notifyCleanup($db);
});
