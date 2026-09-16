<?php

declare(strict_types=1);

use LogWarden\Alerting\AlertRepository;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Rules\AlertCandidate;
use LogWarden\Rules\Builtin\AccountLockout;
use LogWarden\Rules\Builtin\FailedLoginBurst;
use LogWarden\Rules\Builtin\VpnThenAdFail;
use LogWarden\Rules\RuleContext;
use LogWarden\Rules\RuleRegistry;

/**
 * Rule tests run against a live PostgreSQL because the rules *are* SQL — a
 * mocked database would only test the string concatenation. Set LW_TEST_DSN to
 * a throwaway database; these insert and delete rows.
 */

const RT_PREFIX = 'ruletest-';

function ruleDb(): ?Db
{
    static $db = null;

    if ($db === false) {
        return null;
    }

    if ($db === null) {
        $settings = testDbSettings();
        if ($settings === null) {
            $db = false;

            return null;
        }
        $db = new Db($settings);
    }

    return $db;
}

function rtCleanup(Db $db): void
{
    $db->execute('DELETE FROM alert_events WHERE alert_id IN (SELECT id FROM alerts WHERE dedup_key LIKE ?)', [RT_PREFIX . '%']);
    $db->execute('DELETE FROM alerts WHERE dedup_key LIKE ?', [RT_PREFIX . '%']);
    $db->execute('DELETE FROM events WHERE dedup_key LIKE ?', [RT_PREFIX . '%']);
}

/**
 * @param array<string, mixed> $event
 */
function rtEvent(Db $db, int $minutesAgo, array $event): void
{
    static $counter = 0;
    $counter++;

    $db->execute(
        "INSERT INTO events (ts, source_type, source_host, event_type, username, src_ip,
                             result, raw_message, details, dedup_key)
         VALUES (now() - make_interval(mins => ?), ?, ?, ?, ?, ?::inet,
                 ?::event_result_t, ?, ?::jsonb, ?)",
        [
            $minutesAgo,
            $event['source_type'],
            $event['source_host'] ?? 'TEST-HOST',
            $event['event_type'],
            $event['username'] ?? null,
            $event['src_ip'] ?? null,
            $event['result'] ?? 'fail',
            $event['raw_message'] ?? 'test event',
            json_encode($event['details'] ?? []),
            RT_PREFIX . $counter,
        ],
    );
}

function rtContext(Db $db, int $windowMinutes = 30): RuleContext
{
    // Same shape the engine builds: end short of now() by the lag, start a
    // window back from there.
    $end   = new DateTimeImmutable('-60 seconds', new DateTimeZone('UTC'));
    $start = $end->modify("-{$windowMinutes} minutes");

    return new RuleContext($db, $start, $end, new Logger(null, 'error', false));
}

function rtSkip(): bool
{
    if (ruleDb() === null) {
        assertTrue(true, 'skipped: set LW_TEST_DSN to run');

        return true;
    }

    return false;
}

/**
 * Rules evaluate the whole estate, so a test must not assert on the total
 * number of candidates — any other data in the database would change it, and
 * in production there is always other data. Assertions scope to the account
 * the test created.
 *
 * @param list<\LogWarden\Rules\AlertCandidate> $candidates
 * @return list<\LogWarden\Rules\AlertCandidate>
 */
function rtFor(array $candidates, string $username): array
{
    return array_values(array_filter(
        $candidates,
        static fn (AlertCandidate $c): bool => $c->entityUser === $username,
    ));
}

// ---------------------------------------------------------------------------

test('registry discovers the built-in rules by their own key', function (): void {
    $registry = new RuleRegistry([LW_ROOT . '/src/Rules/Builtin']);

    assertTrue($registry->has('failed_login_burst'));
    assertTrue($registry->has('account_lockout'));
    assertTrue($registry->has('vpn_then_ad_fail'));
    assertSame(FailedLoginBurst::class, $registry->map()['failed_login_burst']);
});

test('registry refuses a key it did not discover', function (): void {
    $registry = new RuleRegistry([LW_ROOT . '/src/Rules/Builtin']);
    $thrown   = false;

    try {
        // A rule row is config data; it must never be able to name an
        // arbitrary class for the engine to instantiate.
        $registry->get('LogWarden\\Rules\\Builtin\\..\\..\\Evil');
    } catch (RuntimeException) {
        $thrown = true;
    }

    assertTrue($thrown);
    assertFalse($registry->has('SplFileObject'));
});

test('failed logins are counted across sources', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    // Three at the VPN and three against AD: under threshold on either source
    // alone, over it together. This is the whole point of the rule.
    foreach ([9, 8, 7] as $m) {
        rtEvent($db, $m, ['source_type' => 'ad', 'event_type' => '4625', 'username' => 'rtburst', 'src_ip' => '10.0.0.5']);
    }
    foreach ([6, 5, 4] as $m) {
        rtEvent($db, $m, ['source_type' => 'fortigate_vpn', 'event_type' => 'ssl-login-fail', 'username' => 'rtburst', 'src_ip' => '203.0.113.5']);
    }

    $candidates = rtFor((new FailedLoginBurst())->evaluate(rtContext($db, 10), FailedLoginBurst::defaultParams()), 'rtburst');

    assertCount(1, $candidates);
    assertSame(6, $candidates[0]->eventCount);
    assertSame('rtburst', $candidates[0]->entityUser);
    assertSame(['ad' => 3, 'fortigate_vpn' => 3], $candidates[0]->evidence['by_source']);
    assertSame(5, $candidates[0]->severity, 'more than one source raises the severity');

    rtCleanup($db);
});

test('a count below the threshold raises nothing', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    foreach ([8, 6, 4] as $m) {
        rtEvent($db, $m, ['source_type' => 'ad', 'event_type' => '4625', 'username' => 'rtquiet', 'src_ip' => '10.0.0.6']);
    }

    assertCount(0, rtFor((new FailedLoginBurst())->evaluate(rtContext($db, 10), FailedLoginBurst::defaultParams()), 'rtquiet'));

    rtCleanup($db);
});

test('event types outside the configured list do not count as logon failures', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    // Failed DHCP and DNS events are failures, but they are not logons.
    foreach ([9, 8, 7, 6, 5, 4] as $m) {
        rtEvent($db, $m, ['source_type' => 'ad', 'event_type' => '4634', 'username' => 'rtwrongtype']);
    }

    assertCount(0, rtFor((new FailedLoginBurst())->evaluate(rtContext($db, 10), FailedLoginBurst::defaultParams()), 'rtwrongtype'));

    rtCleanup($db);
});

test('ignored accounts are skipped however loudly they fail', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    foreach (range(2, 10) as $m) {
        rtEvent($db, $m, ['source_type' => 'ad', 'event_type' => '4771', 'username' => 'svc-backup-01']);
    }

    $params = FailedLoginBurst::defaultParams();
    $params['ignore_users'] = ['svc-*'];

    assertCount(0, rtFor((new FailedLoginBurst())->evaluate(rtContext($db, 10), $params), 'svc-backup-01'), 'wildcard ignore must match');
    assertCount(1, rtFor((new FailedLoginBurst())->evaluate(rtContext($db, 10), FailedLoginBurst::defaultParams()), 'svc-backup-01'));

    rtCleanup($db);
});

test('a lockout carries the preceding failures as evidence', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    foreach (range(16, 36, 2) as $m) {
        rtEvent($db, $m, [
            'source_type' => 'ad', 'event_type' => '4625',
            'username' => 'rtlocked', 'src_ip' => '10.20.55.12', 'source_host' => 'DC02',
        ]);
    }
    rtEvent($db, 4, [
        'source_type' => 'ad', 'event_type' => '4740', 'username' => 'rtlocked',
        'result' => 'info', 'source_host' => 'DC02',
        'details' => ['caller_computer' => 'IPHONE-RTLOCKED'],
    ]);

    $candidates = rtFor((new AccountLockout())->evaluate(rtContext($db, 15), AccountLockout::defaultParams()), 'rtlocked');

    assertCount(1, $candidates);
    assertSame('rtlocked', $candidates[0]->entityUser);
    assertSame('IPHONE-RTLOCKED', $candidates[0]->evidence['caller_computer']);
    assertSame(11, $candidates[0]->evidence['preceding_failures']);
    assertSame('10.20.55.12', $candidates[0]->entityIp, 'the dominant origin answers "what locked it"');

    rtCleanup($db);
});

test('a lockout with no recorded failures says so instead of implying none happened', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    rtEvent($db, 3, [
        'source_type' => 'ad', 'event_type' => '4740',
        'username' => 'rtorphan', 'result' => 'info',
    ]);

    $candidates = rtFor((new AccountLockout())->evaluate(rtContext($db, 15), AccountLockout::defaultParams()), 'rtorphan');

    assertCount(1, $candidates);
    assertSame(0, $candidates[0]->evidence['preceding_failures']);
    assertTrue(
        str_contains($candidates[0]->summary, 'noch nicht angebundene Quelle'),
        'the gap in coverage is the finding, and has to be stated',
    );

    rtCleanup($db);
});

test('a VPN login followed by AD failures correlates', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    rtEvent($db, 20, [
        'source_type' => 'fortigate_vpn', 'event_type' => 'tunnel-up',
        'username' => 'rtcorr', 'src_ip' => '198.51.100.203', 'result' => 'success',
    ]);
    foreach ([18, 17, 16, 15] as $m) {
        rtEvent($db, $m, [
            'source_type' => 'ad', 'event_type' => '4625',
            'username' => 'rtcorr', 'src_ip' => '172.16.8.40', 'source_host' => 'FS01',
        ]);
    }

    $candidates = rtFor((new VpnThenAdFail())->evaluate(rtContext($db, 30), VpnThenAdFail::defaultParams()), 'rtcorr');

    assertCount(1, $candidates);
    assertSame(4, $candidates[0]->evidence['ad_failures']);
    assertSame('198.51.100.203', $candidates[0]->entityIp);
    assertTrue(str_starts_with($candidates[0]->dedupKey, 'vpn_then_ad_fail:rtcorr:'));

    rtCleanup($db);
});

test('a VPN login with too few later failures does not correlate', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    rtEvent($db, 22, [
        'source_type' => 'fortigate_vpn', 'event_type' => 'tunnel-up',
        'username' => 'rtquietcorr', 'src_ip' => '198.51.100.9', 'result' => 'success',
    ]);
    rtEvent($db, 19, ['source_type' => 'ad', 'event_type' => '4625', 'username' => 'rtquietcorr']);

    assertCount(0, rtFor((new VpnThenAdFail())->evaluate(rtContext($db, 30), VpnThenAdFail::defaultParams()), 'rtquietcorr'));

    rtCleanup($db);
});

test('AD failures outside the correlation window do not correlate', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    rtEvent($db, 28, [
        'source_type' => 'fortigate_vpn', 'event_type' => 'tunnel-up',
        'username' => 'rtlate', 'src_ip' => '198.51.100.11', 'result' => 'success',
    ]);
    // 13-15 minutes after the login; the default correlation window is 10.
    foreach ([15, 14, 13] as $m) {
        rtEvent($db, $m, ['source_type' => 'ad', 'event_type' => '4625', 'username' => 'rtlate']);
    }

    assertCount(0, rtFor((new VpnThenAdFail())->evaluate(rtContext($db, 30), VpnThenAdFail::defaultParams()), 'rtlate'));

    rtCleanup($db);
});

test('a recurring condition grows the open alert instead of duplicating it', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    $repo  = new AlertRepository($db);
    $start = new DateTimeImmutable('-10 minutes');
    $end   = new DateTimeImmutable('now');

    $ruleId = (int) $db->fetchValue('SELECT id FROM rules ORDER BY id LIMIT 1');

    $first = $repo->record($ruleId, 4, 900, new AlertCandidate(
        dedupKey: RT_PREFIX . 'grow', title: 'Erste Meldung', summary: '5 Fehlschläge', eventCount: 5,
        evidence: ['failures' => 5],
    ), $start, $end);

    $second = $repo->record($ruleId, 4, 900, new AlertCandidate(
        dedupKey: RT_PREFIX . 'grow', title: 'Erste Meldung', summary: '9 Fehlschläge', eventCount: 9,
        evidence: ['failures' => 9],
    ), $start, $end);

    assertSame(AlertRepository::CREATED, $first['action']);
    assertSame(AlertRepository::UPDATED, $second['action']);
    assertSame($first['alert_id'], $second['alert_id']);
    assertSame(1, (int) $db->fetchValue('SELECT count(*) FROM alerts WHERE dedup_key = ?', [RT_PREFIX . 'grow']));

    $row = $db->fetchRow('SELECT event_count, summary, evidence FROM alerts WHERE id = ?', [$first['alert_id']]);
    assertSame(9, (int) $row['event_count']);
    assertSame('9 Fehlschläge', $row['summary']);
    assertSame(2, (int) (json_decode((string) $row['evidence'], true)['evaluations'] ?? 0));

    rtCleanup($db);
});

test('the peak survives even when the current window quietens down', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    $repo   = new AlertRepository($db);
    $start  = new DateTimeImmutable('-10 minutes');
    $end    = new DateTimeImmutable('now');
    $ruleId = (int) $db->fetchValue('SELECT id FROM rules ORDER BY id LIMIT 1');

    foreach ([5, 40, 6] as $count) {
        $repo->record($ruleId, 4, 900, new AlertCandidate(
            dedupKey: RT_PREFIX . 'peak', title: 'Peak', summary: "{$count}", eventCount: $count,
        ), $start, $end);
    }

    $row = $db->fetchRow('SELECT event_count, evidence FROM alerts WHERE dedup_key = ?', [RT_PREFIX . 'peak']);

    assertSame(6, (int) $row['event_count'], 'event_count shows the current window');
    assertSame(40, (int) (json_decode((string) $row['evidence'], true)['peak_count'] ?? 0), 'the peak says how bad it got');

    rtCleanup($db);
});

test('a condition recurring after acknowledgement opens a fresh alert', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    $repo   = new AlertRepository($db);
    $start  = new DateTimeImmutable('-10 minutes');
    $end    = new DateTimeImmutable('now');
    $ruleId = (int) $db->fetchValue('SELECT id FROM rules ORDER BY id LIMIT 1');

    $candidate = new AlertCandidate(
        dedupKey: RT_PREFIX . 'reopen', title: 'Wiederkehrend', summary: 'x', eventCount: 5,
    );

    $first = $repo->record($ruleId, 4, 900, $candidate, $start, $end);
    $db->execute("UPDATE alerts SET status = 'ack', ack_at = now() WHERE id = ?", [$first['alert_id']]);
    $second = $repo->record($ruleId, 4, 900, $candidate, $start, $end);

    assertSame(AlertRepository::CREATED, $second['action']);
    assertFalse($first['alert_id'] === $second['alert_id']);
    assertSame(2, (int) $db->fetchValue('SELECT count(*) FROM alerts WHERE dedup_key = ?', [RT_PREFIX . 'reopen']));

    rtCleanup($db);
});

test('the cooldown governs renotification, not alert creation', function (): void {
    if (rtSkip()) { return; }
    $db = ruleDb();
    rtCleanup($db);

    $repo   = new AlertRepository($db);
    $start  = new DateTimeImmutable('-10 minutes');
    $end    = new DateTimeImmutable('now');
    $ruleId = (int) $db->fetchValue('SELECT id FROM rules ORDER BY id LIMIT 1');

    $candidate = new AlertCandidate(
        dedupKey: RT_PREFIX . 'cooldown', title: 'Cooldown', summary: 'x', eventCount: 5,
    );

    $created = $repo->record($ruleId, 4, 900, $candidate, $start, $end);
    assertTrue($created['notify'], 'a new alert always notifies');

    $repo->markNotified($created['alert_id']);
    assertFalse($repo->record($ruleId, 4, 900, $candidate, $start, $end)['notify'], 'within the cooldown it stays quiet');

    $db->execute("UPDATE alerts SET notified_at = now() - interval '20 minutes' WHERE id = ?", [$created['alert_id']]);
    assertTrue($repo->record($ruleId, 4, 900, $candidate, $start, $end)['notify'], 'after the cooldown it speaks again');

    rtCleanup($db);
});
