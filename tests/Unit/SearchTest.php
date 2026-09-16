<?php

declare(strict_types=1);

use LogWarden\Core\Db;
use LogWarden\Search\EventQuery;
use LogWarden\Search\SearchCriteria;

// ---------------------------------------------------------------------------
// SearchCriteria
// ---------------------------------------------------------------------------

test('a preset resolves to a time window ending now', function (): void {
    $c = SearchCriteria::fromArray(['preset' => '1h']);

    assertSame('1h', $c->preset);
    $span = $c->to->getTimestamp() - $c->from->getTimestamp();
    assertTrue($span >= 3599 && $span <= 3601, "expected about an hour, got {$span}s");
});

test('an unknown preset falls back rather than producing an empty window', function (): void {
    assertSame('24h', SearchCriteria::fromArray(['preset' => 'letzte-woche-vielleicht'])->preset);
    assertSame(100, SearchCriteria::fromArray(['limit' => '999999'])->limit);
    assertNull(SearchCriteria::fromArray(['result' => 'maybe'])->result);
    assertSame('any', SearchCriteria::fromArray(['ipfield' => 'somewhere'])->ipField);
});

test('a reversed custom range is swapped, not left empty', function (): void {
    // Typing the dates the wrong way round returns nothing, which reads as a
    // bug rather than as the typo it is.
    $c = SearchCriteria::fromArray([
        'preset' => 'custom',
        'from'   => '2026-09-16T12:00',
        'to'     => '2026-09-15T12:00',
    ]);

    assertTrue($c->from < $c->to);
    assertSame('2026-09-15T12:00', $c->from->format('Y-m-d\TH:i'));
});

test('unknown source types are discarded', function (): void {
    $c = SearchCriteria::fromArray(['source' => ['ad', 'mainframe', 'fortigate_vpn']]);

    assertSame(['ad', 'fortigate_vpn'], $c->sourceTypes);
});

test('a search round-trips through its query string', function (): void {
    $original = SearchCriteria::fromArray([
        'preset'   => '7d',
        'username' => 'jdoe',
        'ip'       => '10.0.0.0/8',
        'ipfield'  => 'src',
        'result'   => 'fail',
        'source'   => ['ad'],
        'q'        => 'tunnel up',
    ]);

    parse_str($original->toQueryString(), $params);
    $restored = SearchCriteria::fromArray($params);

    assertSame('jdoe', $restored->username);
    assertSame('10.0.0.0/8', $restored->ip);
    assertSame('src', $restored->ipField);
    assertSame('fail', $restored->result);
    assertSame(['ad'], $restored->sourceTypes);
    assertSame('tunnel up', $restored->query);
    assertSame('7d', $restored->preset);
});

test('a filter can be dropped from the query string', function (): void {
    $c = SearchCriteria::fromArray(['username' => 'jdoe', 'result' => 'fail']);

    parse_str($c->toQueryString(['username' => null]), $params);
    $without = SearchCriteria::fromArray($params);

    assertNull($without->username);
    assertSame('fail', $without->result);
});

test('active filters are listed for display, the time range is not one', function (): void {
    assertTrue(SearchCriteria::fromArray(['preset' => '7d'])->isEmpty());
    assertCount(0, SearchCriteria::fromArray(['preset' => '7d'])->activeFilters());

    $filters = SearchCriteria::fromArray(['username' => 'jdoe', 'source' => ['ad']])->activeFilters();
    assertCount(2, $filters);
    assertSame('source', $filters[0]['key']);
    assertSame('Active Directory', $filters[0]['value']);
});

// ---------------------------------------------------------------------------
// EventQuery
// ---------------------------------------------------------------------------

const SQ_PREFIX = 'searchtest-';

function searchCleanup(Db $db): void
{
    $db->execute('DELETE FROM events WHERE dedup_key LIKE ?', [SQ_PREFIX . '%']);
}

/** Events far enough in the past that the bulk fixtures cannot overlap. */
function searchFixture(Db $db): void
{
    searchCleanup($db);

    $rows = [
        // minutes ago, source_type, host, event_type, user, src_ip, dst_ip, result, raw
        [5,  'ad',             'SQ-DC01', '4625',           'sqjdoe',   '10.90.1.10', '10.90.9.1',  'fail',    'An account failed to log on Kennwort falsch'],
        [6,  'ad',             'SQ-DC01', '4624',           'sqjdoe',   '10.90.1.10', '10.90.9.1',  'success', 'An account was successfully logged on'],
        [7,  'fortigate_vpn',  'SQ-FGT',  'ssl-login-fail', 'sqjdoe',   '10.90.2.20', null,         'fail',    'SSL user failed to logged in'],
        [8,  'fortigate_auth', 'SQ-FGT',  'authentication', 'sqasmith', '10.90.2.21', '10.90.9.2',  'success', 'User succeeded in authentication'],
        [9,  'dhcp',           'SQ-DHCP', 'DHCP-ACK',       'sqsvc-x',  '10.90.3.30', null,         'info',    'DHCP lease granted to workstation'],
        [10, 'dns',            'SQ-DNS',  'query',          null,       '10.90.4.40', '10.90.9.53', 'info',    'DNS query for example invalid'],
    ];

    foreach ($rows as $i => [$min, $type, $host, $event, $user, $src, $dst, $result, $raw]) {
        $db->execute(
            "INSERT INTO events (ts, source_type, source_host, event_type, username, src_ip, dst_ip,
                                 result, raw_message, details, dedup_key)
             VALUES (now() - make_interval(mins => ?), ?::source_type_t, ?, ?, ?, ?::inet, ?::inet,
                     ?::event_result_t, ?, '{}'::jsonb, ?)",
            [$min, $type, $host, $event, $user, $src, $dst, $result, $raw, SQ_PREFIX . $i],
        );
    }
}

/**
 * Restrict a search to the fixture rows.
 *
 * A production database is never empty, and neither is this one — the fixture
 * hosts carry an SQ- prefix so nothing else can be mistaken for them.
 */
function searchRows(EventQuery $q, array $params): array
{
    $c    = SearchCriteria::fromArray($params + ['preset' => '1h', 'limit' => 250]);
    $rows = $q->search($c)['rows'];

    return array_values(array_filter(
        $rows,
        static fn (array $r): bool => str_starts_with((string) $r['source_host'], 'SQ-'),
    ));
}

function searchSkip(): bool
{
    if (ruleDb() === null) {
        assertTrue(true, 'skipped: set LW_TEST_DSN to run');

        return true;
    }

    return false;
}

test('an exact account filter matches across sources', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    $rows = searchRows($q, ['username' => 'sqjdoe']);

    assertCount(3, $rows);
    assertSame(['ad', 'ad', 'fortigate_vpn'], array_column($rows, 'source_type'), 'newest first');

    searchCleanup($db);
});

test('a trailing wildcard matches by prefix', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    assertCount(3, searchRows($q, ['username' => 'sqj*']));
    assertCount(1, searchRows($q, ['username' => 'sqa*']));
    assertCount(4, array_merge(searchRows($q, ['username' => 'sqj*']), searchRows($q, ['username' => 'sqa*'])));
    assertCount(1, searchRows($q, ['host' => 'SQ-DHCP*']));

    searchCleanup($db);
});

test('an IP filter searches source and destination, or just one', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    assertCount(1, searchRows($q, ['ip' => '10.90.9.53']), 'only as a destination');
    assertCount(0, searchRows($q, ['ip' => '10.90.9.53', 'ipfield' => 'src']));
    assertCount(1, searchRows($q, ['ip' => '10.90.9.53', 'ipfield' => 'dst']));

    searchCleanup($db);
});

test('a CIDR filter matches the whole network', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    assertCount(6, searchRows($q, ['ip' => '10.90.0.0/16']));
    assertCount(2, searchRows($q, ['ip' => '10.90.1.0/24']), 'two events share the /24 as source');
    assertCount(0, searchRows($q, ['ip' => '192.168.0.0/16']));

    searchCleanup($db);
});

test('filters combine as AND, not OR', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    assertCount(2, searchRows($q, ['username' => 'sqjdoe', 'result' => 'fail']));
    assertCount(1, searchRows($q, ['username' => 'sqjdoe', 'result' => 'fail', 'source' => ['ad']]));
    assertCount(0, searchRows($q, ['username' => 'sqjdoe', 'result' => 'fail', 'source' => ['dhcp']]));

    searchCleanup($db);
});

test('full text searches the original message word by word', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    assertCount(2, searchRows($q, ['q' => 'account']));
    assertCount(1, searchRows($q, ['q' => '"failed to logged"']), 'a quoted phrase matches as a phrase');
    assertCount(1, searchRows($q, ['q' => 'account -successfully']), 'a minus excludes');
    assertCount(0, searchRows($q, ['q' => 'kennwortfalsch']), 'full text is word-based, not substring');

    searchCleanup($db);
});

test('the event time range excludes what falls outside it', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    // The fixture sits 5-10 minutes back, so a 15-minute window sees it all and
    // a window ending an hour ago sees none of it.
    assertCount(6, searchRows($q, ['preset' => '15m']));
    assertCount(0, searchRows($q, [
        'preset' => 'custom',
        'from'   => (new DateTimeImmutable('-3 hours'))->format('Y-m-d\TH:i'),
        'to'     => (new DateTimeImmutable('-2 hours'))->format('Y-m-d\TH:i'),
    ]), 'the fixture is minutes old, so an older window must not see it');

    searchCleanup($db);
});

test('keyset paging returns every row exactly once', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    $seen  = [];
    $cts   = null;
    $cid   = null;
    $pages = 0;

    do {
        $params = ['preset' => '1h', 'ip' => '10.90.0.0/16', 'limit' => 50];
        if ($cts !== null) {
            $params['cts'] = $cts;
            $params['cid'] = $cid;
        }

        $page = $q->search(SearchCriteria::fromArray($params));
        $pages++;

        foreach ($page['rows'] as $row) {
            $key = $row['ts_iso'] . '|' . $row['id'];
            assertFalse(isset($seen[$key]), 'a row must not appear on two pages');
            $seen[$key] = true;
        }

        if ($page['rows'] !== []) {
            $last = $page['rows'][count($page['rows']) - 1];
            $cts  = $last['ts_iso'];
            $cid  = (int) $last['id'];
        }
    } while ($page['hasMore'] && $pages < 20);

    assertSame(6, count($seen));

    searchCleanup($db);
});

test('a single event is fetched by its full key', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    $row   = searchRows($q, ['username' => 'sqjdoe', 'result' => 'fail', 'source' => ['ad']])[0];
    $event = $q->find((string) $row['ts_iso'], (int) $row['id']);

    assertFalse($event === null);
    assertSame('4625', $event['event_type']);
    assertSame('sqjdoe', $event['username']);
    assertNull($q->find((string) $row['ts_iso'], 999_999_999), 'a wrong id finds nothing');

    searchCleanup($db);
});

test('neighbours show what else the account and address did', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    $row   = searchRows($q, ['username' => 'sqjdoe', 'result' => 'fail', 'source' => ['ad']])[0];
    $event = $q->find((string) $row['ts_iso'], (int) $row['id']);

    $neighbours = array_values(array_filter(
        $q->neighbours($event),
        static fn (array $n): bool => str_starts_with((string) $n['source_host'], 'SQ-'),
    ));

    $ids = array_column($neighbours, 'id');
    assertFalse(in_array((int) $event['id'], array_map('intval', $ids), true), 'the event itself is not its own neighbour');
    assertTrue(count($neighbours) >= 2, 'the other two sqjdoe events are found');

    searchCleanup($db);
});

test('the export streams the same rows the search returns', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    $exported = [];
    foreach ($q->export(SearchCriteria::fromArray(['preset' => '1h', 'ip' => '10.90.0.0/16'])) as $row) {
        $exported[] = $row;
    }

    assertCount(6, $exported);
    assertTrue(isset($exported[0]['ts_utc'], $exported[0]['raw_message']));

    searchCleanup($db);
});

test('input that looks like SQL is treated as a value', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    // Every one of these is bound, never interpolated. If any were not, the
    // table would be gone and the next assertion would fail loudly.
    $hostile = "x'; DROP TABLE events; --";

    foreach (['username', 'host', 'event_type', 'q'] as $field) {
        $rows = $q->search(SearchCriteria::fromArray(['preset' => '1h', $field => $hostile]))['rows'];
        assertCount(0, $rows, "{$field} must yield nothing, not an error");
    }

    // The IP field never reaches the database at all: it is validated as an
    // address first, so the filter is dropped rather than cast.
    $c = SearchCriteria::fromArray(['preset' => '1h', 'ip' => $hostile]);
    assertFalse($c->ipValid);
    assertCount(0, searchRows($q, ['ip' => $hostile, 'username' => 'nobody-here']));

    assertCount(6, searchRows($q, ['preset' => '1h']), 'the table is still there');

    searchCleanup($db);
});

test('wildcard metacharacters in a value stay literal', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    // `%` must not act as a wildcard: only `*` does, by design.
    assertCount(0, searchRows($q, ['username' => 'sq%']));
    assertCount(0, searchRows($q, ['username' => '_qjdoe']));
    assertCount(3, searchRows($q, ['username' => 'sq*doe']), 'a wildcard in the middle still works');

    searchCleanup($db);
});

test('an invalid address is flagged rather than sent to the database', function (): void {
    // Passing it through would reach PostgreSQL's inet cast and surface as a
    // 500 for what is really a typo.
    foreach (['keine-ip', '10.0.0.0/99', '999.1.1.1', '10.0.0.1/abc', ''] as $bad) {
        $c = SearchCriteria::fromArray(['ip' => $bad]);
        assertFalse($c->ip !== null && $c->ipValid, "'{$bad}' must not be treated as valid");
    }

    foreach (['203.0.113.9', '10.0.0.0/8', '2001:db8::1', '2001:db8::/32', '10.1.2.3/32'] as $good) {
        assertTrue(SearchCriteria::fromArray(['ip' => $good])->ipValid, "'{$good}' must be accepted");
    }
});

test('an invalid address filter is dropped, not applied as text', function (): void {
    if (searchSkip()) { return; }
    $db = ruleDb();
    searchFixture($db);
    $q = new EventQuery($db);

    // No exception, and the remaining filters still apply.
    $rows = searchRows($q, ['ip' => 'keine-ip', 'username' => 'sqjdoe']);
    assertCount(3, $rows);

    searchCleanup($db);
});

test('the logger works outside the CLI, where STDERR does not exist', function (): void {
    // Regression: referencing the STDERR constant under php-fpm made the
    // logger fatal exactly when it was asked to report an error, so the web
    // error path took the whole request down with it.
    $file = sys_get_temp_dir() . '/lw-logger-' . bin2hex(random_bytes(4)) . '.log';

    $logger = new \LogWarden\Core\Logger($file, 'info', true, 'sapitest');
    $logger->error('Fehlerpfad');

    assertTrue(is_file($file));
    assertTrue(str_contains((string) file_get_contents($file), 'Fehlerpfad'));

    unlink($file);
});
