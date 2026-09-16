<?php

declare(strict_types=1);

use LogWarden\Core\Logger;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\EventWriter;
use LogWarden\Ingest\Dhcp\DhcpCsvParser;
use LogWarden\Ingest\Dhcp\DhcpEventCatalog;
use LogWarden\Ingest\Dhcp\DhcpNormalizer;
use LogWarden\Ingest\SourceRepository;
use LogWarden\Ingest\Winrm\DhcpLogQuery;
use LogWarden\Ingest\Winrm\WinrmCollector;

function dhcpParser(): DhcpCsvParser
{
    foreach (fixtureRaw('dhcp-srvlog.log') as $line) {
        if (DhcpCsvParser::isHeaderRow($line)) {
            return DhcpCsvParser::fromHeaderLine($line);
        }
    }

    throw new RuntimeException('fixture has no header row');
}

/** @return list<string> Every line, prose included — the parser has to cope. */
function fixtureRaw(string $name): array
{
    return array_map('rtrim', explode("\n", fixture($name)));
}

function dhcpEvent(string $id): Event
{
    $normalizer = new DhcpNormalizer('DHCP01.corp.local', dhcpParser());

    foreach (fixtureRaw('dhcp-srvlog.log') as $line) {
        if (preg_match('/^' . preg_quote(ltrim($id, '0') ?: '0', '/') . ',/', $line) !== 1
            && !str_starts_with($line, $id . ',')) {
            continue;
        }

        $events = $normalizer->normalize($line);

        if ($events !== []) {
            return $events[0];
        }
    }

    throw new RuntimeException('no event for id ' . $id);
}

// ---------------------------------------------------------------------------
// The file is not plain CSV
// ---------------------------------------------------------------------------

test('the documentation block at the top is not mistaken for data', function (): void {
    // Those lines begin with a number too — "10  A new IP address was leased" —
    // so "starts with digits" would have swallowed the whole header.
    $parser = dhcpParser();
    $prose  = 0;

    foreach (fixtureRaw('dhcp-srvlog.log') as $line) {
        if ($line === '' || DhcpCsvParser::isHeaderRow($line)) {
            continue;
        }

        if (!DhcpCsvParser::isDataRow($line)) {
            $prose++;
            assertNull($parser->parse($line), 'prose parsed as data: ' . $line);
        }
    }

    assertTrue($prose > 15, 'the fixture really does carry the header block');
});

test('the columns come from the file, not from a fixed list', function (): void {
    // Server 2008 wrote eleven columns, 2016 writes nineteen. Parsing by
    // position against one fixed list shifts every field on the other.
    $old = DhcpCsvParser::fromHeaderLine('ID,Date,Time,Description,IP Address,Host Name,MAC Address');
    $row = $old->parse('10,09/16/26,08:14:22,Assign,10.20.30.44,WS-ASMITH,A0B1C2D3E4F5');

    assertSame('WS-ASMITH', $row['Host Name']);
    assertSame('A0B1C2D3E4F5', $row['MAC Address']);

    assertCount(19, DhcpCsvParser::DEFAULT_COLUMNS);
});

test('a header row is recognised by its first three columns only', function (): void {
    assertTrue(DhcpCsvParser::isHeaderRow('ID,Date,Time,Description,IP Address'));
    assertTrue(DhcpCsvParser::isHeaderRow('ID,Date,Time,Description,IP Address,Host Name,Something,New'));
    assertFalse(DhcpCsvParser::isHeaderRow('10,09/16/26,08:14:22,Assign'));
    assertFalse(DhcpCsvParser::isHeaderRow(''));
});

// ---------------------------------------------------------------------------
// Attribution is the point
// ---------------------------------------------------------------------------

test('a lease ties an address to a host and a MAC', function (): void {
    // Three weeks later a firewall log says 10.20.30.44 did something, and
    // this is the only record that can still say which machine that was.
    $event = dhcpEvent('10');

    assertSame('dhcp', $event->sourceType->value);
    assertSame('10.20.30.44', $event->srcIp, 'the leased address goes in src_ip, where a search looks');
    assertSame('WS-ASMITH.corp.local', $event->details['hostname']);
    assertSame('A0-B1-C2-D3-E4-F5', $event->details['mac']);
    assertSame('A0-B1-C2', $event->details['mac_oui'], 'the vendor prefix is kept separately');
    assertSame(EventResult::Success, $event->result);
});

test('a MAC is normalised however the server wrote it', function (): void {
    $parser     = dhcpParser();
    $normalizer = new DhcpNormalizer('DHCP01.corp.local', $parser);

    $colons = $normalizer->normalize('10,09/16/26,10:01:00,Assign,10.20.30.77,WS-PWEBER,C8:1A:2B:3C:4D:5E,,1,0')[0];
    $bare   = $normalizer->normalize('10,09/16/26,10:02:00,Assign,10.20.30.78,WS-X,C81A2B3C4D5F,,1,0')[0];

    assertSame('C8-1A-2B-3C-4D-5E', $colons->details['mac']);
    assertSame('C8-1A-2B-3C-4D-5F', $bare->details['mac']);
});

test('the events with no lease still read as sentences', function (): void {
    assertTrue(str_contains(dhcpEvent('14')->rawMessage, 'Adresspool erschöpft'));
    assertTrue(str_contains(dhcpEvent('54')->rawMessage, 'Autorisierung fehlgeschlagen'));
    assertNull(dhcpEvent('54')->srcIp);
});

test('a rogue DHCP server is a failure, not a note', function (): void {
    // 54, 56 and 62 are the security-relevant part of this channel: they say
    // somebody else is handing out addresses.
    foreach (['54', '62'] as $id) {
        assertSame(EventResult::Fail, dhcpEvent($id)->result, $id);
        assertSame('rogue', dhcpEvent($id)->details['category']);
    }
});

test('an unknown id keeps the description the server itself wrote', function (): void {
    // Unlike the DNS and AD channels, every DHCP row carries Microsoft's own
    // wording — so an id the catalogue misses still arrives readable.
    $event = dhcpEvent('99');

    assertSame('99', $event->eventType);
    assertSame('Etwas ganz Neues', $event->details['label']);
});

test('single-digit ids are padded so that 0 and 00 are the same event', function (): void {
    assertTrue(DhcpEventCatalog::knows('0'));
    assertTrue(DhcpEventCatalog::knows('00'));
    assertSame('Protokoll gestartet', DhcpEventCatalog::describe('0')['label']);
});

// ---------------------------------------------------------------------------
// The date trap
// ---------------------------------------------------------------------------

test('an ISO timestamp from the server wins over the local date columns', function (): void {
    // The server resolved it with its own culture; that beats anything this
    // end could infer.
    $line  = '10,05/06/26,08:00:00,Assign,10.0.0.5,HOST,001122334455,,1,0';
    $event = (new DhcpNormalizer('DHCP01.corp.local', dhcpParser()))->normalize(json_encode([
        'l' => $line,
        't' => '2026-06-05T06:00:00.0000000Z',
        'c' => 'DHCP02.corp.local',
    ]))[0];

    assertSame('2026-06-05 06:00:00', $event->ts->format('Y-m-d H:i:s'));
    assertSame('DHCP02.corp.local', $event->sourceHost, 'and the host comes from the envelope too');
});

test('an unambiguous local date is still readable both ways round', function (): void {
    $normalizer = new DhcpNormalizer('DHCP01.corp.local', dhcpParser());

    $us = $normalizer->normalize('10,09/16/26,08:00:00,Assign,10.0.0.5,HOST,001122334455,,1,0')[0];
    $de = $normalizer->normalize('10,16.09.26,08:00:00,Assign,10.0.0.6,HOST,001122334456,,1,0')[0];

    $iso = $normalizer->normalize('10,2026-09-16,08:00:00,Assign,10.0.0.7,HOST,001122334457,,1,0')[0];

    assertSame('2026-09-16', $us->ts->format('Y-m-d'));
    assertSame('2026-09-16', $de->ts->format('Y-m-d'), 'German short date, same day');
    assertSame('2026-09-16', $iso->ts->format('Y-m-d'), 'ISO short date, same day');
});

test('an ambiguous local date is refused rather than guessed', function (): void {
    // 05/06/26 is the fifth of June or the sixth of May depending on the
    // install. Putting it on the wrong day for half the year would be worse
    // than losing the record, because nothing about it would look wrong.
    $events = (new DhcpNormalizer('DHCP01.corp.local', dhcpParser()))
        ->normalize('10,05/06/26,08:00:00,Assign,10.0.0.5,HOST,001122334455,,1,0');

    assertCount(0, $events);
});

// ---------------------------------------------------------------------------
// Filtering and identity
// ---------------------------------------------------------------------------

test('the id filter keeps 00 rather than turning it into zero', function (): void {
    $normalizer = new DhcpNormalizer('DHCP01.corp.local', dhcpParser(), ['00', '54']);

    assertCount(1, $normalizer->normalize('00,09/16/26,00:00:03,Started,,,,,0,0'));
    assertCount(0, $normalizer->normalize('10,09/16/26,08:14:22,Assign,10.0.0.5,HOST,001122334455,,1,0'));
});

test('the volume ids are named, and still on by default', function (): void {
    // They are the bulk of the file and the reason to collect it at all, so
    // they stay on — but they are the first thing to switch off.
    assertTrue(in_array('10', DhcpEventCatalog::highVolumeIds(), true));
    assertTrue(in_array('11', DhcpEventCatalog::highVolumeIds(), true));
    assertTrue(in_array('10', DhcpEventCatalog::defaultIds(), true));
    assertTrue(in_array('54', DhcpEventCatalog::defaultIds(), true));
    assertFalse(in_array('32', DhcpEventCatalog::defaultIds(), true), 'successful DNS updates are noise');

    // Every id comes back as a two-character string. PHP turns a
    // numeric-looking array key into an integer, and a mixed list silently
    // fails every strict comparison downstream — including the one that ticks
    // the boxes on the settings page.
    foreach (DhcpEventCatalog::defaultIds() as $id) {
        assertSame(2, strlen($id), var_export($id, true));
        assertTrue(is_string($id), var_export($id, true));
    }
});

test('the same line read twice produces the same identity', function (): void {
    $line  = '11,09/16/26,08:44:19,Renew,10.20.30.44,WS-ASMITH,A0B1C2D3E4F5,,1,0';
    $first = (new DhcpNormalizer('DHCP01.corp.local', dhcpParser()))->normalize($line)[0];
    $again = (new DhcpNormalizer('DHCP01.corp.local', dhcpParser()))->normalize($line)[0];

    assertSame($first->dedupKey, $again->dedupKey, 'overlapping windows stay free');

    $other = (new DhcpNormalizer('DHCP02.corp.local', dhcpParser()))->normalize($line)[0];
    assertTrue($first->dedupKey !== $other->dedupKey, 'two servers are two records');
});

test('malformed input produces no event', function (): void {
    $normalizer = new DhcpNormalizer('DHCP01.corp.local', dhcpParser());

    foreach (['', '   ', 'nur Text', '{}', '{"l":123}', ',,,', '10,', 'ID,Date,Time'] as $input) {
        assertCount(0, $normalizer->normalize($input), var_export($input, true));
    }
});

// ---------------------------------------------------------------------------
// The query built for the server
// ---------------------------------------------------------------------------

test('the query enumerates the directory instead of computing file names', function (): void {
    $script = (new DhcpLogQuery())->script(new DateTimeImmutable('-1 hour'), new DateTimeImmutable('now'));

    // The weekday in DhcpSrvLog-Mon.log is localised — "Mo" on a German
    // install — so a computed name works in a lab and fails in half of Europe.
    assertTrue(str_contains($script, "Filter 'DhcpSrvLog-*.log'"));
    assertTrue(str_contains($script, 'LastWriteTimeUtc'));
    assertFalse(str_contains($script, 'DhcpSrvLog-Mon'), 'no computed weekday');
});

test('the query resolves dates where the culture is known', function (): void {
    $script = (new DhcpLogQuery())->script(new DateTimeImmutable('-1 hour'), new DateTimeImmutable('now'));

    assertTrue(str_contains($script, 'CurrentCulture'), 'the server parses its own date format');
    assertTrue(str_contains($script, 'ToUniversalTime'));
    assertTrue(str_contains($script, 'ANSICodePage'), 'and reads the file as ANSI, not UTF-8');
});

test('the log path cannot break out of the PowerShell literal', function (): void {
    $script = (new DhcpLogQuery("C:\\dhcp'; Remove-Item C:\\ -Recurse #"))
        ->script(new DateTimeImmutable('-1 hour'), new DateTimeImmutable('now'));

    assertTrue(str_contains($script, "'C:\\dhcp''; Remove-Item C:\\ -Recurse #'"), 'quote doubled');
});

test('the IPv6 log is a different file pattern', function (): void {
    $script = (new DhcpLogQuery(DhcpLogQuery::DEFAULT_PATH, [], 1000, true))
        ->script(new DateTimeImmutable('-1 hour'), new DateTimeImmutable('now'));

    assertTrue(str_contains($script, 'DhcpV6SrvLog-*.log'));
});

test('the header script asks the server for its own event-id list', function (): void {
    // The DHCP server documents its ids in the top of every file it writes,
    // which makes this the DHCP counterpart of --discover.
    $script = (new DhcpLogQuery())->headerScript();

    assertTrue(str_contains($script, 'Sort-Object LastWriteTimeUtc -Descending'));
    assertTrue(str_contains($script, "^ID,"), 'stops at the column header');
});

// ---------------------------------------------------------------------------
// Through the collector
// ---------------------------------------------------------------------------

test('a DHCP source collects over the same transport and bookmark', function (): void {
    if (winrmSkip() || winrmDbSkip()) {
        return;
    }

    $db = ruleDb();
    dhcpCleanup($db);

    $repo = new SourceRepository($db);
    $id   = $repo->upsert([
        'name'            => 'dhcptest-audit',
        'collector'       => 'dhcp_csv',
        'source_type'     => 'dhcp',
        'target_host'     => 'dhcptest-srv',
        'enabled'         => true,
        'username'        => 'CORP\\svc',
        'auth_mode'       => 'ntlm',
        'poll_interval_s' => 900,
        'config'          => [
            'log_path'         => 'C:\\Windows\\System32\\dhcp',
            'event_ids'        => ['10', '11', '54'],
            'path'             => '/wsman',
            'window_seconds'   => 86400,
            'initial_lookback' => 172800,
            'lag_seconds'      => 0,
        ],
    ]);

    $writer    = new EventWriter($db, new Logger(null, 'error', false), 500, 1.0, null);
    $collector = new WinrmCollector($writer, new Logger(null, 'error', false));

    $result = $collector->collect($repo->find($id), winrmFactory(), new DateTimeImmutable('2026-09-16T12:00:00Z'));

    assertSame('ok', $result['status']);
    assertSame(12, $result['fetched'], 'the mock answered with the audit log');
    assertSame(4, $result['stored'], 'only the three requested ids, one of them twice');
    assertSame(8, $result['skipped']);

    $row = $db->query(
        "SELECT raw_message, details->>'mac' AS mac FROM events
          WHERE source_type = 'dhcp' AND source_host = 'DHCP01.corp.local' AND event_type = '10'
          ORDER BY ts LIMIT 1",
    )->fetch();

    assertTrue($row !== false, 'a lease was stored');
    assertSame('A0-B1-C2-D3-E4-F5', $row['mac'], 'the column header from the stream was applied');

    dhcpCleanup($db);
});

function dhcpCleanup(LogWarden\Core\Db $db): void
{
    $db->execute("DELETE FROM events WHERE source_type = 'dhcp' AND source_host IN ('DHCP01.corp.local', 'dhcptest-srv')");
    $db->execute("DELETE FROM ingest_sources WHERE name LIKE 'dhcptest-%'");
}
