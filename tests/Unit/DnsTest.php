<?php

declare(strict_types=1);

use LogWarden\Core\Logger;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\EventWriter;
use LogWarden\Ingest\SourceRepository;
use LogWarden\Ingest\Windows\AdNormalizer;
use LogWarden\Ingest\Windows\DnsEventCatalog;
use LogWarden\Ingest\Windows\DnsNormalizer;
use LogWarden\Ingest\Windows\WindowsNormalizerFactory;
use LogWarden\Ingest\Winrm\EventLogQuery;
use LogWarden\Ingest\Winrm\WinrmCollector;

const DNS_AUDIT  = 'Microsoft-Windows-DNSServer/Audit';
const DNS_SERVER = 'DNS Server';

function dnsEvent(int $id, string $channel = DNS_AUDIT, string $fixture = 'dns-audit.ndjson'): Event
{
    foreach (fixtureLines($fixture) as $line) {
        if (str_contains($line, '"i":' . $id . ',')) {
            $events = (new DnsNormalizer('DC01.corp.local', $channel))->normalize($line);

            if ($events === []) {
                throw new RuntimeException('Event ' . $id . ' produced nothing');
            }

            return $events[0];
        }
    }

    throw new RuntimeException('No fixture line for ' . $id);
}

// ---------------------------------------------------------------------------
// Channel detection
// ---------------------------------------------------------------------------

test('the channel decides the normaliser, not the transport', function (): void {
    // Running DNS through AdNormalizer produced "Ereignis 542" with no user:
    // the fields it looks for are simply not in the record.
    $dns = WindowsNormalizerFactory::for(makeSource(['channel' => DNS_AUDIT], 'dns'));
    $ad  = WindowsNormalizerFactory::for(makeSource(['channel' => 'Security'], 'ad'));

    assertTrue($dns instanceof DnsNormalizer);
    assertTrue($ad instanceof AdNormalizer);

    assertTrue(WindowsNormalizerFactory::for(makeSource(['channel' => DNS_SERVER], 'dns')) instanceof DnsNormalizer);
});

test('both DNS channels are recognised, other channels are not', function (): void {
    assertTrue(DnsEventCatalog::isDnsChannel(DNS_AUDIT));
    assertTrue(DnsEventCatalog::isDnsChannel(DNS_SERVER));
    assertTrue(DnsEventCatalog::isAuditChannel(DNS_AUDIT));

    assertFalse(DnsEventCatalog::isAuditChannel(DNS_SERVER), 'the classic log is not the audit channel');
    assertFalse(DnsEventCatalog::isDnsChannel('Security'));
    assertFalse(DnsEventCatalog::isDnsChannel('System'));
});

test('the same id means different things on the two channels', function (): void {
    // 2 is "service started" on the classic log and nothing on the audit
    // channel; sharing one table would have made both wrong.
    assertSame('DNS-Dienst gestartet', DnsEventCatalog::describe(2, DNS_SERVER)['label']);
    assertNull(DnsEventCatalog::describe(2, DNS_AUDIT));
    assertNull(DnsEventCatalog::describe(542, DNS_SERVER));
});

// ---------------------------------------------------------------------------
// The change log
// ---------------------------------------------------------------------------

test('a record change reads as a sentence', function (): void {
    $event = dnsEvent(542);

    assertSame('dns', $event->sourceType->value);
    assertSame('Administrator', $event->username);
    assertSame('corp.local', $event->details['zone']);
    assertSame('ws-asmith.corp.local', $event->details['record']);
    assertSame('A', $event->details['record_type']);
    assertSame('10.20.30.44', $event->details['record_data']);
    assertTrue(str_contains($event->rawMessage, 'Record angelegt ws-asmith.corp.local A 10.20.30.44 in "corp.local" durch Administrator'));
});

test('a configuration change names the new value', function (): void {
    // "Weiterleitungen geändert durch jdoe" tells nobody whether resolution
    // now goes somewhere it should not.
    assertTrue(str_contains(dnsEvent(562)->rawMessage, 'auf 9.9.9.9, 1.1.1.1'));
    assertTrue(str_contains(dnsEvent(522)->rawMessage, 'auf 198.51.100.42'));
});

test('an event without an account falls back to the acting address', function (): void {
    // A dynamic update has no logged-on user; the client address is the only
    // actor there is.
    $event = dnsEvent(544);

    assertNull($event->username);
    assertSame('10.20.30.61', $event->srcIp);
    assertTrue(str_contains($event->rawMessage, 'von 10.20.30.61'));
});

test('the security-relevant changes are marked as such', function (): void {
    foreach ([514, 522, 542, 543, 562] as $id) {
        assertTrue(dnsEvent($id)->details['notable'], $id . ' should be notable');
    }

    assertFalse(dnsEvent(520)->details['notable'], 'a zone write-back is routine');
});

test('an unknown id is stored, not dropped', function (): void {
    // The opposite of the Cisco plugin, and deliberately so: the audit channel
    // is tiny, so dropping an unrecognised change loses exactly the rare event
    // the channel exists for.
    $event = dnsEvent(599);

    assertSame('599', $event->eventType);
    assertSame('DNS-Ereignis 599', $event->details['label']);
    assertSame('Administrator', $event->username);
});

test('routine events can be switched off without affecting the rest', function (): void {
    $lines  = fixtureLines('dns-audit.ndjson');
    $quiet  = new DnsNormalizer('DC01.corp.local', DNS_AUDIT, false);
    $noisy  = new DnsNormalizer('DC01.corp.local', DNS_AUDIT, true);

    $writeBack = '';
    $recordAdd = '';

    foreach ($lines as $line) {
        if (str_contains($line, '"i":520,')) { $writeBack = $line; }
        if (str_contains($line, '"i":542,')) { $recordAdd = $line; }
    }

    assertCount(0, $quiet->normalize($writeBack), 'write-back dropped');
    assertCount(1, $noisy->normalize($writeBack), 'kept by default');
    assertCount(1, $quiet->normalize($recordAdd), 'changes are never dropped');
});

test('the classic server log reports failures as failures', function (): void {
    $failed = dnsEvent(4007, DNS_SERVER, 'dns-server.ndjson');

    assertSame(EventResult::Fail, $failed->result);
    assertSame('legacy.corp.local', $failed->details['zone']);

    assertSame(EventResult::Info, dnsEvent(2, DNS_SERVER, 'dns-server.ndjson')->result);
});

test('a refused zone transfer keeps the address that asked', function (): void {
    $event = dnsEvent(6527, DNS_SERVER, 'dns-server.ndjson');

    assertSame('198.51.100.42', $event->srcIp);
    assertTrue(str_contains($event->rawMessage, 'von 198.51.100.42'));
});

test('malformed input produces no event', function (): void {
    $normalizer = new DnsNormalizer('DC01.corp.local');

    foreach (['', '  ', 'not json', '{}', '{"i":542}', '{"i":"x","t":"y","r":1}', '{"i":542,"t":"gestern","r":1}'] as $input) {
        assertCount(0, $normalizer->normalize($input), var_export($input, true));
    }
});

test('the dedup key separates the two DNS channels on one host', function (): void {
    $line = '{"r":7,"t":"2026-09-16T09:00:00.0000000Z","i":2,"c":"DC01.corp.local","d":{}}';

    $audit  = (new DnsNormalizer('DC01.corp.local', DNS_AUDIT))->normalize($line)[0];
    $server = (new DnsNormalizer('DC01.corp.local', DNS_SERVER))->normalize($line)[0];

    // Record ids are per channel, so the same number means different records.
    assertTrue($audit->dedupKey !== $server->dedupKey);
});

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

test('the discovery script asks the channel instead of trusting the catalogue', function (): void {
    $script = EventLogQuery::discoveryScript(DNS_AUDIT, 5000);

    assertTrue(str_contains($script, "LogName 'Microsoft-Windows-DNSServer/Audit'"));
    assertTrue(str_contains($script, 'Group-Object Id'), 'counts per id');
    assertTrue(str_contains($script, 'NoMatchingEventsFound'), 'an empty channel is not an error');
    assertTrue(str_contains($script, 'EventData.Data'), 'reports the field names too');
});

test('a channel name with a quote cannot break out of the discovery script', function (): void {
    $script = EventLogQuery::discoveryScript("DNS'; Remove-Item C:\\ -Recurse #", 10);

    assertTrue(str_contains($script, "'DNS''; Remove-Item C:\\ -Recurse #'"), 'quote doubled');
});

// ---------------------------------------------------------------------------
// Through the collector
// ---------------------------------------------------------------------------

test('a DNS source collects through the same transport as an AD one', function (): void {
    if (winrmSkip() || winrmDbSkip()) {
        return;
    }

    $db = ruleDb();
    dnsCleanup($db);

    $repo   = new SourceRepository($db);
    $id     = $repo->upsert([
        'name'            => 'dnstest-audit',
        'collector'       => 'winrm',
        'source_type'     => 'dns',
        'target_host'     => 'dnstest-dc',
        'enabled'         => true,
        'username'        => 'CORP\\svc',
        'auth_mode'       => 'ntlm',
        'poll_interval_s' => 300,
        'config'          => [
            'channel'          => DNS_AUDIT,
            'event_ids'        => [],
            'path'             => '/wsman',
            'window_seconds'   => 3600,
            'initial_lookback' => 7200,
            'lag_seconds'      => 0,
        ],
    ]);

    $writer    = new EventWriter($db, new Logger(null, 'error', false), 500, 1.0, null);
    $collector = new WinrmCollector($writer, new Logger(null, 'error', false));

    $result = $collector->collect($repo->find($id), winrmFactory(), new DateTimeImmutable('2026-09-16T10:30:00Z'));

    assertSame('ok', $result['status']);
    assertSame(8, $result['fetched'], 'the mock answered with DNS records, not Security ones');
    assertSame(8, $result['stored'], 'nothing is dropped on this channel');

    $row = $db->query(
        "SELECT raw_message FROM events
          WHERE source_type = 'dns' AND source_host = 'DC01.corp.local' AND event_type = '522'
          LIMIT 1",
    )->fetch();

    assertTrue($row !== false, 'the zone transfer change was stored');
    assertTrue(str_contains((string) $row['raw_message'], 'Zonentransfer-Einstellungen'));

    dnsCleanup($db);
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** @param array<string, mixed> $config */
function makeSource(array $config, string $sourceType): LogWarden\Ingest\IngestSource
{
    return LogWarden\Ingest\IngestSource::fromRow([
        'id'              => 1,
        'name'            => 'test',
        'collector'       => 'winrm',
        'source_type'     => $sourceType,
        'target_host'     => 'dc01',
        'enabled'         => true,
        'config'          => json_encode($config),
        'secret_ref'      => null,
        'username'        => null,
        'auth_mode'       => 'ntlm',
        'poll_interval_s' => 300,
        'bookmark'        => null,
        'last_success_at' => null,
        'last_run_at'     => null,
        'last_error'      => null,
        'last_error_at'   => null,
        'events_total'    => 0,
    ]);
}

function dnsCleanup(LogWarden\Core\Db $db): void
{
    $db->execute("DELETE FROM events WHERE source_type = 'dns' AND source_host IN ('DC01.corp.local', 'dnstest-dc')");
    $db->execute("DELETE FROM ingest_sources WHERE name LIKE 'dnstest-%'");
}
