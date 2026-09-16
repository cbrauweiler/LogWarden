<?php

declare(strict_types=1);

use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\EventWriter;
use LogWarden\Event\SourceType;
use LogWarden\Ingest\IngestSource;
use LogWarden\Ingest\SourceRepository;
use LogWarden\Ingest\Windows\AdEventCatalog;
use LogWarden\Ingest\Windows\AdNormalizer;
use LogWarden\Ingest\Windows\WindowsCodes;
use LogWarden\Ingest\Winrm\EventLogQuery;
use LogWarden\Ingest\Winrm\WinrmClient;
use LogWarden\Ingest\Winrm\WinrmCollector;
use LogWarden\Ingest\Winrm\WinrmException;
use LogWarden\Ingest\Winrm\WinrmShell;
use LogWarden\Ingest\Winrm\WsmanEnvelope;
use LogWarden\Ingest\Winrm\WsmanFault;
use LogWarden\Ingest\Winrm\WsmanResponse;

const WR_PREFIX = 'winrmtest-';

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

test('every envelope is well-formed XML with the expected action', function (): void {
    $envelope = new WsmanEnvelope('https://dc01.corp.local:5986/wsman');

    $cases = [
        [$envelope->createShell(), '/transfer/Create'],
        [$envelope->command('SHELL-1', 'powershell.exe', ['-NoProfile']), '/shell/Command'],
        [$envelope->receive('SHELL-1', 'CMD-1'), '/shell/Receive'],
        [$envelope->signal('SHELL-1', 'CMD-1'), '/shell/Signal'],
        [$envelope->deleteShell('SHELL-1'), '/transfer/Delete'],
        [$envelope->identify(), null],
    ];

    foreach ($cases as [$xml, $action]) {
        $dom = new DOMDocument();
        assertTrue($dom->loadXML($xml), 'envelope parses');

        if ($action !== null) {
            assertTrue(str_contains($xml, $action), 'carries ' . $action);
        }
    }
});

test('values are XML-escaped rather than concatenated into the envelope', function (): void {
    $envelope = new WsmanEnvelope('https://dc01/wsman');

    // A shell id is server-supplied, but the escaping has to hold regardless
    // of what comes back: an unescaped one would break the envelope, and a
    // hostile endpoint could then inject headers into the next request.
    $xml = $envelope->command('A&B"<C>', 'powershell.exe', ['--x=<script>']);

    $dom = new DOMDocument();
    assertTrue($dom->loadXML($xml), 'still well-formed with metacharacters');
    assertFalse(str_contains($xml, '<script>'), 'argument is not raw in the document');

    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('w', WsmanEnvelope::NS_WSMAN);
    assertSame('A&B"<C>', $xpath->query('//w:Selector')->item(0)->textContent);
});

test('the message id is a fresh v4 UUID each time', function (): void {
    $seen = [];

    for ($i = 0; $i < 50; $i++) {
        $uuid = WsmanEnvelope::uuid();
        assertSame(1, preg_match('/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/', $uuid), $uuid);
        $seen[$uuid] = true;
    }

    assertCount(50, $seen, 'no repeats');
});

// ---------------------------------------------------------------------------
// Responses and faults
// ---------------------------------------------------------------------------

test('stream chunks are concatenated before being read as text', function (): void {
    // "Domänen-Admins" with the ä split across two base64 chunks: decoding
    // each chunk to text on its own would corrupt it.
    $text   = 'Domänen-Admins';
    $first  = substr($text, 0, 6);   // ends mid-character
    $second = substr($text, 6);

    $xml = sprintf(
        '<s:Envelope xmlns:s="%s"><s:Body><rsp:ReceiveResponse xmlns:rsp="%s">'
        . '<rsp:Stream Name="stdout" CommandId="C">%s</rsp:Stream>'
        . '<rsp:Stream Name="stdout" CommandId="C">%s</rsp:Stream>'
        . '<rsp:CommandState State="%s/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState>'
        . '</rsp:ReceiveResponse></s:Body></s:Envelope>',
        WsmanEnvelope::NS_SOAP,
        WsmanEnvelope::NS_SHELL,
        base64_encode($first),
        base64_encode($second),
        WsmanEnvelope::NS_SHELL,
    );

    $response = WsmanResponse::parse($xml);
    assertSame($text, $response->stream('stdout'));
    assertTrue($response->isDone());
    assertSame(0, $response->exitCode());
});

test('a SOAP fault becomes a typed exception, not a parsed response', function (): void {
    $xml = faultXml('Zugriff verweigert.', 5, 'wsman:AccessDenied');

    try {
        WsmanResponse::parse($xml);
        assertTrue(false, 'should have thrown');
    } catch (WsmanFault $fault) {
        assertSame(5, $fault->faultCode);
        assertSame('AccessDenied', $fault->subcode, 'the prefix is stripped, the local part kept');
        assertTrue($fault->isAccessDenied());
        assertFalse($fault->isTimeout());
        assertTrue($fault->advice() !== null, 'access denied has an actionable hint');
    }
});

test('an operation timeout is recognised by code and by subcode alike', function (): void {
    // Windows sends both; a host that reports only one must still get a retry
    // rather than an abort, so either signal is enough on its own.
    foreach ([[2150858793, 'wsman:SomethingElse'], [0, 'wsman:TimedOut']] as [$code, $subcode]) {
        try {
            WsmanResponse::parse(faultXml('timed out', $code, $subcode));
            assertTrue(false, 'should have thrown');
        } catch (WsmanFault $fault) {
            assertTrue($fault->isTimeout(), 'code=' . $code . ' subcode=' . $subcode);
        }
    }
});

test('a non-XML body is reported as such instead of crashing the parser', function (): void {
    try {
        WsmanResponse::parse('<html>502 Bad Gateway</htm>');
        assertTrue(false, 'should have thrown');
    } catch (WinrmException $e) {
        assertTrue(str_contains($e->getMessage(), 'gültiges XML'));
    }
});

test('XML entities in the response are never expanded', function (): void {
    // A compromised or spoofed endpoint must not be able to read local files
    // through the response parser.
    $xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
        . '<s:Envelope xmlns:s="' . WsmanEnvelope::NS_SOAP . '"><s:Body>'
        . '<rsp:ReceiveResponse xmlns:rsp="' . WsmanEnvelope::NS_SHELL . '">'
        . '<rsp:Stream Name="stdout" CommandId="C">&xxe;</rsp:Stream>'
        . '</rsp:ReceiveResponse></s:Body></s:Envelope>';

    try {
        $response = WsmanResponse::parse($xml);
        assertSame('', $response->stream('stdout'), 'the entity resolved to nothing');
    } catch (WinrmException) {
        assertTrue(true, 'refusing the document outright is equally correct');
    }
});

// ---------------------------------------------------------------------------
// PowerShell generation
// ---------------------------------------------------------------------------

test('the generated script bounds the query by time, never by record count alone', function (): void {
    $script = (new EventLogQuery('Security', [4625], false, 5000))->script(
        new DateTimeImmutable('2026-09-16T07:00:00Z'),
        new DateTimeImmutable('2026-09-16T07:15:00Z'),
    );

    assertTrue(str_contains($script, 'StartTime = $from'), 'window start');
    assertTrue(str_contains($script, 'EndTime = $to'), 'window end');
    assertTrue(str_contains($script, "'2026-09-16T07:00:00.000000Z'"), 'explicit UTC');
    assertTrue(str_contains($script, 'RoundtripKind'), 'parsed without the host time zone');
});

test('an empty channel is not treated as a failed collection', function (): void {
    $script = (new EventLogQuery('Security'))->script(
        new DateTimeImmutable('-1 hour'),
        new DateTimeImmutable('now'),
    );

    // Get-WinEvent raises an error when nothing matches. Matching on the
    // message text would break on a German host, so the culture-independent
    // FullyQualifiedErrorId is what decides.
    assertTrue(str_contains($script, 'NoMatchingEventsFound'), 'recognised by error id');
    assertFalse(str_contains($script, '-ErrorAction Stop)'), 'not aborted on the empty case');
});

test('the channel name is a PowerShell literal, not an interpolation', function (): void {
    $script = (new EventLogQuery("Sec'urity"))->script(
        new DateTimeImmutable('-1 hour'),
        new DateTimeImmutable('now'),
    );

    assertTrue(str_contains($script, "LogName = 'Sec''urity'"), 'quote doubled');
});

test('the script survives the round trip through -EncodedCommand', function (): void {
    $script  = (new EventLogQuery('Microsoft-Windows-DNSServer/Audit', [513, 515]))->script(
        new DateTimeImmutable('2026-01-01T00:00:00Z'),
        new DateTimeImmutable('2026-01-01T00:15:00Z'),
    );
    $args    = EventLogQuery::powershellArguments($script);
    $index   = array_search('-EncodedCommand', $args, true);
    $decoded = mb_convert_encoding(base64_decode($args[$index + 1], true), 'UTF-8', 'UTF-16LE');

    assertSame($script, $decoded);
    assertTrue(in_array('-NoProfile', $args, true));
});

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

test('a failed logon carries the specific reason, not the generic status', function (): void {
    $event = normaliseOne(4625);

    assertSame(EventResult::Fail, $event->result);
    assertSame('pweber', $event->username);
    assertSame('10.20.30.77', $event->srcIp);
    // Status is 0xc000006d ("logon failure") on almost every 4625; SubStatus
    // is the half that distinguishes a wrong password from a missing account.
    assertSame('Falsches Passwort', $event->details['reason']);
    assertSame(3, $event->details['logon_type']);
});

test('a lockout names the machine that caused it', function (): void {
    $event = normaliseOne(4740);

    // 4740 reuses TargetDomainName for the calling computer. Storing it as a
    // domain would hide the one fact the event exists to deliver.
    assertSame('pweber', $event->username);
    assertSame('WS-PWEBER', $event->details['lockout_source']);
    assertFalse(isset($event->details['target_domain']), 'not filed as a domain');
    assertTrue(str_contains($event->rawMessage, 'ausgelöst von WS-PWEBER'));
});

test('a group change is filed under the member, not under the group', function (): void {
    $event = normaliseOne(4728);

    assertSame('Peter Weber', $event->username, 'the account that was added');
    assertSame('Domänen-Admins', $event->details['group']);
    assertSame('Administrator', $event->details['actor']);
    assertTrue(str_contains($event->details['member_sid'], 'S-1-5-21-'));
});

test('an IPv4-mapped IPv6 address is stored as plain IPv4', function (): void {
    // Windows logs 4771 as ::ffff:10.20.30.91 on a dual-stack DC. Kept in that
    // notation it would never match a search for the address, nor correlate
    // with the FortiGate's plain IPv4.
    assertSame('10.20.30.91', normaliseOne(4771)->srcIp);
});

test('4776 uses a different spelling for the workstation field', function (): void {
    $event = normaliseOne(4776);

    assertSame('WS-PWEBER', $event->details['workstation']);
    assertSame('Falsches Passwort', $event->details['reason']);
});

test('fields under UserData are read as well as those under EventData', function (): void {
    // Event 1102 puts its fields one level deeper. Reading only EventData
    // would deliver "security log cleared" with nobody attached to it.
    $event = normaliseOne(1102);

    assertSame('Administrator', $event->username);
    assertSame('audit', $event->details['category']);
});

test('machine and system accounts are dropped by default but can be kept', function (): void {
    $lines = fixtureLines('ad-security.ndjson');

    $strict = new AdNormalizer('DC01.corp.local');
    $loose  = new AdNormalizer('DC01.corp.local', 'Security', SourceType::Ad, true, true);

    $machine   = firstLineWith($lines, '"TargetUserName":"WS-ASMITH$"');
    $anonymous = firstLineWith($lines, 'ANONYMOUS LOGON');

    assertCount(0, $strict->normalize($machine), 'computer account dropped');
    assertCount(0, $strict->normalize($anonymous), 'ANONYMOUS LOGON dropped');
    assertCount(1, $loose->normalize($machine), 'kept when asked for');
    assertCount(1, $loose->normalize($anonymous), 'kept when asked for');
});

test('an unknown event id is stored rather than silently discarded', function (): void {
    $event = normaliseOne(4999);

    assertSame('4999', $event->eventType);
    assertSame('Ereignis 4999', $event->details['label']);
});

test('the same record always produces the same dedup key', function (): void {
    $line  = firstLineWith(fixtureLines('ad-security.ndjson'), '"i":4625');
    $first = (new AdNormalizer('DC01.corp.local'))->normalize($line)[0];
    $again = (new AdNormalizer('DC01.corp.local'))->normalize($line)[0];

    assertSame($first->dedupKey, $again->dedupKey, 'EventRecordID makes re-reads free');

    // A different channel on the same host is a different record space.
    $other = (new AdNormalizer('DC01.corp.local', 'System'))->normalize($line)[0];
    assertTrue($first->dedupKey !== $other->dedupKey);
});

test('malformed input produces no event instead of an exception', function (): void {
    $normalizer = new AdNormalizer('DC01.corp.local');

    foreach (['', '   ', 'not json', '{}', '{"i":4625}', '[1,2,3]', '{"i":"x","t":"y","r":1}'] as $input) {
        assertCount(0, $normalizer->normalize($input), var_export($input, true));
    }
});

// ---------------------------------------------------------------------------
// Catalogue and code tables
// ---------------------------------------------------------------------------

test('the default event selection excludes the high-volume ids', function (): void {
    $defaults = AdEventCatalog::defaultIds();

    assertTrue(in_array(4625, $defaults, true), 'failed logons are the point');
    assertTrue(in_array(4740, $defaults, true));
    assertTrue(in_array(1102, $defaults, true), 'log cleared is never optional');

    // 4769 alone can be 80% of a domain controller's Security channel.
    assertFalse(in_array(4769, $defaults, true));
    assertFalse(in_array(4634, $defaults, true));
    assertTrue(AdEventCatalog::volumeNote(4769) !== null, 'and the cost is stated');
});

test('status and Kerberos codes are translated in both notations', function (): void {
    assertSame('Falsches Passwort', WindowsCodes::status('0xC000006A'), 'uppercase');
    assertSame('Konto gesperrt', WindowsCodes::status('0xc0000234'));
    assertSame('Konto deaktiviert, gesperrt oder abgelaufen', WindowsCodes::kerberos('0x12'));
    assertSame('Falsches Passwort (Pre-Authentication fehlgeschlagen)', WindowsCodes::kerberos('0x00000018'));
    assertNull(WindowsCodes::status('-'));
    assertNull(WindowsCodes::status('nonsense'));
});

test('computer accounts are told apart from people', function (): void {
    assertTrue(WindowsCodes::isComputerAccount('WS-ASMITH$'));
    assertFalse(WindowsCodes::isComputerAccount('asmith'));
    assertTrue(WindowsCodes::isSystemAccount('ANONYMOUS LOGON'));
    assertFalse(WindowsCodes::isSystemAccount('asmith'));
});

// ---------------------------------------------------------------------------
// Against the mock endpoint
// ---------------------------------------------------------------------------

test('the whole shell conversation runs on a single connection', function (): void {
    if (winrmSkip()) {
        return;
    }

    $before = mockCounters();
    $client = mockClient('/wsman');
    $shell  = new WinrmShell($client, new Logger(null, 'error', false), 30);

    $result = $shell->run('powershell.exe', EventLogQuery::powershellArguments(
        (new EventLogQuery('Security', AdEventCatalog::defaultIds()))->script(
            new DateTimeImmutable('2026-09-16T07:00:00Z'),
            new DateTimeImmutable('2026-09-16T08:00:00Z'),
        ),
    ));

    assertSame(0, $result['exit_code']);
    assertTrue(str_contains($result['stdout'], '##LW-COUNT:'), 'the count marker came through');

    $client->close();
    $after = mockCounters();

    // NTLM authenticates the connection, not the request. Create, Command,
    // several Receives, Signal and Delete have to share one connection or the
    // handshake repeats on every call.
    assertSame(1, $after['connections'] - $before['connections'], 'one connection for the whole lifecycle');
    assertTrue($after['requests'] - $before['requests'] >= 5, 'several requests on it');
});

test('an operation timeout on Receive is retried, not reported as a failure', function (): void {
    if (winrmSkip()) {
        return;
    }

    $client = mockClient('/wsman-slow');
    $shell  = new WinrmShell($client, new Logger(null, 'error', false), 30);

    $result = $shell->run('powershell.exe', EventLogQuery::powershellArguments(
        (new EventLogQuery('Security'))->script(
            new DateTimeImmutable('2026-09-16T07:00:00Z'),
            new DateTimeImmutable('2026-09-16T08:00:00Z'),
        ),
    ));

    assertSame(0, $result['exit_code'], 'the timeout fault did not abort the run');
    assertTrue(strlen($result['stdout']) > 0);
    $client->close();
});

test('output split across many chunks reassembles byte for byte', function (): void {
    if (winrmSkip()) {
        return;
    }

    $script = (new EventLogQuery('Security', AdEventCatalog::defaultIds()))->script(
        new DateTimeImmutable('2026-09-16T07:00:00Z'),
        new DateTimeImmutable('2026-09-16T08:00:00Z'),
    );

    $whole   = mockRun('/wsman', $script);
    $chunked = mockRun('/wsman-chunked', $script);

    assertSame($whole['stdout'], $chunked['stdout'], 'same bytes either way');
    assertTrue($chunked['receives'] > $whole['receives'], 'and it really was chunked');
    assertTrue(str_contains($chunked['stdout'], 'Domänen-Admins'), 'umlaut intact across a chunk boundary');
});

test('a denied command surfaces as an access-denied fault with advice', function (): void {
    if (winrmSkip()) {
        return;
    }

    $client = mockClient('/wsman-denied');

    try {
        (new WinrmShell($client, new Logger(null, 'error', false), 30))
            ->run('powershell.exe', ['-NoProfile']);
        assertTrue(false, 'should have thrown');
    } catch (WsmanFault $fault) {
        assertTrue($fault->isAccessDenied());
        assertTrue(str_contains((string) $fault->advice(), 'Remote Management Users'));
    } finally {
        $client->close();
    }
});

test('a rejected login is reported as credentials, not as a transport error', function (): void {
    if (winrmSkip()) {
        return;
    }

    $client = mockClient('/wsman-401');

    try {
        $client->identify();
        assertTrue(false, 'should have thrown');
    } catch (WinrmException $e) {
        assertTrue(str_contains($e->getMessage(), 'HTTP 401'));
        assertTrue(str_contains($e->getMessage(), 'DOMAENE'), 'names the NTLM name format');
    } finally {
        $client->close();
    }
});

// ---------------------------------------------------------------------------
// Collector, end to end
// ---------------------------------------------------------------------------

test('a run collects the window, advances the bookmark and repeats free', function (): void {
    if (winrmSkip() || winrmDbSkip()) {
        return;
    }

    $db = ruleDb();
    winrmCleanup($db);

    $repo   = new SourceRepository($db);
    $source = $repo->find(makeWinrmSource($repo, '/wsman'));
    $writer = new EventWriter($db, new Logger(null, 'error', false), 500, 1.0, null);

    $collector = new WinrmCollector($writer, new Logger(null, 'error', false));
    $now       = new DateTimeImmutable('2026-09-16T09:00:00Z');

    $first = $collector->collect($source, winrmFactory(), $now);

    assertSame('ok', $first['status']);
    assertSame(11, $first['fetched'], 'every record in the window');
    assertSame(9, $first['stored'], 'minus the machine and system accounts');
    assertSame(2, $first['skipped']);
    assertTrue($first['caught_up'], 'no phantom backlog after reaching the ceiling');

    $repo->recordSuccess($source, $first['bookmark'], $first['fetched'], $first['stored'], $first['skipped'], 10);

    $stored = (int) $db->query(
        'SELECT count(*) AS c FROM events WHERE source_host = ?',
        [WR_FIXTURE_HOST],
    )->fetch()['c'];
    assertSame(9, $stored);

    // The same window again: the record ids make the inserts no-ops.
    $second = $collector->collect($repo->find($source->id), winrmFactory(), $now);
    assertSame(0, $second['fetched'], 'the bookmark moved past the window');

    winrmCleanup($db);
});

test('a collector in arrears works through several windows in one run', function (): void {
    if (winrmSkip() || winrmDbSkip()) {
        return;
    }

    $db = ruleDb();
    winrmCleanup($db);

    $repo   = new SourceRepository($db);
    $source = $repo->find(makeWinrmSource($repo, '/wsman', [
        'window_seconds'      => 900,
        'initial_lookback'    => 7200,
        'max_windows_per_run' => 3,
    ]));

    $writer    = new EventWriter($db, new Logger(null, 'error', false), 500, 1.0, null);
    $collector = new WinrmCollector($writer, new Logger(null, 'error', false));
    $now       = new DateTimeImmutable('2026-09-16T09:00:00Z');

    // Without multi-window catch-up a source two hours behind with a
    // 15-minute window would need eight runs, advancing 15 minutes at a time
    // while reporting success on every one of them.
    $result = $collector->collect($source, winrmFactory(), $now);

    assertSame(3, $result['windows'], 'capped by max_windows_per_run');
    assertFalse($result['caught_up']);
    assertTrue(str_contains((string) $result['note'], 'Rückstand'), 'and it says so');

    winrmCleanup($db);
});

test('a failed run leaves the bookmark where it was', function (): void {
    if (winrmSkip() || winrmDbSkip()) {
        return;
    }

    $db = ruleDb();
    winrmCleanup($db);

    $repo   = new SourceRepository($db);
    $source = $repo->find(makeWinrmSource($repo, '/wsman'));

    $repo->recordSuccess($source, ['until' => '2026-09-16T08:00:00+00:00', 'last_record_id' => 7], 1, 1, 0, 5);
    $repo->recordFailure($repo->find($source->id), 'Host nicht erreichbar', 12);

    $after = $repo->find($source->id);

    // Advancing on failure would turn every transient outage into a gap that
    // nothing ever reports.
    assertSame('2026-09-16T08:00:00+00:00', $after->bookmark['until']);
    assertSame(1, $after->consecutiveFailures);
    assertTrue(str_contains((string) $after->lastError, 'nicht erreichbar'));

    $runs = $repo->recentRuns($source->id, 5);
    assertSame('error', $runs[0]['status']);
    assertSame('ok', $runs[1]['status']);

    winrmCleanup($db);
});

test('a window that overflows the cap is shrunk before it is accepted', function (): void {
    if (winrmSkip() || winrmDbSkip()) {
        return;
    }

    $db = ruleDb();
    winrmCleanup($db);

    $repo   = new SourceRepository($db);
    $source = $repo->find(makeWinrmSource($repo, '/wsman-flood', [
        'window_seconds'      => 3600,
        'initial_lookback'    => 7200,
        'max_events'          => 100,
        'max_windows_per_run' => 1,
    ]));

    $writer    = new EventWriter($db, new Logger(null, 'error', false), 500, 1.0, null);
    $collector = new WinrmCollector($writer, new Logger(null, 'error', false));

    $result = $collector->collect($source, winrmFactory(), new DateTimeImmutable('2026-09-16T09:00:00Z'));

    // Every window still overflows, so the run reports partial instead of
    // pretending the gap is not there.
    assertSame('partial', $result['status']);
    assertTrue(str_contains((string) $result['note'], 'max_events'), 'and names the fix');

    winrmCleanup($db);
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function faultXml(string $reason, int $code, string $subcode): string
{
    return sprintf(
        '<s:Envelope xmlns:s="%s" xmlns:f="%s"><s:Body><s:Fault>'
        . '<s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>%s</s:Value></s:Subcode></s:Code>'
        . '<s:Reason><s:Text xml:lang="de-DE">%s</s:Text></s:Reason>'
        . '<s:Detail><f:WSManFault Code="%d"><f:Message>%s</f:Message></f:WSManFault></s:Detail>'
        . '</s:Fault></s:Body></s:Envelope>',
        WsmanEnvelope::NS_SOAP,
        WsmanEnvelope::NS_FAULT,
        $subcode,
        htmlspecialchars($reason, ENT_XML1),
        $code,
        htmlspecialchars($reason, ENT_XML1),
    );
}

/** @param list<string> $lines */
function firstLineWith(array $lines, string $needle): string
{
    foreach ($lines as $line) {
        if (str_contains($line, $needle)) {
            return $line;
        }
    }

    throw new RuntimeException('No fixture line contains ' . $needle);
}

function normaliseOne(int $eventId): Event
{
    $line   = firstLineWith(fixtureLines('ad-security.ndjson'), '"i":' . $eventId . ',');
    $events = (new AdNormalizer('DC01.corp.local'))->normalize($line);

    if ($events === []) {
        throw new RuntimeException('Event ' . $eventId . ' produced nothing');
    }

    return $events[0];
}

function winrmEndpoint(): ?string
{
    $value = getenv('LW_TEST_WINRM');

    return ($value === false || $value === '') ? null : $value;
}

function winrmSkip(): bool
{
    if (winrmEndpoint() === null || !extension_loaded('curl')) {
        assertTrue(true, 'skipped: start tests/support/winrm-mock.php and set LW_TEST_WINRM');

        return true;
    }

    return false;
}

function winrmDbSkip(): bool
{
    if (ruleDb() === null) {
        assertTrue(true, 'skipped: set LW_TEST_DSN to run');

        return true;
    }

    return false;
}

function mockClient(string $path): WinrmClient
{
    [$host, $port] = array_pad(explode(':', (string) winrmEndpoint(), 2), 2, '5985');

    return new WinrmClient($host, 'CORP\\svc-logwarden', 'geheim', [
        'tls'  => false,
        'port' => (int) $port,
        'path' => $path,
        'auth' => 'ntlm',
    ]);
}

/** @return array{stdout: string, stderr: string, exit_code: int, truncated: bool, receives: int} */
function mockRun(string $path, string $script): array
{
    $client = mockClient($path);

    try {
        return (new WinrmShell($client, new Logger(null, 'error', false), 30))
            ->run('powershell.exe', EventLogQuery::powershellArguments($script));
    } finally {
        $client->close();
    }
}

/** @return array{connections: int, requests: int} */
function mockCounters(): array
{
    $file = (getenv('LW_MOCK_STATE') ?: sys_get_temp_dir() . '/lw-winrm-mock') . '/counters.json';

    if (!is_file($file)) {
        return ['connections' => 0, 'requests' => 0];
    }

    $data = json_decode((string) file_get_contents($file), true);

    return [
        'connections' => (int) ($data['connections'] ?? 0),
        'requests'    => (int) ($data['requests'] ?? 0),
    ];
}

function winrmFactory(): callable
{
    return static fn (IngestSource $source): WinrmClient => mockClient(
        (string) $source->setting('path', '/wsman'),
    );
}

/** @param array<string, mixed> $overrides */
function makeWinrmSource(SourceRepository $repo, string $path, array $overrides = []): int
{
    return $repo->upsert([
        'name'            => WR_PREFIX . 'quelle',
        'collector'       => 'winrm',
        'source_type'     => 'ad',
        'target_host'     => WR_PREFIX . 'dc01',
        'enabled'         => true,
        'username'        => 'CORP\\svc',
        'auth_mode'       => 'ntlm',
        'poll_interval_s' => 300,
        'config'          => $overrides + [
            'channel'          => 'Security',
            'event_ids'        => AdEventCatalog::defaultIds(),
            'path'             => $path,
            'window_seconds'   => 3600,
            'initial_lookback' => 7200,
            'lag_seconds'      => 0,
            'max_events'       => 5000,
        ],
    ]);
}

/**
 * The fixture records carry their own MachineName, and the normaliser trusts
 * it over the configured host — that is what makes one source able to serve a
 * WEF collector holding several machines' logs. So the cleanup has to name
 * the host the fixtures claim to come from, not the one the source is
 * configured with.
 */
const WR_FIXTURE_HOST = 'DC01.corp.local';

function winrmCleanup(Db $db): void
{
    $db->execute('DELETE FROM events WHERE source_host IN (?, ?)', [WR_PREFIX . 'dc01', WR_FIXTURE_HOST]);
    $db->execute('DELETE FROM ingest_sources WHERE name LIKE ?', [WR_PREFIX . '%']);
}
