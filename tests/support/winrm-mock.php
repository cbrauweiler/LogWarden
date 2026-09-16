<?php
/**
 * A stand-in for a Windows WinRM endpoint.
 *
 * It speaks the MS-WSMV shell conversation for real — Identify, Create,
 * Command, Receive, Signal, Delete — parses the envelopes LogWarden sends,
 * decodes the base64/UTF-16LE PowerShell out of the command line, and answers
 * with the event records a Windows host would have returned for that time
 * window.
 *
 * It is a socket server rather than a `php -S` router because NTLM
 * authenticates the *connection*: the handshake needs three requests on one
 * keep-alive connection, and PHP's built-in server answers every request with
 * `Connection: close`. That is also what makes the connection-reuse assertion
 * possible — the test compares accepted connections against HTTP requests.
 *
 * This is not a substitute for a domain controller, and docs/winrm.md says so.
 * What it does verify is everything between the collector and the wire:
 * envelope shape, encoding, chunked stream reassembly across a multi-byte
 * boundary, the operation-timeout retry, fault handling and shell cleanup.
 *
 * Usage: php winrm-mock.php --listen=127.0.0.1:5985 [--ntlm]
 *
 * Behaviour is steered per request through the path:
 *   /wsman            normal
 *   /wsman-slow       one operation-timeout fault before the first output
 *   /wsman-chunked    output split into many small chunks
 *   /wsman-denied     access-denied fault on Command
 *   /wsman-401        HTTP 401
 *   /wsman-flood      every window returns more events than the cap
 */

declare(strict_types=1);

const NS_SOAP  = 'http://www.w3.org/2003/05/soap-envelope';
const NS_ADDR  = 'http://schemas.xmlsoap.org/ws/2004/08/addressing';
const NS_SHELL = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell';
const NS_FAULT = 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault';

/** @return array{0:int, 1:array<string,string>, 2:string} */
function handleRequest(string $path, array $headers, string $body, string $stateDir, bool $ntlm, int $connectionId): array
{
    $mode = match ($path) {
        '/wsman-slow'    => 'slow',
        '/wsman-chunked' => 'chunked',
        '/wsman-denied'  => 'denied',
        '/wsman-401'     => 'unauthorized',
        '/wsman-flood'   => 'flood',
        default          => 'normal',
    };

    if ($mode === 'unauthorized') {
        return [401, ['WWW-Authenticate' => 'Negotiate'], ''];
    }

    // NTLM authenticates the connection, not the request, and curl therefore
    // withholds the request body until it has been challenged: the first POST
    // arrives empty, carrying only the Type 1 token. A mock that answers 200
    // straight away never receives a single envelope — which is exactly what
    // happened the first time this ran. Three legs, then the body appears.
    if ($ntlm && !isset($GLOBALS['lw_authenticated'][$connectionId])) {
        $authorization = $headers['authorization'] ?? '';

        if ($authorization === '') {
            return [401, ['WWW-Authenticate' => 'NTLM'], ''];
        }

        if (str_starts_with($authorization, 'NTLM ')) {
            $token = base64_decode(substr($authorization, 5), true) ?: '';
            $type  = strlen($token) >= 12 ? unpack('V', substr($token, 8, 4))[1] : 0;

            if ($type === 1) {
                return [401, ['WWW-Authenticate' => 'NTLM ' . base64_encode(ntlmChallenge())], ''];
            }

            // Any well-formed Type 3 is accepted: this mock proves the
            // conversation, not the cryptography.
            $GLOBALS['lw_authenticated'][$connectionId] = true;
        }
    }

    // Record every envelope so the tests can assert on what was actually sent.
    if (trim($body) !== '') {
        file_put_contents($stateDir . '/requests.log', $body . "\n\x1e", FILE_APPEND);
    }

    $dom = new DOMDocument();
    if ($body === '' || !@$dom->loadXML($body, LIBXML_NONET)) {
        return [400, [], 'not xml'];
    }

    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('s', NS_SOAP);
    $xpath->registerNamespace('a', NS_ADDR);
    $xpath->registerNamespace('w', 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd');
    $xpath->registerNamespace('rsp', NS_SHELL);
    $xpath->registerNamespace('wsmid', 'http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd');

    $action  = $xpath->query('//a:Action')->item(0)?->textContent ?? '';
    $shellId = $xpath->query('//w:Selector[@Name="ShellId"]')->item(0)?->textContent ?? '';

    if ($xpath->query('//wsmid:Identify')->length > 0) {
        return ok(
            '<wsmid:IdentifyResponse xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
            . '<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>'
            . '<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>'
            . '<wsmid:ProductVersion>OS: 10.0.20348 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>'
            . '</wsmid:IdentifyResponse>',
        );
    }

    if (str_ends_with($action, '/transfer/Create')) {
        $id = 'SHELL-' . bin2hex(random_bytes(8));
        file_put_contents(state($stateDir, $id), json_encode(['created' => time()]));

        return ok(sprintf(
            '<rsp:Shell xmlns:rsp="%s"><rsp:ShellId>%s</rsp:ShellId>'
            . '<rsp:Owner>CORP\\svc-logwarden</rsp:Owner>'
            . '<rsp:ResourceUri>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</rsp:ResourceUri>'
            . '</rsp:Shell>',
            NS_SHELL,
            $id,
        ));
    }

    if (str_ends_with($action, '/shell/Command')) {
        if ($mode === 'denied') {
            return fault('Zugriff verweigert.', 5, 'wsman:AccessDenied');
        }

        $command = $xpath->query('//rsp:Command')->item(0)?->textContent ?? '';
        $args    = [];
        foreach ($xpath->query('//rsp:Arguments') as $node) {
            $args[] = $node->textContent;
        }

        $script    = decodeCommand($args);
        $commandId = 'CMD-' . bin2hex(random_bytes(8));

        file_put_contents(state($stateDir, $shellId . '-' . $commandId), json_encode([
            'command'  => $command,
            'script'   => $script,
            'output'   => renderOutput($script, $mode),
            'offset'   => 0,
            'timeouts' => $mode === 'slow' ? 1 : 0,
        ], JSON_UNESCAPED_UNICODE));

        return ok(sprintf(
            '<rsp:CommandResponse xmlns:rsp="%s"><rsp:CommandId>%s</rsp:CommandId></rsp:CommandResponse>',
            NS_SHELL,
            $commandId,
        ));
    }

    if (str_ends_with($action, '/shell/Receive')) {
        $node      = $xpath->query('//rsp:DesiredStream')->item(0);
        $commandId = $node instanceof DOMElement ? $node->getAttribute('CommandId') : '';
        $file      = state($stateDir, $shellId . '-' . $commandId);

        if (!is_file($file)) {
            return fault('Die angegebene Shell wurde nicht gefunden.', 2150858843, 'wsman:InvalidSelectors');
        }

        $st = json_decode((string) file_get_contents($file), true);

        if (($st['timeouts'] ?? 0) > 0) {
            $st['timeouts']--;
            file_put_contents($file, json_encode($st, JSON_UNESCAPED_UNICODE));

            return fault(
                'The WS-Management service cannot complete the operation within the time specified in OperationTimeout.',
                2150858793,
                'wsman:TimedOut',
            );
        }

        $chunk = $mode === 'chunked' ? 997 : 65536;
        $slice = substr($st['output'], $st['offset'], $chunk);
        $st['offset'] += strlen($slice);
        $done  = $st['offset'] >= strlen($st['output']);
        file_put_contents($file, json_encode($st, JSON_UNESCAPED_UNICODE));

        $streams = $slice === '' ? '' : sprintf(
            '<rsp:Stream Name="stdout" CommandId="%s">%s</rsp:Stream>',
            $commandId,
            base64_encode($slice),
        );

        $stateXml = $done
            ? sprintf(
                '<rsp:Stream Name="stdout" CommandId="%s" End="true"></rsp:Stream>'
                . '<rsp:Stream Name="stderr" CommandId="%s" End="true"></rsp:Stream>'
                . '<rsp:CommandState CommandId="%s" State="%s/CommandState/Done">'
                . '<rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState>',
                $commandId,
                $commandId,
                $commandId,
                NS_SHELL,
            )
            : sprintf(
                '<rsp:CommandState CommandId="%s" State="%s/CommandState/Running"/>',
                $commandId,
                NS_SHELL,
            );

        return ok(sprintf('<rsp:ReceiveResponse xmlns:rsp="%s">%s%s</rsp:ReceiveResponse>', NS_SHELL, $streams, $stateXml));
    }

    if (str_ends_with($action, '/shell/Signal')) {
        return ok(sprintf('<rsp:SignalResponse xmlns:rsp="%s"/>', NS_SHELL));
    }

    if (str_ends_with($action, '/transfer/Delete')) {
        foreach (glob($stateDir . '/' . preg_replace('/[^A-Za-z0-9-]/', '', $shellId) . '*') ?: [] as $f) {
            @unlink($f);
        }

        return ok('');
    }

    return fault('Unbekannte Aktion: ' . $action, 2150858770, 'wsman:ActionNotSupported');
}

// ---------------------------------------------------------------------------

function state(string $dir, string $key): string
{
    return $dir . '/' . preg_replace('/[^A-Za-z0-9-]/', '', $key) . '.json';
}

/**
 * Plays the part of the DHCP audit log: sends the column header once, then the
 * rows whose timestamp falls inside the requested window, each wrapped the way
 * the real script wraps them.
 */
function renderDhcp(string $script): string
{
    preg_match("/\\\$from = \[datetime\]::Parse\('([^']+)'/", $script, $mFrom);
    preg_match("/\\\$to   = \[datetime\]::Parse\('([^']+)'/", $script, $mTo);
    preg_match('/\\\$wanted = @\(([^)]*)\)/', $script, $mWanted);

    $from   = strtotime($mFrom[1] ?? '@0');
    $to     = strtotime($mTo[1] ?? 'now');
    $wanted = [];

    if (!empty($mWanted[1])) {
        foreach (explode(',', $mWanted[1]) as $id) {
            $wanted[] = trim($id, " '");
        }
    }

    $file = dirname(__DIR__) . '/fixtures/dhcp-srvlog.log';
    $out  = [];
    $sent = 0;

    foreach (file($file) ?: [] as $line) {
        $line = rtrim($line, "\r\n");

        if (preg_match('/^ID,\s*Date,\s*Time,/', $line) === 1) {
            $out[] = json_encode(['h' => $line], JSON_UNESCAPED_SLASHES);
            continue;
        }

        if (preg_match('/^\s*(\d{1,2}),\s*(\d{2})\/(\d{2})\/(\d{2}),\s*(\d{2}:\d{2}:\d{2}),/', $line, $m) !== 1) {
            continue;
        }

        $id = str_pad($m[1], 2, '0', STR_PAD_LEFT);

        if ($wanted !== [] && !in_array($id, $wanted, true)) {
            continue;
        }

        // The fixture is written in the US short-date order the English
        // install produces; the real script resolves this with the server's
        // own culture, which is the whole point of doing it over there.
        $ts = strtotime(sprintf('20%s-%s-%s %s UTC', $m[4], $m[2], $m[3], $m[5]));

        if ($ts === false || $ts < $from || $ts >= $to) {
            continue;
        }

        $out[] = json_encode([
            'l' => $line,
            't' => gmdate('Y-m-d\TH:i:s', $ts) . '.0000000Z',
            'c' => 'DHCP01.corp.local',
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $sent++;
    }

    return implode("\n", $out) . ($out === [] ? '' : "\n") . '##LW-COUNT:' . $sent . "\n";
}

function firstFixtureLine(): string
{
    foreach (file(dirname(__DIR__) . '/fixtures/ad-security.ndjson') ?: [] as $line) {
        $line = trim($line);
        if ($line !== '' && $line[0] !== '#') {
            return $line;
        }
    }

    throw new RuntimeException('fixture is empty');
}

/** @param list<string> $args */
function decodeCommand(array $args): string
{
    $index = array_search('-EncodedCommand', $args, true);
    if ($index === false || !isset($args[$index + 1])) {
        return '';
    }

    $raw = base64_decode($args[$index + 1], true);

    return $raw === false ? '' : (string) mb_convert_encoding($raw, 'UTF-8', 'UTF-16LE');
}

/**
 * Plays the part of Get-WinEvent: returns the fixture records whose timestamp
 * falls inside the window the script asks for, in the same NDJSON shape the
 * real script emits.
 */
function renderOutput(string $script, string $mode): string
{
    // The reachability probe asks for a record count, not for events.
    if (str_contains($script, '-ListLog')) {
        return "184529402\n";
    }

    // The DHCP collector reads a file, not a channel: same bounded window,
    // completely different script, so the mock has to answer it differently.
    if (str_contains($script, 'DhcpSrvLog') || str_contains($script, 'DhcpV6SrvLog')) {
        return renderDhcp($script);
    }

    if (!str_contains($script, 'Get-WinEvent')) {
        return "0\n";
    }

    preg_match("/\\\$from = \[datetime\]::Parse\('([^']+)'/", $script, $mFrom);
    preg_match("/\\\$to   = \[datetime\]::Parse\('([^']+)'/", $script, $mTo);
    preg_match('/-MaxEvents (\d+)/', $script, $mMax);
    preg_match("/LogName = '([^']*)'/", $script, $mLog);
    preg_match('/\$filter\[.Id.\] = @\(([0-9,]+)\)/', $script, $mIds);

    $from = strtotime($mFrom[1] ?? '@0');
    $to   = strtotime($mTo[1] ?? 'now');
    $max  = (int) ($mMax[1] ?? 5000);
    $ids  = isset($mIds[1]) ? array_map('intval', explode(',', $mIds[1])) : [];

    // One mock, several channels: a DNS source has to be answerable with DNS
    // records, or the collector's channel handling is never exercised.
    $channel = $mLog[1] ?? 'Security';
    $fixture = dirname(__DIR__) . '/fixtures/' . match (true) {
        stripos($channel, 'DNSServer/Audit') !== false => 'dns-audit.ndjson',
        strcasecmp(trim($channel), 'DNS Server') === 0 => 'dns-server.ndjson',
        default                                        => 'ad-security.ndjson',
    };

    if (!is_file($fixture)) {
        return '##LW-COUNT:0' . "\n";
    }
    $records = [];

    foreach (file($fixture) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }

        $record = json_decode($line, true);
        $ts     = strtotime($record['t']);

        if ($ts < $from || $ts >= $to) {
            continue;
        }

        if ($ids !== [] && !in_array((int) $record['i'], $ids, true)) {
            continue;
        }

        $records[] = $line;
    }

    if ($mode === 'flood') {
        // A busy domain controller, as the collector sees one: the cap is
        // exceeded no matter how narrow the window gets. Deliberately not
        // derived from the records that fall inside the window — a flood that
        // thins out when the window shrinks would let the collector escape
        // the very case this mode exists to exercise.
        $seed = json_decode(firstFixtureLine(), true);
        $records = [];

        for ($i = 0; $i < $max + 25; $i++) {
            $seed['r'] = 900000000 + $i;
            $seed['t'] = gmdate('Y-m-d\TH:i:s', $from + ($i % max(1, $to - $from))) . '.0000000Z';
            $records[] = json_encode($seed, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
    }

    $count   = count($records);
    $records = array_slice($records, 0, $max);

    return implode("\n", $records) . ($records === [] ? '' : "\n") . '##LW-COUNT:' . $count . "\n";
}

/** @return array{0:int, 1:array<string,string>, 2:string} */
function ok(string $bodyXml): array
{
    return [200, [], '<?xml version="1.0" encoding="UTF-8"?>'
        . '<s:Envelope xmlns:s="' . NS_SOAP . '" xmlns:a="' . NS_ADDR . '">'
        . '<s:Header><a:MessageID>uuid:' . strtoupper(bin2hex(random_bytes(8))) . '</a:MessageID></s:Header>'
        . '<s:Body>' . $bodyXml . '</s:Body>'
        . '</s:Envelope>'];
}

/** @return array{0:int, 1:array<string,string>, 2:string} */
function fault(string $reason, int $code, string $subcode): array
{
    return [500, [], '<?xml version="1.0" encoding="UTF-8"?>'
        . '<s:Envelope xmlns:s="' . NS_SOAP . '" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
        . 'xmlns:f="' . NS_FAULT . '">'
        . '<s:Header/><s:Body><s:Fault>'
        . '<s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>' . $subcode . '</s:Value></s:Subcode></s:Code>'
        . '<s:Reason><s:Text xml:lang="de-DE">' . htmlspecialchars($reason, ENT_XML1) . '</s:Text></s:Reason>'
        . '<s:Detail><f:WSManFault xmlns:f="' . NS_FAULT . '" Code="' . $code . '" Machine="dc01.corp.local">'
        . '<f:Message>' . htmlspecialchars($reason, ENT_XML1) . '</f:Message></f:WSManFault></s:Detail>'
        . '</s:Fault></s:Body></s:Envelope>'];
}

/** A minimal NTLMSSP Type 2 message: enough for curl to produce a Type 3. */
function ntlmChallenge(): string
{
    return "NTLMSSP\0"
        . pack('V', 2)                       // message type
        . pack('vvV', 0, 0, 48)              // target name: empty, at offset 48
        . pack('V', 0x00028201)              // unicode | ntlm | target=server | always sign
        . random_bytes(8)                    // server challenge
        . str_repeat("\0", 8)                // reserved
        . pack('vvV', 0, 0, 48);             // target info: empty
}

// ---------------------------------------------------------------------------
// Socket server
// ---------------------------------------------------------------------------

// Guard: the test suite loads this file for its helper functions, and under
// any SAPI other than CLI there is no STDERR to complain to — the same trap
// the logger fell into. Only an explicit --listen starts the server.
if (PHP_SAPI !== 'cli' || !in_array('--listen', array_map(
    static fn (string $a): string => explode('=', $a)[0],
    $GLOBALS['argv'] ?? [],
), true)) {
    return;
}

$options  = getopt('', ['listen::', 'ntlm', 'state::']);
$listen   = is_string($options['listen'] ?? null) ? $options['listen'] : '127.0.0.1:5985';
$ntlm     = isset($options['ntlm']);
$stateDir = is_string($options['state'] ?? null)
    ? $options['state']
    : (getenv('LW_MOCK_STATE') ?: sys_get_temp_dir() . '/lw-winrm-mock');

@mkdir($stateDir, 0700, true);

// Fresh counters per server start, so a restart cannot leave a stale, higher
// number behind for the next test run to subtract from.
@unlink($stateDir . '/counters.json');
@unlink($stateDir . '/requests.log');

$server = stream_socket_server('tcp://' . $listen, $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "winrm-mock: {$errstr} ({$errno})\n");
    exit(1);
}

fwrite(STDERR, "winrm-mock hört auf {$listen}" . ($ntlm ? ' (NTLM)' : '') . "\n");

$connections = 0;
$requests    = 0;
$GLOBALS['lw_authenticated'] = [];

while (true) {
    $client = @stream_socket_accept($server, 30);
    if ($client === false) {
        continue;
    }

    $connections++;
    $connectionId = $connections;
    stream_set_timeout($client, 5);

    // One connection, as many requests as the client wants to send on it.
    // Without this loop NTLM cannot complete and nothing else here would run.
    while (!feof($client)) {
        $request = readRequest($client);
        if ($request === null) {
            break;
        }

        $requests++;
        [$path, $headers, $body] = $request;

        [$status, $extra, $responseBody] = handleRequest($path, $headers, $body, $stateDir, $ntlm, $connectionId);

        $head = sprintf("HTTP/1.1 %d %s\r\n", $status, $status === 200 ? 'OK' : ($status === 401 ? 'Unauthorized' : 'Error'));
        $head .= "Content-Type: application/soap+xml;charset=UTF-8\r\n";
        $head .= 'Content-Length: ' . strlen($responseBody) . "\r\n";
        $head .= "Connection: keep-alive\r\n";

        foreach ($extra as $name => $value) {
            $head .= $name . ': ' . $value . "\r\n";
        }

        fwrite($client, $head . "\r\n" . $responseBody);

        // Written per request, not per connection: a test that asserts on the
        // connection count runs while the client still holds the connection
        // open, so deferring this until close would always read the previous
        // value.
        file_put_contents($stateDir . '/counters.json', json_encode([
            'connections' => $connections,
            'requests'    => $requests,
        ]));
    }

    unset($GLOBALS['lw_authenticated'][$connectionId]);
    fclose($client);
}

/**
 * Reads one HTTP request from the socket.
 *
 * @return array{0:string, 1:array<string,string>, 2:string}|null
 */
function readRequest($client): ?array
{
    $requestLine = fgets($client);
    if ($requestLine === false || trim($requestLine) === '') {
        return null;
    }

    $parts = explode(' ', trim($requestLine));
    $path  = parse_url($parts[1] ?? '/', PHP_URL_PATH) ?: '/';

    $headers = [];
    while (($line = fgets($client)) !== false) {
        $line = rtrim($line, "\r\n");
        if ($line === '') {
            break;
        }
        [$name, $value] = array_pad(explode(':', $line, 2), 2, '');
        $headers[strtolower(trim($name))] = trim($value);
    }

    $length = (int) ($headers['content-length'] ?? 0);
    $body   = '';
    while (strlen($body) < $length) {
        $chunk = fread($client, $length - strlen($body));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $body .= $chunk;
    }

    return [$path, $headers, $body];
}
