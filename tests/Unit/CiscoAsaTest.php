<?php

declare(strict_types=1);

use LogWarden\Event\EventResult;
use LogWarden\Plugin\CiscoAsa\AsaMessageCatalog;
use LogWarden\Plugin\CiscoAsa\CiscoAsaNormalizer;
use LogWarden\Plugin\PluginRegistry;

/** The plugin's classes are only loaded once the registry has been asked for it. */
function asa(): CiscoAsaNormalizer
{
    PluginRegistry::default()->get('cisco-asa');

    return new CiscoAsaNormalizer();
}

/** @return list<string> */
function asaFixtures(): array
{
    $file = LW_ROOT . '/plugins/cisco-asa/fixtures/cisco-asa.log';

    return array_values(array_filter(
        array_map('rtrim', explode("\n", (string) file_get_contents($file))),
        static fn (string $l): bool => $l !== '' && !str_starts_with($l, '#'),
    ));
}

function asaLineWith(string $needle): string
{
    foreach (asaFixtures() as $line) {
        if (str_contains($line, $needle)) {
            return $line;
        }
    }

    throw new RuntimeException('no fixture contains ' . $needle);
}

function asaOne(string $needle): LogWarden\Event\Event
{
    $events = asa()->normalize(asaLineWith($needle), ['peer' => '10.0.0.7']);

    if ($events === []) {
        throw new RuntimeException($needle . ' produced nothing');
    }

    return $events[0];
}

// ---------------------------------------------------------------------------

test('the three ASA field styles are all parsed', function (): void {
    // Angle brackets: Group <x> User <y> IP <z>
    $angle = asaOne('113039');
    assertSame('asmith', $angle->username);
    assertSame('203.0.113.5', $angle->srcIp);
    assertSame('SSL-VPN', $angle->details['group']);

    // Commas: Group = x, Username = y, IP = z
    $comma = asaOne('113019');
    assertSame('asmith', $comma->username);
    assertSame('203.0.113.5', $comma->srcIp);

    // Colon-separated key = value
    $colon = asaOne('113005');
    assertSame('pweber', $colon->username);
    assertSame('203.0.113.9', $colon->srcIp, 'from "user IP =", not from "server ="');
    assertSame('10.0.0.10', $colon->details['server']);
});

test('a user name containing no spaces is not cut at the wrong separator', function (): void {
    // "user = pweber : user IP = ..." — reading to the next whitespace would
    // have produced "pweber" by luck; reading to the next " : " is why it also
    // works when the directory hands back a display name.
    $events = asa()->normalize(
        '<166>Sep 16 08:14:41 asa01 %ASA-6-113005: AAA user authentication Rejected : '
        . 'reason = Invalid password : server = 10.0.0.10 : user = van der Berg : user IP = 203.0.113.9',
    );

    assertSame('van der Berg', $events[0]->username);
});

test('the management login styles are recognised', function (): void {
    $denied = asaOne('605004');
    assertSame('root', $denied->username);
    assertSame('203.0.113.9', $denied->srcIp);
    assertSame('outside', $denied->details['interface']);
    assertSame(EventResult::Fail, $denied->result);

    $uname = asaOne('611102');
    assertSame('pweber', $uname->username, 'Uname: style');

    $lockout = asaOne('113006');
    assertSame('pweber', $lockout->username, '"User x locked out" style');
});

test('the failure reason is translated rather than passed through', function (): void {
    assertSame('Falsches Passwort', asaOne('113005')->details['reason']);
    assertSame('Konto deaktiviert', AsaMessageCatalog::reason('Account disabled'));

    // An unknown reason is kept verbatim: losing it would be worse than not
    // translating it.
    assertSame('Etwas Neues', AsaMessageCatalog::reason('Etwas Neues'));
    assertNull(AsaMessageCatalog::reason(null));
});

test('VPN and authentication land in different source types', function (): void {
    assertSame('cisco_asa_vpn', asaOne('113039')->sourceType->value);
    assertSame('cisco_asa_auth', asaOne('113004')->sourceType->value);
});

test('connection bookkeeping is dropped', function (): void {
    // 302013/302014 are one line per TCP connection. Keeping unknown ids would
    // mean keeping exactly the flood the catalogue exists to exclude.
    foreach (['302013', '302014'] as $id) {
        assertCount(0, asa()->normalize(asaLineWith($id)));
    }
});

test('the Firepower spelling of the same message is recognised', function (): void {
    $event = asaOne('%FTD-6-113004');

    assertSame('lwagner', $event->username);
    assertSame('cisco_asa_auth', $event->sourceType->value);
});

test('the normaliser claims ASA lines and nothing else', function (): void {
    $normalizer = asa();

    assertTrue($normalizer->supports(asaLineWith('113004')));
    assertFalse($normalizer->supports('date=2026-09-16 time=10:01:15 devname="FGT-60F-HQ" logid="0101039426"'));
    assertFalse($normalizer->supports('irgendein Text'));
    assertFalse($normalizer->supports(''));
});

test('every fixture line is either understood or deliberately dropped', function (): void {
    $normalizer = asa();
    $seen       = 0;

    foreach (asaFixtures() as $line) {
        $events = $normalizer->normalize($line, ['peer' => '10.0.0.7']);

        foreach ($events as $event) {
            $seen++;
            assertTrue($event->username !== null || $event->srcIp !== null, 'carries an actor: ' . $line);
            assertTrue($event->details['label'] !== '', 'carries a label: ' . $line);
        }
    }

    assertSame(12, $seen, 'twelve of the fourteen fixture lines are collected');
});

test('the host comes from the syslog header, not from the peer', function (): void {
    // A relay in front of the collector would otherwise make every appliance
    // look like the relay.
    assertSame('asa01.corp.local', asaOne('113004')->sourceHost);
});
