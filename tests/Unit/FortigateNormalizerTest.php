<?php

declare(strict_types=1);

use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\SourceType;
use LogWarden\Ingest\Fortigate\FortigateNormalizer;

/** @return array<int, \LogWarden\Event\Event> */
function normalizeAll(string $fixture): array
{
    $normalizer = new FortigateNormalizer();
    $events     = [];

    foreach (fixtureLines($fixture) as $line) {
        foreach ($normalizer->normalize($line, ['peer' => '10.0.0.1']) as $event) {
            $events[] = $event;
        }
    }

    return $events;
}

test('native VPN tunnel-up is normalised', function (): void {
    $event = normalizeAll('fortigate-native.log')[0];

    assertSame(SourceType::FortigateVpn, $event->sourceType);
    assertSame('FGT-60F-HQ', $event->sourceHost);
    assertSame('tunnel-up', $event->eventType);
    assertSame('jdoe', $event->username);
    assertSame('203.0.113.9', $event->srcIp);
    assertSame(EventResult::Success, $event->result);
    assertSame('ssl-tunnel', $event->details['tunneltype']);
    assertSame('VPN-Users', $event->details['group']);
    // eventtime is nanoseconds on FortiOS 6.2+
    assertSame('2026-09-15T08:00:01+00:00', $event->ts->format('c'));
});

test('DOMAIN\\user is reduced to the bare principal for correlation', function (): void {
    $event = normalizeAll('fortigate-native.log')[1];

    assertSame('asmith', $event->username, 'username must correlate with AD events');
    assertSame('CORP\asmith', $event->details['user_raw'], 'original form must be preserved');
    assertSame(EventResult::Fail, $event->result);
    assertSame('ssl-login-fail', $event->eventType);
    assertSame('sslvpn_login_permission_denied', $event->details['reason']);
});

test('user@domain is reduced the same way', function (): void {
    $event = normalizeAll('fortigate-native.log')[2];

    assertSame(SourceType::FortigateAuth, $event->sourceType);
    assertSame('asmith', $event->username);
    assertSame('asmith@corp.local', $event->details['user_raw']);
    assertSame(EventResult::Fail, $event->result);
    assertSame('198.51.100.44', $event->srcIp);
    assertSame('10.10.0.1', $event->dstIp);
});

test('authentication success maps to result success', function (): void {
    $event = normalizeAll('fortigate-native.log')[3];

    assertSame(SourceType::FortigateAuth, $event->sourceType);
    assertSame(EventResult::Success, $event->result);
    assertSame('jdoe', $event->username);
});

test('tunnel-down is informational, not a failure', function (): void {
    $event = normalizeAll('fortigate-native.log')[4];

    assertSame(EventResult::Info, $event->result);
    assertSame('tunnel-down', $event->eventType);
    assertSame('1799', $event->details['duration']);
});

test('traffic logs are dropped instead of stored', function (): void {
    $events = normalizeAll('fortigate-native.log');

    foreach ($events as $event) {
        assertFalse(str_contains($event->rawMessage, 'type="traffic"'), 'traffic log leaked into the store');
    }

    // Seven fixture lines, one of which is traffic.
    assertCount(6, $events);
});

test('eventtime in seconds is understood as well as nanoseconds', function (): void {
    $events = normalizeAll('fortigate-native.log');
    $event  = $events[count($events) - 1];

    assertSame('FGT-90D-BR1', $event->sourceHost);
    assertSame('2026-09-15T08:04:00+00:00', $event->ts->format('c'));
});

test('CEF login failure is normalised identically to the native form', function (): void {
    $event = normalizeAll('fortigate-cef.log')[0];

    assertSame(SourceType::FortigateVpn, $event->sourceType);
    assertSame('ssl-login-fail', $event->eventType);
    assertSame('asmith', $event->username);
    assertSame('198.51.100.44', $event->srcIp);
    assertSame(EventResult::Fail, $event->result);
    assertSame('0101039426', $event->details['logid']);
});

test('CEF custom labels reach the details column', function (): void {
    $event = normalizeAll('fortigate-cef.log')[1];

    assertSame(SourceType::FortigateAuth, $event->sourceType);
    assertSame(EventResult::Success, $event->result);
    assertSame('fortitoken', $event->details['method']);
    assertSame('10.10.0.1', $event->dstIp);
});

test('CEF falls back to dvchost when devname is absent', function (): void {
    $event = normalizeAll('fortigate-cef.log')[2];

    assertSame('FGT-60F-HQ', $event->sourceHost);
    assertSame('tunnel-up', $event->eventType);
});

test('an envelope-wrapped payload is normalised through the envelope', function (): void {
    $events = normalizeAll('syslog-framing.log');

    assertCount(3, $events);
    assertSame('jdoe', $events[0]->username);
    assertSame(SourceType::FortigateVpn, $events[0]->sourceType);
    assertSame('asmith', $events[1]->username);
    assertSame(EventResult::Fail, $events[1]->result);
    assertSame(EventResult::Fail, $events[2]->result);
});

test('supports() accepts FortiGate traffic and rejects foreign lines', function (): void {
    $normalizer = new FortigateNormalizer();

    assertTrue($normalizer->supports(fixtureLines('fortigate-native.log')[0]));
    assertTrue($normalizer->supports(fixtureLines('fortigate-cef.log')[0]));
    assertFalse($normalizer->supports('<34>Oct 11 22:14:15 mymachine su: failed for lonvick'));
    assertFalse($normalizer->supports('CEF:0|Cisco|ASA|9.1|106023|Deny|5|src=1.2.3.4'));
});

test('the same line normalises to the same dedup key', function (): void {
    $line  = fixtureLines('fortigate-native.log')[0];
    $first  = (new FortigateNormalizer())->normalize($line, ['peer' => '10.0.0.1'])[0];
    $second = (new FortigateNormalizer())->normalize($line, ['peer' => '10.0.0.1'])[0];

    assertSame($first->dedupKey, $second->dedupKey, 'a UDP retransmit must not create a second event');
});

test('garbage never escapes as an exception', function (): void {
    $normalizer = new FortigateNormalizer();

    assertCount(0, $normalizer->normalize(''));
    assertCount(0, $normalizer->normalize('<189>'));
    assertCount(0, $normalizer->normalize("<189>devname=\"x\" \x00\xff binary"));
    assertCount(0, $normalizer->normalize('<189>logid="0000000013" type="traffic"'));
});

test('invalid IP values are stored as null rather than failing the insert', function (): void {
    assertNull(Event::normaliseIp('N/A'));
    assertNull(Event::normaliseIp('-'));
    assertNull(Event::normaliseIp(''));
    assertNull(Event::normaliseIp('not-an-ip'));
    assertSame('203.0.113.9', Event::normaliseIp('203.0.113.9:443'));
    assertSame('2001:db8::1', Event::normaliseIp('2001:db8::1'));
});

test('NUL bytes are removed so PostgreSQL text accepts the message', function (): void {
    assertSame('abc', Event::sanitiseText("a\0b\0c"));
    assertSame('ab', Event::sanitiseText('abcdef', 2));
});
