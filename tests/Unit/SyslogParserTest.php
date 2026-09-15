<?php

declare(strict_types=1);

use LogWarden\Ingest\Syslog\PeerFilter;
use LogWarden\Ingest\Syslog\SyslogParser;

test('RFC 5424 envelope is split into header and payload', function (): void {
    $lines   = fixtureLines('syslog-framing.log');
    $message = (new SyslogParser())->parse($lines[0], '10.0.0.1');

    assertSame(16, $message->facility);
    assertSame(6, $message->severity);
    assertSame('fgt-hq.corp.local', $message->hostname);
    assertSame('FortiGate', $message->appName);
    assertSame('2026-09-15T08:00:01+00:00', $message->timestamp?->format('c'));
    assertTrue(str_starts_with($message->content, 'date=2026-09-15'));
});

test('RFC 5424 structured data is stripped from the payload', function (): void {
    $lines   = fixtureLines('syslog-framing.log');
    $message = (new SyslogParser())->parse($lines[1], '10.0.0.1');

    assertSame('relay01', $message->hostname);
    assertTrue(str_starts_with($message->content, 'date=2026-09-15'), 'SD must not leak into content');
    assertFalse(str_contains($message->content, 'rsyslog'));
});

test('RFC 3164 envelope is parsed including the tag', function (): void {
    $lines   = fixtureLines('syslog-framing.log');
    $message = (new SyslogParser())->parse($lines[2], '10.0.0.1', new DateTimeImmutable('2026-09-15T09:00:00Z'));

    assertSame('fgt-hq', $message->hostname);
    assertSame('FortiGate', $message->appName);
    assertSame('2026-09-15T08:10:00+00:00', $message->timestamp?->format('c'));
    assertTrue(str_starts_with($message->content, 'date=2026-09-15'));
});

test('a December timestamp received in January belongs to the previous year', function (): void {
    $message = (new SyslogParser())->parse(
        '<189>Dec 31 23:59:00 fgt-hq FortiGate: test',
        null,
        new DateTimeImmutable('2027-01-01T00:02:00Z'),
    );

    assertSame('2026-12-31T23:59:00+00:00', $message->timestamp?->format('c'));
});

test('a FortiGate line with no envelope is passed through as content', function (): void {
    $message = (new SyslogParser())->parse('<189>date=2026-09-15 time=10:00:01 devname="FGT-60F-HQ"');

    assertSame(23, $message->facility);
    assertSame(5, $message->severity);
    assertNull($message->hostname);
    assertSame('date=2026-09-15 time=10:00:01 devname="FGT-60F-HQ"', $message->content);
});

test('an out-of-range priority is treated as payload, not dropped', function (): void {
    $message = (new SyslogParser())->parse('<999>something odd');

    assertNull($message->facility);
    assertSame('<999>something odd', $message->content);
});

test('peer filter matches IPv4 networks and rejects everything else', function (): void {
    $filter = new PeerFilter(['10.0.0.0/8', '192.168.1.10', '2001:db8::/32']);

    assertTrue($filter->allows('10.255.3.1'));
    assertTrue($filter->allows('192.168.1.10'));
    assertTrue($filter->allows('2001:db8:1234::5'));
    assertFalse($filter->allows('192.168.1.11'));
    assertFalse($filter->allows('203.0.113.9'));
    assertFalse($filter->allows('2001:db9::1'));
    assertFalse($filter->allows(null));
    assertFalse($filter->allows('not-an-ip'));
});

test('peer filter honours bit boundaries that are not byte aligned', function (): void {
    $filter = new PeerFilter(['203.0.113.0/26']);

    assertTrue($filter->allows('203.0.113.0'));
    assertTrue($filter->allows('203.0.113.63'));
    assertFalse($filter->allows('203.0.113.64'));
});

test('an empty allow list permits everything', function (): void {
    $filter = new PeerFilter([]);

    assertTrue($filter->allows('203.0.113.9'));
    assertTrue($filter->allows(null));
});
