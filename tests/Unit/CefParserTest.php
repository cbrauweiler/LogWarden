<?php

declare(strict_types=1);

use LogWarden\Ingest\Fortigate\CefParser;

test('CEF header fields are split on unescaped pipes', function (): void {
    $parsed = (new CefParser())->parse('CEF:0|Fortinet|Fortigate|v7.4.4|0101039426|ssl-login-fail|8|src=1.2.3.4');

    assertSame(0, $parsed['version']);
    assertSame('Fortinet', $parsed['vendor']);
    assertSame('Fortigate', $parsed['product']);
    assertSame('v7.4.4', $parsed['device_version']);
    assertSame('0101039426', $parsed['signature_id']);
    assertSame('ssl-login-fail', $parsed['name']);
    assertSame('8', $parsed['severity']);
});

test('escaped pipes stay inside the header field they belong to', function (): void {
    $parsed = (new CefParser())->parse('CEF:0|Vendor|Prod|1.0|100|Login a\|b failed|5|src=1.2.3.4');

    assertSame('Login a|b failed', $parsed['name']);
    assertSame(['src' => '1.2.3.4'], $parsed['extensions']);
});

test('extension values may contain spaces', function (): void {
    $fields = (new CefParser())->parseExtensions('src=1.2.3.4 msg=SSL user failed to logged in act=ssl-login-fail');

    assertSame('1.2.3.4', $fields['src']);
    assertSame('SSL user failed to logged in', $fields['msg']);
    assertSame('ssl-login-fail', $fields['act']);
});

test('escaped equals signs do not start a new key', function (): void {
    $fields = (new CefParser())->parseExtensions('suser=jdoe cs2=a\=b act=login');

    assertSame('jdoe', $fields['suser']);
    assertSame('a=b', $fields['cs2']);
    assertSame('login', $fields['act']);
});

test('custom field labels replace their csN key', function (): void {
    $fields = (new CefParser())->parseExtensions('cs1Label=method cs1=fortitoken src=1.2.3.4');

    assertSame('fortitoken', $fields['method'] ?? null);
    assertFalse(isset($fields['cs1']));
    assertFalse(isset($fields['cs1Label']));
});

test('a line without a CEF marker is rejected', function (): void {
    assertNull((new CefParser())->parse('date=2026-09-15 time=10:00:01 devname="FGT"'));
});

test('a truncated CEF header is rejected rather than half-parsed', function (): void {
    assertNull((new CefParser())->parse('CEF:0|Fortinet|Fortigate|v7.4.4'));
});
