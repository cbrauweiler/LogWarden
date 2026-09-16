<?php

declare(strict_types=1);

namespace LogWarden\Plugin\Fortigate;

use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\NormalizerInterface;
use LogWarden\Event\SourceType;
use LogWarden\Ingest\Syslog\SyslogMessage;
use LogWarden\Ingest\Syslog\SyslogParser;

/**
 * Turns FortiGate syslog into normalised events.
 *
 * Handles both wire formats FortiOS can emit — native key=value and CEF — and
 * keeps only the two categories this system cares about: VPN activity
 * (logid 0101…, subtype "vpn") and authentication (logid 0102…, subtype
 * "user"). Everything else is dropped at this stage; traffic and UTM logs
 * would otherwise dominate the store without serving any of the rules.
 */
final class FortigateNormalizer implements NormalizerInterface
{
    /** Actions that are unambiguous regardless of any status field. */
    private const FAIL_ACTIONS = [
        'ssl-login-fail', 'login-fail', 'auth-logon-failed', 'auth-failed',
        'ssl-new-con-fail', 'tunnel-up-fail', 'negotiate-fail', 'phase1-fail',
        'phase2-fail', 'auth-lockout',
    ];

    private const SUCCESS_ACTIONS = [
        'tunnel-up', 'ssl-login', 'auth-logon', 'authentication-success',
        'login', 'phase1-up', 'phase2-up', 'ssl-new-con',
    ];

    private const INFO_ACTIONS = [
        'tunnel-down', 'ssl-logout', 'logout', 'auth-logout', 'timeout',
        'tunnel-stats', 'phase1-down', 'phase2-down',
    ];

    public function __construct(
        private readonly CefParser $cef = new CefParser(),
        private readonly FortigateKvParser $kv = new FortigateKvParser(),
        private readonly SyslogParser $syslog = new SyslogParser(),
    ) {
    }

    public function supports(string $raw, array $context = []): bool
    {
        $content = $this->content($raw, $context);

        if (CefParser::looksLikeCef($content)) {
            $parsed = $this->cef->parse($content);

            return $parsed !== null && stripos($parsed['vendor'], 'fortinet') !== false;
        }

        return FortigateKvParser::looksLikeFortigate($content);
    }

    /** @return list<Event> */
    public function normalize(string $raw, array $context = []): array
    {
        $message = $this->message($raw, $context);
        $content = $message->content;

        $fields = CefParser::looksLikeCef($content)
            ? $this->fromCef($content)
            : $this->fromKv($content);

        if ($fields === null) {
            return [];
        }

        $sourceType = $this->classify($fields);
        if ($sourceType === null) {
            return [];
        }

        $receivedAt = $context['received_at'] ?? new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $sourceHost = $this->pick($fields, ['devname', 'dvchost', 'devid'])
            ?? $message->hostname
            ?? $message->peer
            ?? 'unknown-fortigate';

        $rawMessage = Event::sanitiseText($message->raw, 32768);
        $eventType  = $this->eventType($fields, $sourceType);

        return [new Event(
            ts:         $this->timestamp($fields, $message, $receivedAt),
            sourceType: $sourceType,
            sourceHost: Event::sanitiseText($sourceHost, 255),
            eventType:  $eventType,
            rawMessage: $rawMessage,
            username:   Event::normaliseUsername($this->pick($fields, ['user', 'suser', 'duser', 'srcname'])),
            srcIp:      Event::normaliseIp($this->pick($fields, ['remip', 'srcip', 'src', 'tunnelip'])),
            dstIp:      Event::normaliseIp($this->pick($fields, ['dstip', 'dst', 'dev_ip'])),
            result:     $this->result($fields),
            details:    $this->details($fields, $message),
        )];
    }

    // -----------------------------------------------------------------------
    // Format handling
    // -----------------------------------------------------------------------

    /** @return array<string,string>|null */
    private function fromKv(string $content): ?array
    {
        $fields = $this->kv->parse($content);

        return $fields === [] ? null : $fields;
    }

    /** @return array<string,string>|null */
    private function fromCef(string $content): ?array
    {
        $parsed = $this->cef->parse($content);
        if ($parsed === null) {
            return null;
        }

        $fields = $parsed['extensions'];

        // Fold the header into the same flat map the KV branch produces, so
        // classification and field lookup work identically for both formats.
        $fields['logid']    ??= $parsed['signature_id'];
        $fields['logdesc']  ??= $parsed['name'];
        $fields['cef_name']   = $parsed['name'];
        $fields['cef_vendor'] = $parsed['vendor'];
        $fields['cef_severity'] = $parsed['severity'];

        if (isset($fields['deviceExternalId']) && !isset($fields['devid'])) {
            $fields['devid'] = $fields['deviceExternalId'];
        }
        if (isset($fields['act']) && !isset($fields['action'])) {
            $fields['action'] = $fields['act'];
        }
        if (isset($fields['cat']) && !isset($fields['subtype'])) {
            $fields['subtype'] = $fields['cat'];
        }
        if (isset($fields['outcome']) && !isset($fields['status'])) {
            $fields['status'] = $fields['outcome'];
        }

        return $fields;
    }

    // -----------------------------------------------------------------------
    // Classification
    // -----------------------------------------------------------------------

    /** @param array<string,string> $fields */
    private function classify(array $fields): ?SourceType
    {
        $logid   = (string) ($fields['logid'] ?? '');
        $subtype = strtolower((string) ($fields['subtype'] ?? ''));
        $action  = strtolower((string) ($fields['action'] ?? ''));

        // FortiOS log IDs are the most reliable signal: 0101… is event/vpn,
        // 0102… is event/user.
        if (str_starts_with($logid, '0101')) {
            return SourceType::of('fortigate_vpn');
        }
        if (str_starts_with($logid, '0102')) {
            return SourceType::of('fortigate_auth');
        }

        if ($subtype === 'vpn' || str_contains($subtype, 'vpn')) {
            return SourceType::of('fortigate_vpn');
        }
        if (in_array($subtype, ['user', 'auth', 'authentication'], true)) {
            return SourceType::of('fortigate_auth');
        }

        if (str_contains($action, 'tunnel') || str_contains($action, 'ssl-login') || str_contains($action, 'ssl-logout')) {
            return SourceType::of('fortigate_vpn');
        }
        if (str_contains($action, 'auth') || str_contains($action, 'login') || str_contains($action, 'logout')) {
            return SourceType::of('fortigate_auth');
        }

        return null;
    }

    /** @param array<string,string> $fields */
    private function eventType(array $fields, SourceType $sourceType): string
    {
        $candidate = $this->pick($fields, ['action', 'cef_name', 'logdesc', 'subtype']);

        if ($candidate === null || $candidate === '') {
            // ->is(), not ===: SourceType is a value object now, and two
            // instances of the same type are equal without being identical.
            return $sourceType->is('fortigate_vpn') ? 'vpn-event' : 'auth-event';
        }

        // Normalise to a stable, lowercase, dash-separated token; event_type is
        // a filter facet in the UI and must not fragment on spacing or case.
        $candidate = strtolower(trim($candidate));
        $candidate = preg_replace('/[^a-z0-9]+/', '-', $candidate) ?? $candidate;

        return trim($candidate, '-') !== '' ? trim($candidate, '-') : 'unknown';
    }

    /** @param array<string,string> $fields */
    private function result(array $fields): EventResult
    {
        $status = strtolower(trim((string) ($fields['status'] ?? '')));
        $action = strtolower(trim((string) ($fields['action'] ?? '')));

        if (in_array($action, self::FAIL_ACTIONS, true)) {
            return EventResult::Fail;
        }
        if (in_array($action, self::SUCCESS_ACTIONS, true)) {
            return EventResult::Success;
        }

        if (in_array($status, ['failure', 'failed', 'fail', 'deny', 'denied'], true)) {
            return EventResult::Fail;
        }
        if (in_array($status, ['success', 'succeeded', 'ok', 'accept', 'allow'], true)) {
            return EventResult::Success;
        }

        if (in_array($action, self::INFO_ACTIONS, true)) {
            return EventResult::Info;
        }

        // A trailing "-fail"/"-failed" covers actions FortiOS adds between
        // firmware releases without needing the table above to be exhaustive.
        if (preg_match('/(^|-)(fail(ed|ure)?|denied|error)$/', $action) === 1) {
            return EventResult::Fail;
        }

        return EventResult::Info;
    }

    // -----------------------------------------------------------------------
    // Timestamp
    // -----------------------------------------------------------------------

    /** @param array<string,string> $fields */
    private function timestamp(
        array $fields,
        SyslogMessage $message,
        DateTimeImmutable $receivedAt,
    ): DateTimeImmutable {
        foreach (['eventtime', 'FTNTFGTeventtime', 'rt'] as $key) {
            $value = $fields[$key] ?? null;
            if ($value !== null && $value !== '' && ctype_digit($value)) {
                $parsed = $this->fromEpoch($value);
                if ($parsed !== null) {
                    return $parsed;
                }
            }
        }

        $date = $fields['date'] ?? null;
        $time = $fields['time'] ?? null;
        if ($date !== null && $time !== null && $date !== '' && $time !== '') {
            $tz     = $fields['tz'] ?? '+0000';
            $parsed = DateTimeImmutable::createFromFormat('Y-m-d H:i:s O', "{$date} {$time} {$tz}");
            if ($parsed !== false) {
                return $parsed->setTimezone(new DateTimeZone('UTC'));
            }
        }

        return $message->timestamp?->setTimezone(new DateTimeZone('UTC')) ?? $receivedAt;
    }

    /**
     * FortiOS changed the unit of `eventtime` across releases: seconds up to
     * 6.0, nanoseconds from 6.2. Deriving the unit from the digit count keeps
     * one parser working across a mixed-firmware estate.
     */
    private function fromEpoch(string $digits): ?DateTimeImmutable
    {
        $length = strlen($digits);

        $micros = match (true) {
            $length >= 18 => (int) substr($digits, 0, 16),          // nanoseconds
            $length >= 16 => (int) $digits,                          // microseconds
            $length >= 13 => (int) $digits * 1000,                   // milliseconds
            $length >= 9  => (int) $digits * 1_000_000,              // seconds
            default       => null,
        };

        if ($micros === null) {
            return null;
        }

        $parsed = DateTimeImmutable::createFromFormat(
            'U.u',
            sprintf('%d.%06d', intdiv($micros, 1_000_000), $micros % 1_000_000),
            new DateTimeZone('UTC'),
        );

        return $parsed === false ? null : $parsed->setTimezone(new DateTimeZone('UTC'));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Source-specific fields that do not fit the common schema. Stored as
     * jsonb and GIN-indexed, so `details @> '{"tunneltype":"ssl-tunnel"}'`
     * stays an indexed lookup.
     *
     * @param array<string,string> $fields
     * @return array<string, mixed>
     */
    private function details(array $fields, SyslogMessage $message): array
    {
        $keep = [
            'logid', 'devid', 'vd', 'level', 'logdesc', 'action', 'status', 'reason',
            'msg', 'group', 'tunneltype', 'tunnelid', 'tunnelip', 'method', 'authproto',
            'srcport', 'dstport', 'dst_host', 'sentbyte', 'rcvdbyte', 'duration',
            'policyid', 'profile', 'xauthuser', 'assignip', 'cef_name', 'cef_severity',
        ];

        $details = [];
        foreach ($keep as $key) {
            $value = $fields[$key] ?? null;
            if ($value !== null && $value !== '') {
                $details[$key] = Event::sanitiseText((string) $value, 1024);
            }
        }

        // Keep the login name exactly as sent; the `username` column holds the
        // domain-stripped form used for cross-source correlation.
        $userRaw = $this->pick($fields, ['user', 'suser', 'duser', 'srcname']);
        if ($userRaw !== null) {
            $details['user_raw'] = Event::sanitiseText($userRaw, 255);
        }

        if ($message->severity !== null) {
            $details['syslog_severity'] = $message->severity;
        }
        if ($message->peer !== null) {
            $details['peer'] = $message->peer;
        }

        return $details;
    }

    /** @param array<string,string> $fields @param list<string> $keys */
    private function pick(array $fields, array $keys): ?string
    {
        foreach ($keys as $key) {
            $value = $fields[$key] ?? null;
            if ($value !== null && trim($value) !== '') {
                return trim($value);
            }
        }

        return null;
    }

    private function content(string $raw, array $context): string
    {
        return $this->message($raw, $context)->content;
    }

    private function message(string $raw, array $context): SyslogMessage
    {
        $message = $context['syslog'] ?? null;

        return $message instanceof SyslogMessage
            ? $message
            : $this->syslog->parse($raw, $context['peer'] ?? null);
    }
}
