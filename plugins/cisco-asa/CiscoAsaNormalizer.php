<?php

declare(strict_types=1);

namespace LogWarden\Plugin\CiscoAsa;

use DateTimeImmutable;
use LogWarden\Event\Event;
use LogWarden\Event\EventResult;
use LogWarden\Event\NormalizerInterface;
use LogWarden\Event\SourceType;
use LogWarden\Ingest\Syslog\SyslogMessage;
use LogWarden\Ingest\Syslog\SyslogParser;

/**
 * Cisco ASA syslog.
 *
 * Every ASA line carries `%ASA-<severity>-<message id>: <text>` — the id is
 * the only reliable thing about it. The text after it has at least three
 * different field styles depending on which subsystem emitted it, and Cisco
 * has changed them between releases, so each is parsed explicitly rather than
 * through one hopeful regular expression.
 */
final class CiscoAsaNormalizer implements NormalizerInterface
{
    /** `%ASA-6-113005:` and the Firepower variants `%FTD-`, `%ASASM-`. */
    private const HEADER = '/%(?:ASA|FTD|ASASM)(?:-\w+)?-(\d)-(\d{6}):\s*(.*)$/s';

    public function __construct(private readonly SyslogParser $syslog = new SyslogParser())
    {
    }

    public function supports(string $raw, array $context = []): bool
    {
        return preg_match(self::HEADER, $raw) === 1;
    }

    /** @return list<Event> */
    public function normalize(string $raw, array $context = []): array
    {
        if (preg_match(self::HEADER, $raw, $m) !== 1) {
            return [];
        }

        [, $severity, $id, $body] = $m;

        $message = $this->syslog->parse($raw, isset($context['peer']) ? (string) $context['peer'] : null);

        $meaning = AsaMessageCatalog::describe($id);

        // Unknown ids are dropped rather than stored. An ASA emits hundreds of
        // message types and the bulk of them are per-connection bookkeeping —
        // keeping the unknown ones would mean keeping exactly the flood this
        // catalogue exists to exclude. The Windows collector does the opposite
        // because there the channel is already filtered on the host.
        if ($meaning === null) {
            return [];
        }

        $fields = $this->fields($body);
        $user   = Event::normaliseUsername($fields['user'] ?? null);
        $ip     = Event::normaliseIp($fields['ip'] ?? null);

        $type = $meaning['role'] === 'vpn' ? 'cisco_asa_vpn' : 'cisco_asa_auth';

        $details = array_filter([
            'label'     => $meaning['label'],
            'msg_id'    => $id,
            'severity'  => (int) $severity,
            'group'     => $fields['group'] ?? null,
            'reason'    => AsaMessageCatalog::reason($fields['reason'] ?? null),
            'server'    => $fields['server'] ?? null,
            'interface' => $fields['interface'] ?? null,
            'assigned_ip' => $fields['assigned_ip'] ?? null,
            'user_raw'  => $fields['user'] ?? null,
        ], static fn (mixed $v): bool => $v !== null && $v !== '');

        return [new Event(
            ts:         $this->timestamp($message, $context),
            sourceType: SourceType::of($type),
            sourceHost: $this->host($message, $context),
            eventType:  $id,
            rawMessage: Event::sanitiseText(trim($raw), 2000),
            username:   $user,
            srcIp:      $ip,
            dstIp:      null,
            result:     $meaning['result'] ?? EventResult::Info,
            details:    $details,
        )];
    }

    /**
     * Pulls the fields out of the message body.
     *
     * Three styles appear, sometimes two of them in one line:
     *   Group <SSL-VPN> User <asmith> IP <203.0.113.5>
     *   Group = SSL-VPN, Username = asmith, IP = 203.0.113.5
     *   reason = Invalid password : server = 10.0.0.10 : user = pweber
     * plus `for user "admin"` and `Uname: asmith` in the management messages.
     *
     * @return array<string, string>
     */
    private function fields(string $body): array
    {
        $out = [];

        // Angle-bracket style
        if (preg_match('/\bGroup\s*<([^>]*)>/i', $body, $m) === 1) {
            $out['group'] = trim($m[1]);
        }
        if (preg_match('/\bUser\s*<([^>]*)>/i', $body, $m) === 1) {
            $out['user'] = trim($m[1]);
        }
        if (preg_match('/\bIP\s*<([^>]*)>/i', $body, $m) === 1) {
            $out['ip'] = trim($m[1]);
        }
        if (preg_match('/\bIPv4 Address\s*<([^>]*)>/i', $body, $m) === 1) {
            $out['assigned_ip'] = trim($m[1]);
        }

        // Comma style
        if (preg_match('/\bGroup\s*=\s*([^,]+)/i', $body, $m) === 1) {
            $out['group'] ??= trim($m[1]);
        }
        if (preg_match('/\bUsername\s*=\s*([^,]+)/i', $body, $m) === 1) {
            $out['user'] ??= trim($m[1]);
        }
        if (preg_match('/\bIP\s*=\s*([0-9a-fA-F.:]+)/i', $body, $m) === 1) {
            $out['ip'] ??= trim($m[1]);
        }

        // Colon-separated key = value style. The user field here may legally
        // contain spaces, so it runs to the next " : " rather than to the next
        // whitespace.
        foreach (['reason', 'server', 'user'] as $key) {
            if (preg_match('/\b' . $key . '\s*=\s*(.*?)(?=\s+:\s|\s*$)/i', $body, $m) === 1) {
                $value = trim($m[1], " \t\n\r\0\x0B:");
                if ($value !== '') {
                    $out[$key] ??= $value;
                }
            }
        }

        // `for user "admin"` in 605004/605005
        if (preg_match('/\bfor user\s+"([^"]*)"/i', $body, $m) === 1) {
            $out['user'] = trim($m[1]);
        }

        // `Uname: asmith` in 611101/611102
        if (preg_match('/\bUname:\s*(\S+)/i', $body, $m) === 1) {
            $out['user'] ??= trim($m[1]);
        }

        // `User user1 locked out` in 113006
        if (preg_match('/\bUser\s+(\S+)\s+locked out/i', $body, $m) === 1) {
            $out['user'] = trim($m[1]);
        }

        // `from 203.0.113.9/44321 to outside:198.51.100.1/ssh`
        if (preg_match('/\bfrom\s+([0-9.]+|[0-9a-fA-F:]+)(?:\/\d+)?\s+to\s+(\w+):/i', $body, $m) === 1) {
            $out['ip']        ??= $m[1];
            $out['interface'] ??= $m[2];
        }

        // `user IP = 203.0.113.5`
        if (preg_match('/\buser IP\s*=\s*([0-9a-fA-F.:]+)/i', $body, $m) === 1) {
            $out['ip'] = trim($m[1]);
        }

        return $out;
    }

    /**
     * The ASA's own clock, falling back to arrival time.
     *
     * An ASA without `logging timestamp` sends no timestamp at all, and one
     * whose NTP has drifted sends a wrong one — both are common enough that
     * the fallback is not theoretical.
     */
    private function timestamp(SyslogMessage $message, array $context): DateTimeImmutable
    {
        return $message->timestamp
            ?? ($context['received_at'] ?? new DateTimeImmutable('now'));
    }

    private function host(SyslogMessage $message, array $context): string
    {
        $host = $message->hostname;

        if ($host !== null && $host !== '' && $host !== '-') {
            return Event::sanitiseText($host, 255);
        }

        return Event::sanitiseText((string) ($message->peer ?? $context['peer'] ?? 'unbekannt'), 255);
    }
}
