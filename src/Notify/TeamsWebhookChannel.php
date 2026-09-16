<?php

declare(strict_types=1);

namespace LogWarden\Notify;

use RuntimeException;

/**
 * Delivers an alert to a Microsoft Teams incoming webhook.
 *
 * Covers both endpoint generations: the legacy Office 365 connector
 * (`*.webhook.office.com`) and the Power Automate workflow endpoint Microsoft
 * is migrating customers to. The payload is identical; only the success
 * response differs — the connector answers 200 with the body "1", the workflow
 * answers 202 Accepted.
 */
final class TeamsWebhookChannel implements ChannelInterface
{
    private const CONNECT_TIMEOUT = 8;
    private const TOTAL_TIMEOUT   = 20;

    /** Teams rejects oversized cards; fail before the network rather than after. */
    private const MAX_PAYLOAD_BYTES = 26_000;

    public function __construct(
        private readonly AdaptiveCardBuilder $cards = new AdaptiveCardBuilder(),
        private readonly ?string $proxy = null,
        private readonly bool $allowPrivateTargets = false,
    ) {
    }

    public static function type(): string
    {
        return 'teams_webhook';
    }

    public function send(array $alert, array $channel, array $branding, string $secret): NotificationResult
    {
        return $this->post($secret, $this->cards->envelope($this->cards->alertCard($alert, $branding)));
    }

    public function sendTest(array $channel, array $branding, string $secret): NotificationResult
    {
        $card = $this->cards->testCard($branding, (string) ($channel['name'] ?? 'Kanal'));

        return $this->post($secret, $this->cards->envelope($card));
    }

    /** @param array<string, mixed> $payload */
    private function post(string $url, array $payload): NotificationResult
    {
        try {
            $this->assertUsableUrl($url);
        } catch (RuntimeException $e) {
            // A bad URL will not fix itself; retrying wastes runs and hides it.
            return NotificationResult::failed(null, $e->getMessage(), retryable: false);
        }

        $body  = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        $bytes = strlen((string) $body);

        if ($body === false) {
            return NotificationResult::failed(null, 'Karte konnte nicht als JSON kodiert werden.', retryable: false);
        }

        if ($bytes > self::MAX_PAYLOAD_BYTES) {
            return NotificationResult::failed(
                null,
                sprintf('Karte ist mit %d Bytes zu groß (Grenze %d).', $bytes, self::MAX_PAYLOAD_BYTES),
                payloadBytes: $bytes,
                retryable: false,
            );
        }

        $started = microtime(true);
        $handle  = curl_init($url);

        curl_setopt_array($handle, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json; charset=utf-8'],
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT        => self::TOTAL_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            // A redirect to somewhere else is not something a webhook should
            // ask for, and following one would leak the payload.
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'LogWarden',
        ]);

        // Belt and braces alongside the https check in assertUsableUrl.
        // CURLOPT_PROTOCOLS_STR needs curl 7.85+; the older constant is the
        // fallback on distributions that ship something less recent.
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            curl_setopt($handle, CURLOPT_PROTOCOLS_STR, 'https');
        } elseif (defined('CURLOPT_PROTOCOLS')) {
            curl_setopt($handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        }

        if ($this->proxy !== null && $this->proxy !== '') {
            curl_setopt($handle, CURLOPT_PROXY, $this->proxy);
        }

        $response   = curl_exec($handle);
        $status     = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $curlError  = curl_error($handle);
        $durationMs = (int) round((microtime(true) - $started) * 1000);
        curl_close($handle);

        if ($response === false) {
            return NotificationResult::failed(null, 'Netzwerkfehler: ' . $curlError, $durationMs, $bytes);
        }

        if ($status >= 200 && $status < 300) {
            return NotificationResult::ok($status, $durationMs, $bytes);
        }

        $detail = trim(substr((string) $response, 0, 400));

        return NotificationResult::failed(
            $status,
            "HTTP {$status}" . ($detail === '' ? '' : ': ' . $detail),
            $durationMs,
            $bytes,
            // 4xx means Teams rejected this request as it stands; only 408 and
            // 429 are worth trying again.
            retryable: $status >= 500 || in_array($status, [408, 429], true),
        );
    }

    /**
     * The webhook URL is admin-supplied, and this process can reach the whole
     * internal network. Without these checks LogWarden would happily act as a
     * request proxy into it.
     */
    public function assertUsableUrl(string $url): void
    {
        $parts = parse_url($url);

        if ($parts === false || empty($parts['host'])) {
            throw new RuntimeException('Webhook-URL ist ungültig.');
        }

        if (($parts['scheme'] ?? '') !== 'https') {
            throw new RuntimeException('Webhook-URL muss https verwenden.');
        }

        $host = $parts['host'];

        if ($this->allowPrivateTargets) {
            return;
        }

        // A hostname that already is an address skips DNS; otherwise resolve,
        // because "internal.corp.local" pointing at 10.0.0.1 is the same risk.
        $addresses = filter_var($host, FILTER_VALIDATE_IP) !== false
            ? [$host]
            : array_merge(gethostbynamel($host) ?: [], $this->resolveV6($host));

        if ($addresses === []) {
            throw new RuntimeException("Webhook-Host '{$host}' ist nicht auflösbar.");
        }

        foreach ($addresses as $address) {
            if (filter_var(
                $address,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            ) === false) {
                throw new RuntimeException(
                    "Webhook-Host '{$host}' zeigt auf eine interne Adresse ({$address}). "
                    . 'Für einen internen Relay notify.allow_private_targets aktivieren.'
                );
            }
        }
    }

    /** @return list<string> */
    private function resolveV6(string $host): array
    {
        $records = @dns_get_record($host, DNS_AAAA);

        return $records === false
            ? []
            : array_values(array_filter(array_column($records, 'ipv6')));
    }
}
