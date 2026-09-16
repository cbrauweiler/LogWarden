<?php

declare(strict_types=1);

namespace LogWarden\Notify;

use LogWarden\Alerting\AlertRepository;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use LogWarden\Security\SecretBox;
use Throwable;

/**
 * Decides what to deliver where, and when to stop trying.
 *
 * Gating happens per (alert, channel) pair rather than per alert: one channel
 * being unreachable must not suppress delivery to the others, and a retry to
 * the broken one must not resend to the working ones.
 */
final class Dispatcher
{
    /** Consecutive failures before a pair is given up on. */
    private const MAX_ATTEMPTS = 5;

    /** Backoff per consecutive failure, in seconds. */
    private const BACKOFF = [60, 120, 300, 900, 1800];

    /** Teams throttles bursts; pace the sends rather than collect 429s. */
    private const SEND_DELAY_US = 250_000;

    public function __construct(
        private readonly Db $db,
        private readonly SecretBox $secrets,
        private readonly ChannelFactory $factory,
        private readonly AlertRepository $alerts,
        private readonly Logger $logger,
        private readonly array $branding = [],
    ) {
    }

    /**
     * @return array{considered:int, sent:int, failed:int, skipped:int, unrouted:int}
     */
    public function run(bool $dryRun = false, int $maxAlerts = 200): array
    {
        $stats = ['considered' => 0, 'sent' => 0, 'failed' => 0, 'skipped' => 0, 'unrouted' => 0];

        foreach ($this->openAlerts($maxAlerts) as $alert) {
            $stats['considered']++;

            $channels = $this->channelsFor((int) $alert['rule_id'], (int) $alert['severity']);

            if ($channels === []) {
                $stats['unrouted']++;
                // Worth saying: "no Teams messages arrive" is almost always
                // this, and it is invisible otherwise.
                $this->logger->debug('Alert has no matching channel', [
                    'alert_id' => $alert['id'],
                    'rule'     => $alert['rule_name'],
                    'severity' => $alert['severity'],
                ]);
                continue;
            }

            $anyDelivered = false;

            foreach ($channels as $channel) {
                $decision = $this->due($alert, $channel);

                if (!$decision['due']) {
                    $stats['skipped']++;
                    continue;
                }

                if ($dryRun) {
                    $this->logger->info('[dry-run] would notify', [
                        'alert_id' => $alert['id'],
                        'channel'  => $channel['name'],
                        'title'    => $alert['title'],
                    ]);
                    $stats['sent']++;
                    continue;
                }

                $result = $this->deliver($alert, $channel, $decision['attempt']);

                if ($result->delivered) {
                    $stats['sent']++;
                    $anyDelivered = true;
                } else {
                    $stats['failed']++;
                }

                usleep(self::SEND_DELAY_US);
            }

            if ($anyDelivered && !$dryRun) {
                $this->alerts->markNotified((int) $alert['id']);
            }
        }

        return $stats;
    }

    /**
     * Sends a fixed test card, so a channel can be proven before an incident
     * depends on it.
     *
     * @return array{ok: bool, message: string}
     */
    public function test(int $channelId): array
    {
        $channel = $this->db->fetchRow('SELECT * FROM notification_channels WHERE id = ?', [$channelId]);

        if ($channel === null) {
            return ['ok' => false, 'message' => 'Kanal nicht gefunden.'];
        }

        try {
            $secret = $this->secretFor($channel);
        } catch (Throwable $e) {
            return ['ok' => false, 'message' => $e->getMessage()];
        }

        $result = $this->factory
            ->get((string) $channel['type'])
            ->sendTest($channel, $this->branding, $secret);

        $this->recordChannelHealth((int) $channel['id'], $result);

        return $result->delivered
            ? ['ok' => true, 'message' => sprintf(
                'Testnachricht zugestellt (HTTP %d, %d ms).',
                $result->httpStatus ?? 0,
                $result->durationMs,
            )]
            : ['ok' => false, 'message' => 'Zustellung fehlgeschlagen: ' . $result->error];
    }

    // -----------------------------------------------------------------------

    /** @return list<array<string, mixed>> */
    private function openAlerts(int $limit): array
    {
        return $this->db->fetchAll(
            "SELECT a.id, a.rule_id, a.severity, a.title, a.summary, a.event_count,
                    a.entity_user, host(a.entity_ip) AS entity_ip, a.entity_host,
                    a.evidence, a.notified_at,
                    to_char(a.triggered_at, 'DD.MM.YYYY HH24:MI') AS triggered_label,
                    r.name AS rule_name, r.cooldown_s
               FROM alerts a
               JOIN rules r ON r.id = a.rule_id
              WHERE a.status = 'new'
              ORDER BY a.severity DESC, a.triggered_at
              LIMIT ?",
            [$limit],
        );
    }

    /** @return list<array<string, mixed>> */
    private function channelsFor(int $ruleId, int $severity): array
    {
        return $this->db->fetchAll(
            'SELECT c.*
               FROM notification_channels c
               JOIN rule_channels rc ON rc.channel_id = c.id
              WHERE rc.rule_id = ?
                AND c.enabled
                AND c.min_severity <= ?
              ORDER BY c.name',
            [$ruleId, $severity],
        );
    }

    /**
     * @param array<string, mixed> $alert
     * @param array<string, mixed> $channel
     * @return array{due: bool, attempt: int}
     */
    private function due(array $alert, array $channel): array
    {
        $last = $this->db->fetchRow(
            'SELECT attempt, delivered, extract(epoch FROM (now() - sent_at))::int AS age
               FROM notification_log
              WHERE alert_id = ? AND channel_id = ?
              ORDER BY sent_at DESC
              LIMIT 1',
            [(int) $alert['id'], (int) $channel['id']],
        );

        if ($last === null) {
            return ['due' => true, 'attempt' => 1];
        }

        $age = (int) $last['age'];

        if ((bool) $last['delivered']) {
            // Delivered before; the rule's cooldown decides whether an ongoing
            // incident is worth mentioning again.
            return ['due' => $age >= (int) $alert['cooldown_s'], 'attempt' => 1];
        }

        $attempt = (int) $last['attempt'];

        if ($attempt >= self::MAX_ATTEMPTS) {
            return ['due' => false, 'attempt' => $attempt];
        }

        $wait = self::BACKOFF[$attempt - 1] ?? self::BACKOFF[count(self::BACKOFF) - 1];

        return ['due' => $age >= $wait, 'attempt' => $attempt + 1];
    }

    /**
     * @param array<string, mixed> $alert
     * @param array<string, mixed> $channel
     */
    private function deliver(array $alert, array $channel, int $attempt): NotificationResult
    {
        try {
            $secret = $this->secretFor($channel);
        } catch (Throwable $e) {
            $result = NotificationResult::failed(null, $e->getMessage(), retryable: false);
            $this->record($alert, $channel, $attempt, $result);

            return $result;
        }

        try {
            $result = $this->factory
                ->get((string) $channel['type'])
                ->send($alert, $channel, $this->branding, $secret);
        } catch (Throwable $e) {
            $result = NotificationResult::failed(null, 'Unerwarteter Fehler: ' . $e->getMessage());
        }

        $this->record($alert, $channel, $attempt, $result);

        if ($result->delivered) {
            $this->logger->info('Alert notified', [
                'alert_id' => $alert['id'],
                'channel'  => $channel['name'],
                'ms'       => $result->durationMs,
            ]);
        } else {
            $this->logger->warning('Notification failed', [
                'alert_id'  => $alert['id'],
                'channel'   => $channel['name'],
                'attempt'   => $attempt,
                'error'     => $result->error,
                'retryable' => $result->retryable,
            ]);
        }

        return $result;
    }

    /** @param array<string, mixed> $channel */
    private function secretFor(array $channel): string
    {
        $ref = $channel['secret_ref'] ?? null;

        if (!is_string($ref) || $ref === '') {
            throw new \RuntimeException('Für diesen Kanal ist keine Webhook-URL hinterlegt.');
        }

        $secret = $this->secrets->get($ref);

        if ($secret === null || trim($secret) === '') {
            throw new \RuntimeException("Webhook-URL '{$ref}' ist nicht im Schlüsselspeicher vorhanden.");
        }

        return trim($secret);
    }

    /**
     * @param array<string, mixed> $alert
     * @param array<string, mixed> $channel
     */
    private function record(array $alert, array $channel, int $attempt, NotificationResult $result): void
    {
        // A non-retryable failure is written at the attempt ceiling so the
        // backoff logic stops immediately instead of counting to five against
        // something that will never work.
        $storedAttempt = ($result->delivered || $result->retryable)
            ? $attempt
            : self::MAX_ATTEMPTS;

        $this->db->execute(
            'INSERT INTO notification_log
                (alert_id, channel_id, attempt, http_status, error, delivered, duration_ms, payload_bytes)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
                (int) $alert['id'],
                (int) $channel['id'],
                $storedAttempt,
                $result->httpStatus,
                $result->error === null ? null : substr($result->error, 0, 2000),
                $result->delivered ? 'true' : 'false',
                $result->durationMs,
                $result->payloadBytes,
            ],
        );

        $this->recordChannelHealth((int) $channel['id'], $result);
    }

    private function recordChannelHealth(int $channelId, NotificationResult $result): void
    {
        if ($result->delivered) {
            $this->db->execute(
                'UPDATE notification_channels
                    SET last_success_at = now(), sent_total = sent_total + 1,
                        last_error = NULL, last_error_at = NULL
                  WHERE id = ?',
                [$channelId],
            );

            return;
        }

        $this->db->execute(
            'UPDATE notification_channels
                SET failed_total = failed_total + 1,
                    last_error = ?, last_error_at = now()
              WHERE id = ?',
            [substr((string) $result->error, 0, 2000), $channelId],
        );
    }
}
