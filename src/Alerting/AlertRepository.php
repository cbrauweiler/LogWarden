<?php

declare(strict_types=1);

namespace LogWarden\Alerting;

use DateTimeImmutable;
use LogWarden\Core\Db;
use LogWarden\Rules\AlertCandidate;

/**
 * Persists alerts.
 *
 * The important behaviour is what happens when a condition keeps firing. A
 * rule with a ten-minute window evaluated every minute would otherwise produce
 * ten near-identical alerts for one incident, and an alert list nobody reads
 * is worse than no alert list. So an unacknowledged alert for the same entity
 * is updated in place: one incident, one row, growing.
 *
 * Alerts are never closed automatically. A burst that stops because the
 * attacker got in looks exactly like a burst that stops because they gave up;
 * deciding which it was is a person's job.
 */
final class AlertRepository
{
    public const CREATED = 'created';
    public const UPDATED = 'updated';

    public function __construct(private readonly Db $db)
    {
    }

    /**
     * @return array{action: string, alert_id: int, notify: bool}
     */
    public function record(
        int $ruleId,
        int $ruleSeverity,
        int $cooldownSeconds,
        AlertCandidate $candidate,
        DateTimeImmutable $windowStart,
        DateTimeImmutable $windowEnd,
    ): array {
        $severity = $candidate->severity ?? $ruleSeverity;

        $existing = $this->db->fetchRow(
            "SELECT id, severity, event_count, evidence, notified_at, window_start
               FROM alerts
              WHERE dedup_key = ? AND status = 'new'",
            [$candidate->dedupKey],
        );

        if ($existing !== null) {
            $alertId = (int) $existing['id'];
            $action  = self::UPDATED;

            $previous = json_decode((string) $existing['evidence'], true);
            $evidence = $this->mergeEvidence(
                is_array($previous) ? $previous : [],
                $candidate->evidence,
                (int) $existing['event_count'],
                $candidate->eventCount,
            );

            $this->db->execute(
                'UPDATE alerts
                    SET severity     = GREATEST(severity, ?),
                        event_count  = ?,
                        window_end   = ?::timestamptz,
                        evidence     = ?::jsonb,
                        summary      = ?,
                        last_seen_at = now(),
                        updated_at   = now()
                  WHERE id = ?',
                [
                    $severity,
                    $candidate->eventCount,
                    $windowEnd->format('Y-m-d H:i:s.uP'),
                    json_encode($evidence, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
                    $candidate->summary,
                    $alertId,
                ],
            );
        } else {
            $alertId = (int) $this->db->fetchValue(
                'INSERT INTO alerts (
                    rule_id, window_start, window_end, severity, dedup_key,
                    title, summary, entity_user, entity_ip, entity_host,
                    event_count, evidence, last_seen_at
                 ) VALUES (?, ?::timestamptz, ?::timestamptz, ?, ?, ?, ?, ?, ?::inet, ?, ?, ?::jsonb, now())
                 RETURNING id',
                [
                    $ruleId,
                    $windowStart->format('Y-m-d H:i:s.uP'),
                    $windowEnd->format('Y-m-d H:i:s.uP'),
                    $severity,
                    $candidate->dedupKey,
                    $candidate->title,
                    $candidate->summary,
                    $candidate->entityUser,
                    $candidate->entityIp,
                    $candidate->entityHost,
                    $candidate->eventCount,
                    json_encode(
                        $this->mergeEvidence([], $candidate->evidence, 0, $candidate->eventCount),
                        JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
                    ),
                ],
            );

            $action = self::CREATED;
        }

        $this->linkEvents($alertId, $candidate->eventRefs);

        return [
            'action'   => $action,
            'alert_id' => $alertId,
            'notify'   => $this->shouldNotify($action, $existing, $cooldownSeconds),
        ];
    }

    /**
     * A new alert always notifies. An updated one only notifies again once the
     * cooldown has passed, so an incident that runs for an hour does not send
     * sixty chat messages.
     *
     * @param array<string, mixed>|null $existing
     */
    private function shouldNotify(string $action, ?array $existing, int $cooldownSeconds): bool
    {
        if ($action === self::CREATED) {
            return true;
        }

        $notifiedAt = $existing['notified_at'] ?? null;
        if ($notifiedAt === null) {
            return true;   // never delivered; the previous attempt failed
        }

        return (time() - strtotime((string) $notifiedAt)) >= $cooldownSeconds;
    }

    /**
     * @param array<string, mixed> $previous
     * @param array<string, mixed> $current
     * @return array<string, mixed>
     */
    private function mergeEvidence(array $previous, array $current, int $previousCount, int $currentCount): array
    {
        $merged = $current;

        // The current window shows current intensity; the peak says how bad it
        // got. Both matter when someone triages this an hour later.
        $merged['peak_count']  = max($previous['peak_count'] ?? 0, $previousCount, $currentCount);
        $merged['first_seen']  = $previous['first_seen'] ?? ($current['first_seen'] ?? null);
        $merged['evaluations'] = (int) ($previous['evaluations'] ?? 0) + 1;

        return $merged;
    }

    /** @param list<array{0:string,1:int}> $refs */
    private function linkEvents(int $alertId, array $refs): void
    {
        if ($refs === []) {
            return;
        }

        // Capped: an alert pointing at ten thousand events helps nobody, and
        // `evidence` already carries the readable summary.
        $refs = array_slice($refs, 0, 200);

        $placeholders = [];
        $params       = [];

        foreach ($refs as [$ts, $id]) {
            $placeholders[] = '(?, ?::timestamptz, ?)';
            $params[]       = $alertId;
            $params[]       = $ts;
            $params[]       = $id;
        }

        $this->db->execute(
            'INSERT INTO alert_events (alert_id, event_ts, event_id) VALUES '
            . implode(', ', $placeholders)
            . ' ON CONFLICT DO NOTHING',
            $params,
        );
    }

    public function markNotified(int $alertId): void
    {
        $this->db->execute(
            'UPDATE alerts SET notified_at = now(), notify_count = notify_count + 1 WHERE id = ?',
            [$alertId],
        );
    }

    public function acknowledge(int $alertId, string $username, ?string $note = null): void
    {
        $this->db->execute(
            "UPDATE alerts
                SET status = 'ack',
                    ack_by = (SELECT id FROM users WHERE username = ?),
                    ack_at = now(),
                    ack_note = ?,
                    updated_at = now()
              WHERE id = ? AND status = 'new'",
            [$username, $note, $alertId],
        );
    }

    public function close(int $alertId, string $username, ?string $note = null): void
    {
        $this->db->execute(
            "UPDATE alerts
                SET status = 'closed',
                    ack_by = COALESCE(ack_by, (SELECT id FROM users WHERE username = ?)),
                    ack_at = COALESCE(ack_at, now()),
                    ack_note = COALESCE(?, ack_note),
                    updated_at = now()
              WHERE id = ?",
            [$username, $note, $alertId],
        );
    }
}
