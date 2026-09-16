<?php

declare(strict_types=1);

namespace LogWarden\Alerting;

use LogWarden\Core\Db;

/**
 * Read queries behind the alerts view.
 */
final class AlertQuery
{
    public const SEVERITY_LABELS = [
        1 => 'Info',
        2 => 'Niedrig',
        3 => 'Mittel',
        4 => 'Hoch',
        5 => 'Kritisch',
    ];

    public const STATUS_LABELS = [
        'new'    => 'Offen',
        'ack'    => 'Quittiert',
        'closed' => 'Geschlossen',
    ];

    public function __construct(private readonly Db $db)
    {
    }

    /**
     * @param array{status?:string, severity?:int, rule_id?:int, q?:string, limit?:int} $filter
     * @return list<array<string, mixed>>
     */
    public function list(array $filter = []): array
    {
        $where  = ['1 = 1'];
        $params = [];

        if (!empty($filter['status']) && $filter['status'] !== 'all') {
            $where[]  = 'a.status = ?::alert_status_t';
            $params[] = $filter['status'];
        }

        if (!empty($filter['severity'])) {
            $where[]  = 'a.severity >= ?';
            $params[] = (int) $filter['severity'];
        }

        if (!empty($filter['rule_id'])) {
            $where[]  = 'a.rule_id = ?';
            $params[] = (int) $filter['rule_id'];
        }

        if (!empty($filter['q'])) {
            $where[]  = '(a.title ILIKE ? OR a.entity_user ILIKE ? OR host(a.entity_ip) ILIKE ?)';
            $like     = '%' . $filter['q'] . '%';
            $params[] = $like;
            $params[] = $like;
            $params[] = $like;
        }

        $params[] = (int) ($filter['limit'] ?? 100);

        return $this->db->fetchAll(
            'SELECT a.id, a.severity, a.status::text AS status, a.title, a.summary,
                    a.entity_user, host(a.entity_ip) AS entity_ip, a.entity_host,
                    a.event_count, a.evidence, a.notify_count,
                    to_char(a.triggered_at, \'DD.MM. HH24:MI\') AS triggered_label,
                    to_char(a.last_seen_at,  \'DD.MM. HH24:MI\') AS last_seen_label,
                    to_char(a.ack_at,        \'DD.MM. HH24:MI\') AS ack_label,
                    a.ack_note,
                    u.username AS ack_by_name,
                    r.name     AS rule_name,
                    r.rule_key
               FROM alerts a
               JOIN rules r ON r.id = a.rule_id
               LEFT JOIN users u ON u.id = a.ack_by
              WHERE ' . implode(' AND ', $where) . '
              ORDER BY a.status = \'new\' DESC, a.severity DESC, a.updated_at DESC
              LIMIT ?',
            $params,
        );
    }

    /** @return array<string, mixed>|null */
    public function find(int $id): ?array
    {
        return $this->db->fetchRow(
            'SELECT a.*, host(a.entity_ip) AS entity_ip_text,
                    to_char(a.triggered_at, \'DD.MM.YYYY HH24:MI:SS\') AS triggered_label,
                    to_char(a.last_seen_at,  \'DD.MM.YYYY HH24:MI:SS\') AS last_seen_label,
                    to_char(a.window_start,  \'DD.MM. HH24:MI\')        AS window_start_label,
                    to_char(a.window_end,    \'DD.MM. HH24:MI\')        AS window_end_label,
                    to_char(a.ack_at,        \'DD.MM.YYYY HH24:MI\')    AS ack_label,
                    u.username AS ack_by_name,
                    r.name AS rule_name, r.rule_key, r.params AS rule_params
               FROM alerts a
               JOIN rules r ON r.id = a.rule_id
               LEFT JOIN users u ON u.id = a.ack_by
              WHERE a.id = ?',
            [$id],
        );
    }

    /**
     * The events an alert points at.
     *
     * Joined on (ts, id) rather than id alone so PostgreSQL can prune: without
     * the timestamp this would scan every partition on disk. Events aged out of
     * retention simply do not come back — the alert's own evidence snapshot is
     * what survives.
     *
     * @return list<array<string, mixed>>
     */
    public function events(int $alertId, int $limit = 100): array
    {
        return $this->db->fetchAll(
            "SELECT e.ts, e.id, e.source_type::text AS source_type, e.source_host,
                    e.event_type, e.username, host(e.src_ip) AS src_ip,
                    e.result::text AS result, e.raw_message,
                    to_char(e.ts, 'DD.MM. HH24:MI:SS') AS ts_label,
                    to_char(e.ts, 'YYYY-MM-DD\"T\"HH24:MI:SS.USOF') AS ts_iso
               FROM alert_events ae
               JOIN events e ON e.ts = ae.event_ts AND e.id = ae.event_id
              WHERE ae.alert_id = ?
              ORDER BY e.ts DESC
              LIMIT ?",
            [$alertId, $limit],
        );
    }

    /** @return array{open:int, critical:int, today:int, unnotified:int} */
    public function counters(): array
    {
        $row = $this->db->fetchRow(
            "SELECT count(*) FILTER (WHERE status = 'new')                        AS open,
                    count(*) FILTER (WHERE status = 'new' AND severity >= 5)      AS critical,
                    count(*) FILTER (WHERE triggered_at >= date_trunc('day', now())) AS today,
                    count(*) FILTER (WHERE status = 'new' AND notified_at IS NULL) AS unnotified
               FROM alerts"
        ) ?? [];

        return [
            'open'       => (int) ($row['open'] ?? 0),
            'critical'   => (int) ($row['critical'] ?? 0),
            'today'      => (int) ($row['today'] ?? 0),
            'unnotified' => (int) ($row['unnotified'] ?? 0),
        ];
    }

    /** @return list<array<string, mixed>> */
    public function rules(): array
    {
        return $this->db->fetchAll(
            "SELECT r.id, r.name, r.rule_key, r.enabled, r.severity, r.window_minutes,
                    r.cooldown_s, r.last_error, r.last_duration_ms,
                    to_char(r.last_run_at, 'DD.MM. HH24:MI:SS') AS last_run_label,
                    count(a.id) FILTER (WHERE a.triggered_at >= now() - interval '7 days') AS alerts_7d,
                    count(a.id) FILTER (WHERE a.status = 'new')                            AS open_alerts
               FROM rules r
               LEFT JOIN alerts a ON a.rule_id = r.id
              GROUP BY r.id
              ORDER BY r.enabled DESC, r.name"
        );
    }

    public static function severityClass(int $severity): string
    {
        return match (true) {
            $severity >= 5 => 'critical',
            $severity === 4 => 'serious',
            $severity === 3 => 'warning',
            default         => 'good',
        };
    }
}
