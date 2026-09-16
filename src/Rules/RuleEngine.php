<?php

declare(strict_types=1);

namespace LogWarden\Rules;

use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Alerting\AlertRepository;
use LogWarden\Core\Db;
use LogWarden\Core\Logger;
use Throwable;

/**
 * Loads enabled rules, evaluates each over its own window and hands the
 * findings to the alert repository.
 *
 * One rule failing must never stop the others: a broken detection is bad, a
 * silent detection pipeline is worse.
 */
final class RuleEngine
{
    public function __construct(
        private readonly Db $db,
        private readonly AlertRepository $alerts,
        private readonly Logger $logger,
        private readonly RuleRegistry $registry,
    ) {
    }

    /**
     * @return array{evaluated:int, created:int, updated:int, failed:int, notify: list<int>}
     */
    public function run(bool $dryRun = false, ?string $onlyKey = null): array
    {
        $stats  = ['evaluated' => 0, 'created' => 0, 'updated' => 0, 'failed' => 0, 'notify' => []];
        $now    = new DateTimeImmutable('now', new DateTimeZone('UTC'));

        foreach ($this->enabledRules($onlyKey) as $row) {
            $stats['evaluated']++;

            try {
                $this->runOne($row, $now, $dryRun, $stats);
            } catch (Throwable $e) {
                $stats['failed']++;
                $this->logger->error('Rule failed', [
                    'rule'  => $row['name'],
                    'key'   => $row['rule_key'],
                    'error' => $e->getMessage(),
                ]);

                if (!$dryRun) {
                    $this->db->execute(
                        'UPDATE rules SET last_run_at = now(), last_error = ? WHERE id = ?',
                        [substr($e->getMessage(), 0, 2000), (int) $row['id']],
                    );
                }
            }
        }

        return $stats;
    }

    /**
     * @param array<string, mixed> $row
     * @param array{evaluated:int, created:int, updated:int, failed:int, notify: list<int>} $stats
     */
    private function runOne(array $row, DateTimeImmutable $now, bool $dryRun, array &$stats): void
    {
        $rule   = $this->registry->get((string) $row['rule_key']);
        $params = $this->resolveParams($rule, $row);

        // Stop short of now() so the window is not judged while it is still
        // filling: syslog has network delay and a WinRM pull runs on an
        // interval, so the last few seconds are always incomplete.
        $windowEnd   = $now->modify('-' . (int) $row['lag_seconds'] . ' seconds');
        $windowStart = $windowEnd->modify('-' . (int) $row['window_minutes'] . ' minutes');

        $context = new RuleContext($this->db, $windowStart, $windowEnd, $this->logger);

        $started    = microtime(true);
        $candidates = $rule->evaluate($context, $params);
        $durationMs = (int) round((microtime(true) - $started) * 1000);

        $this->logger->debug('Rule evaluated', [
            'rule'       => $row['name'],
            'window'     => $windowStart->format('H:i:s') . '–' . $windowEnd->format('H:i:s'),
            'candidates' => count($candidates),
            'ms'         => $durationMs,
        ]);

        foreach ($candidates as $candidate) {
            if ($dryRun) {
                $this->logger->info('[dry-run] would alert', [
                    'rule'    => $row['name'],
                    'title'   => $candidate->title,
                    'summary' => $candidate->summary,
                    'dedup'   => $candidate->dedupKey,
                ]);
                $stats['created']++;
                continue;
            }

            $result = $this->alerts->record(
                (int) $row['id'],
                (int) $row['severity'],
                (int) $row['cooldown_s'],
                $candidate,
                $windowStart,
                $windowEnd,
            );

            $stats[$result['action']]++;

            if ($result['notify']) {
                $stats['notify'][] = $result['alert_id'];
            }

            if ($result['action'] === AlertRepository::CREATED) {
                $this->logger->info('Alert raised', [
                    'rule'     => $row['name'],
                    'alert_id' => $result['alert_id'],
                    'title'    => $candidate->title,
                ]);
            }
        }

        if (!$dryRun) {
            $this->db->execute(
                'UPDATE rules
                    SET last_run_at      = now(),
                        last_cursor_ts   = ?::timestamptz,
                        last_error       = NULL,
                        last_duration_ms = ?
                  WHERE id = ?',
                [$windowEnd->format('Y-m-d H:i:s.uP'), $durationMs, (int) $row['id']],
            );
        }
    }

    /**
     * Row params take precedence, the rule's defaults fill the gaps. That way
     * a parameter added in a later version applies to rows created before it
     * existed.
     *
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     */
    private function resolveParams(RuleInterface $rule, array $row): array
    {
        $stored = json_decode((string) ($row['params'] ?? '{}'), true);

        return (is_array($stored) ? $stored : []) + $rule::defaultParams();
    }

    /** @return list<array<string, mixed>> */
    private function enabledRules(?string $onlyKey): array
    {
        $sql    = 'SELECT id, name, rule_key, severity, params, window_minutes, cooldown_s, lag_seconds
                     FROM rules
                    WHERE enabled';
        $params = [];

        if ($onlyKey !== null) {
            $sql     .= ' AND rule_key = ?';
            $params[] = $onlyKey;
        }

        $rows = $this->db->fetchAll($sql . ' ORDER BY id', $params);

        // A row naming a rule that no longer exists on disk is a configuration
        // error, not a reason to abort the whole run.
        return array_values(array_filter($rows, function (array $row): bool {
            if ($this->registry->has((string) $row['rule_key'])) {
                return true;
            }

            $this->logger->warning('Rule row references an unknown key, skipping', [
                'rule' => $row['name'],
                'key'  => $row['rule_key'],
            ]);

            return false;
        }));
    }
}
