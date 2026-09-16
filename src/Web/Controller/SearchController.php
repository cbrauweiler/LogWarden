<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Core\Db;
use LogWarden\Search\EventQuery;
use LogWarden\Search\EventStats;
use LogWarden\Search\SearchCriteria;
use LogWarden\Web\Response;
use LogWarden\Web\View;

final class SearchController
{
    public function __construct(
        private readonly EventQuery $events,
        private readonly Db $db,
        private readonly View $view,
    ) {
    }

    public function search(): Response
    {
        $criteria = SearchCriteria::fromArray($_GET);
        $page     = $this->events->search($criteria);
        $rows     = $page['rows'];
        $total    = $this->events->countCapped($criteria);

        $last = $rows === [] ? null : $rows[count($rows) - 1];

        return Response::html($this->view->page('search', [
            'title'      => 'Suche',
            'active'     => 'search',
            'criteria'   => $criteria,
            'rows'       => $rows,
            'hasMore'    => $page['hasMore'],
            'total'      => $total,
            'facets'     => $this->events->facets($criteria, $total['capped']),
            'labels'     => EventStats::sourceLabels(),
            'nextCursor' => $last === null ? null : ['cts' => $last['ts_iso'], 'cid' => $last['id']],
            'ftsWarning' => $this->fullTextWarning($criteria),
            'ipWarning'  => $criteria->ip !== null && !$criteria->ipValid
                ? sprintf(
                    '»%s« ist keine gültige IP-Adresse oder Netzangabe — der IP-Filter wurde ignoriert. '
                    . 'Beispiele: 203.0.113.9 oder 10.0.0.0/8.',
                    $criteria->ip,
                )
                : null,
        ]));
    }

    public function event(): Response
    {
        $ts = (string) ($_GET['ts'] ?? '');
        $id = (int) ($_GET['id'] ?? 0);

        // Validate before the query: an unparseable timestamp would otherwise
        // reach PostgreSQL's timestamptz cast and come back as a 500, when the
        // honest answer is that the reference is wrong.
        if ($ts === '' || $id <= 0 || !self::isTimestamp($ts)) {
            return Response::html($this->view->page('event_missing', [
                'title'  => 'Event nicht gefunden',
                'active' => 'search',
                'ts'     => $ts === '' ? '—' : $ts,
                'id'     => $id,
            ]), 404);
        }

        $event = $this->events->find($ts, $id);

        if ($event === null) {
            return Response::html($this->view->page('event_missing', [
                'title'  => 'Event nicht gefunden',
                'active' => 'search',
                'ts'     => $ts,
                'id'     => $id,
            ]), 404);
        }

        return Response::html($this->view->page('event', [
            'title'      => 'Event ' . $event['ts_label'],
            'active'     => 'search',
            'event'      => $event,
            'details'    => json_decode((string) $event['details'], true) ?: [],
            'neighbours' => $this->events->neighbours($event),
            'labels'     => EventStats::sourceLabels(),
        ]));
    }

    public function export(): Response
    {
        $criteria = SearchCriteria::fromArray($_GET);
        $rows     = $this->events->export($criteria);

        $filename = 'logwarden-' . gmdate('Ymd-His') . '.csv';

        return Response::streamed(
            function () use ($rows): void {
                $out = fopen('php://output', 'wb');

                // Excel opens UTF-8 CSV as Latin-1 unless a BOM says otherwise,
                // and these exports usually end up in a spreadsheet.
                fwrite($out, "\xEF\xBB\xBF");

                fputcsv($out, [
                    'timestamp_utc', 'timestamp_iso', 'source_type', 'source_host',
                    'event_type', 'username', 'src_ip', 'dst_ip', 'result', 'raw_message',
                ], ';');

                foreach ($rows as $row) {
                    fputcsv($out, [
                        $row['ts_utc'],
                        $row['ts_iso'],
                        $row['source_type'],
                        $row['source_host'],
                        $row['event_type'],
                        $row['username'] ?? '',
                        $row['src_ip'] ?? '',
                        $row['dst_ip'] ?? '',
                        $row['result'] ?? '',
                        // A raw syslog line can contain newlines; fputcsv quotes
                        // them correctly, but keeping one event on one line is
                        // what makes the file usable in a spreadsheet.
                        str_replace(["\r", "\n"], ' ', (string) $row['raw_message']),
                    ], ';');

                    // Keep memory flat on a long export.
                    if (function_exists('ob_get_level') && ob_get_level() > 0) {
                        ob_flush();
                    }
                    flush();
                }

                fclose($out);
            },
            [
                'Content-Type'        => 'text/csv; charset=utf-8',
                'Content-Disposition' => 'attachment; filename="' . $filename . '"',
                'Cache-Control'       => 'no-store',
            ],
        );
    }

    private static function isTimestamp(string $value): bool
    {
        if (mb_strlen($value) > 40) {
            return false;
        }

        try {
            new \DateTimeImmutable($value);

            return true;
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * The full-text index only covers recent partitions, so a free-text search
     * over a longer window falls back to a sequential scan. Saying so is more
     * useful than letting it silently take thirty seconds.
     */
    private function fullTextWarning(SearchCriteria $criteria): ?string
    {
        if ($criteria->query === null) {
            return null;
        }

        $ftsDays = (int) $this->db->fetchValue(
            'SELECT max(fts_days) FROM retention_policies',
            [],
            14,
        );

        if ($criteria->rangeDays() <= $ftsDays) {
            return null;
        }

        return sprintf(
            'Die Volltextsuche ist nur für die letzten %d Tage indiziert. '
            . 'Ihr Zeitraum reicht weiter zurück — die Suche liest die älteren Tage vollständig '
            . 'und kann entsprechend lange dauern.',
            $ftsDays,
        );
    }
}
