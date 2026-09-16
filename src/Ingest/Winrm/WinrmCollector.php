<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Core\Logger;
use LogWarden\Event\EventWriter;
use LogWarden\Ingest\IngestSource;
use LogWarden\Ingest\Windows\WindowsNormalizerFactory;

/**
 * Collects one source: one Windows host, one channel, one bounded time window
 * per run.
 *
 * ### The window, and why it is not a record count
 *
 * Get-WinEvent returns newest first, so asking for "the next 5000 events"
 * silently skips everything between the bookmark and the newest 5000 whenever
 * the collector has fallen behind. Bounding by time makes completeness
 * checkable instead: either the window came back below the cap — in which case
 * it is provably whole — or it hit the cap and is retried half as wide. A run
 * that cannot get under the cap even at the minimum width says so rather than
 * quietly losing the remainder.
 */
final class WinrmCollector
{
    private const DEFAULT_INITIAL_LOOKBACK = 3600;
    private const MIN_WINDOW_SECONDS       = 60;
    private const MAX_SHRINKS              = 4;
    private const COUNT_MARKER             = '##LW-COUNT:';

    /**
     * How many windows one run may collect before handing control back.
     *
     * Without this a source that has fallen behind advances by exactly one
     * window per run: after a weekend of downtime, a 15-minute window and a
     * five-minute timer would need two full days to catch up — while quietly
     * reporting success on every run. The budget below lets a run work through
     * the backlog and still finish inside its timer interval.
     */
    private const DEFAULT_MAX_WINDOWS = 12;
    private const DEFAULT_RUN_BUDGET  = 240;

    public function __construct(
        private readonly EventWriter $writer,
        private readonly Logger $logger,
    ) {
    }

    /**
     * Collects everything between the bookmark and now, in windows, within the
     * run's budget.
     *
     * @param callable(IngestSource): WinrmClient $clientFactory
     * @return array{status: string, fetched: int, stored: int, skipped: int, windows: int, caught_up: bool, bookmark: array<string, mixed>, note: ?string}
     */
    public function collect(IngestSource $source, callable $clientFactory, ?DateTimeImmutable $now = null): array
    {
        $utc = new DateTimeZone('UTC');
        $now ??= new DateTimeImmutable('now', $utc);

        $lag = (int) $source->setting('lag_seconds', EventLogQuery::DEFAULT_LAG_SECONDS);

        // Truncated to whole seconds. The bookmark is stored as RFC 3339
        // without sub-second precision, so a ceiling carrying microseconds is
        // always a fraction ahead of the bookmark that just reached it — and
        // every successful run would end by warning about a backlog of zero
        // seconds. One spurious warning per run is how an operator learns to
        // stop reading them.
        $ceiling = (new DateTimeImmutable('@' . ($now->getTimestamp() - max(0, $lag))))->setTimezone($utc);
        $from    = $this->startOf($source, $now);

        $maxWindows = max(1, (int) $source->setting('max_windows_per_run', self::DEFAULT_MAX_WINDOWS));
        $budget     = microtime(true) + max(30, (int) $source->setting('max_run_seconds', self::DEFAULT_RUN_BUDGET));

        $totals   = ['fetched' => 0, 'stored' => 0, 'skipped' => 0];
        $bookmark = $source->bookmark;
        $notes    = [];
        $status   = 'empty';
        $windows  = 0;
        $client   = null;

        while ($from < $ceiling && $windows < $maxWindows && microtime(true) < $budget) {
            $client ??= $clientFactory($source);

            $result = $this->collectWindow($source, $client, $from, $ceiling, $bookmark);
            $windows++;

            $totals['fetched'] += $result['fetched'];
            $totals['stored']  += $result['stored'];
            $totals['skipped'] += $result['skipped'];
            $bookmark = $result['bookmark'];

            // Deduplicated: an overfull channel produces the identical note on
            // every window of the run, and repeating it a dozen times buries
            // the one sentence that matters.
            if ($result['note'] !== null && !in_array($result['note'], $notes, true)) {
                $notes[] = $result['note'];
            }

            $status = match (true) {
                $result['status'] === 'partial' => 'partial',
                $status === 'partial'           => 'partial',
                $result['status'] === 'ok'      => 'ok',
                default                         => $status,
            };

            $next = $source->bookmarkTimeFrom($bookmark);
            if ($next === null || $next <= $from) {
                break;
            }

            $from = $next;
        }

        $caughtUp = $from >= $ceiling;

        if (!$caughtUp && $windows > 0) {
            $behind  = $ceiling->getTimestamp() - $from->getTimestamp();
            $notes[] = sprintf(
                'Nach %d Fenstern noch %s Rückstand — der nächste Lauf holt weiter auf.',
                $windows,
                $this->humanise($behind),
            );
        }

        return [
            'status'    => $status,
            'fetched'   => $totals['fetched'],
            'stored'    => $totals['stored'],
            'skipped'   => $totals['skipped'],
            'windows'   => $windows,
            'caught_up' => $caughtUp,
            'bookmark'  => $bookmark,
            'note'      => $notes === [] ? null : implode(' ', $notes),
        ];
    }

    /**
     * One window: query, shrink on overflow, store.
     *
     * @param array<string, mixed> $bookmark
     * @return array{status: string, fetched: int, stored: int, skipped: int, bookmark: array<string, mixed>, note: ?string}
     */
    private function collectWindow(
        IngestSource $source,
        WinrmClient $client,
        DateTimeImmutable $from,
        DateTimeImmutable $ceiling,
        array $bookmark,
    ): array {
        $window    = max(self::MIN_WINDOW_SECONDS, (int) $source->setting('window_seconds', EventLogQuery::DEFAULT_WINDOW_SECONDS));
        $maxEvents = max(100, (int) $source->setting('max_events', 5000));
        $shell     = new WinrmShell(
            $client,
            $this->logger,
            (int) $source->setting('operation_timeout', 60),
            (int) $source->setting('max_output_bytes', 64 * 1024 * 1024),
        );

        $note      = null;
        $partial   = false;

        for ($shrink = 0; ; $shrink++) {
            $to = $this->min($from->add(new DateInterval('PT' . $window . 'S')), $ceiling);

            $query  = new EventLogQuery(
                $source->channel(),
                $source->eventIds(),
                (bool) $source->setting('include_message', false),
                $maxEvents,
            );
            $script = $query->script($from, $to);
            $result = $shell->run('powershell.exe', EventLogQuery::powershellArguments($script));

            if ($result['exit_code'] !== 0) {
                throw new WinrmException($this->describeScriptFailure($result, $source));
            }

            [$lines, $reported] = $this->split($result['stdout']);
            $capHit = $reported !== null ? $reported >= $maxEvents : count($lines) >= $maxEvents;

            if ($result['truncated']) {
                // The byte ceiling cut the output mid-stream, so this window is
                // incomplete no matter what the count says. Reported as partial
                // rather than shrunk and retried: the same window would produce
                // the same volume again.
                return $this->store($source, $lines, $to, sprintf(
                    'Die Ausgabe überschritt max_output_bytes und wurde abgeschnitten. '
                    . 'Ein Teil des Fensters (%s bis %s) fehlt. Abhilfe: window_seconds verkleinern.',
                    $from->format('H:i:s'),
                    $to->format('H:i:s'),
                ), true, $bookmark);
            }

            if (!$capHit) {
                return $this->store($source, $lines, $to, $note, $partial, $bookmark);
            }

            $span = $to->getTimestamp() - $from->getTimestamp();

            if ($shrink >= self::MAX_SHRINKS || $span <= self::MIN_WINDOW_SECONDS) {
                // The minimum window genuinely holds more events than the cap.
                // Advancing anyway is the lesser evil: stalling here would put
                // the source further behind on every run while reporting the
                // same error, and the fix (a tighter event filter or a larger
                // cap) needs a human either way.
                $partial = true;
                $note    = sprintf(
                    'Das Zeitfenster von %d s enthielt mehr als %d Events. Der Rest dieses Fensters '
                    . 'fehlt. Abhilfe: max_events erhöhen oder die Event-ID-Auswahl enger fassen.',
                    $span,
                    $maxEvents,
                );

                $this->logger->warning('Collector-Fenster übervoll', [
                    'source'     => $source->name,
                    'window_s'   => $span,
                    'max_events' => $maxEvents,
                ]);

                return $this->store($source, $lines, $to, $note, $partial, $bookmark);
            }

            $window = max(self::MIN_WINDOW_SECONDS, intdiv($span, 2));

            $this->logger->debug('Fenster verkleinert', [
                'source'   => $source->name,
                'window_s' => $window,
            ]);
        }
    }

    /**
     * @param list<string> $lines
     * @return array{status: string, fetched: int, stored: int, skipped: int, bookmark: array<string, mixed>, note: ?string}
     */
    private function store(
        IngestSource $source,
        array $lines,
        DateTimeImmutable $to,
        ?string $note,
        bool $partial,
        array $bookmark,
    ): array {
        $normalizer = WindowsNormalizerFactory::for($source);

        $before       = $this->writer->stats()['written'];
        $skipped      = 0;
        $lastRecordId = (int) ($bookmark['last_record_id'] ?? 0);

        foreach ($lines as $line) {
            $events = $normalizer->normalize($line);

            if ($events === []) {
                $skipped++;
                continue;
            }

            foreach ($events as $event) {
                $this->writer->add($event);
                $recordId = (int) ($event->details['record_id'] ?? 0);
                if ($recordId > $lastRecordId) {
                    $lastRecordId = $recordId;
                }
            }
        }

        $this->writer->flush();
        $stored = $this->writer->stats()['written'] - $before;

        return [
            'status'   => $partial ? 'partial' : (count($lines) === 0 ? 'empty' : 'ok'),
            'fetched'  => count($lines),
            'stored'   => $stored,
            'skipped'  => $skipped,
            'bookmark' => [
                'until'          => $to->format(DATE_ATOM),
                'last_record_id' => $lastRecordId,
            ],
            'note'     => $note,
        ];
    }

    /**
     * Splits stdout into NDJSON lines and the count marker the script appends.
     *
     * The marker exists because "how many lines did I get" and "how many
     * events matched" differ as soon as one record fails to serialise, and the
     * cap check has to be made against the second number.
     *
     * @return array{0: list<string>, 1: ?int}
     */
    private function split(string $stdout): array
    {
        $lines    = [];
        $reported = null;

        foreach (preg_split('/\R/', $stdout) ?: [] as $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, self::COUNT_MARKER)) {
                $reported = (int) substr($line, strlen(self::COUNT_MARKER));
                continue;
            }

            $lines[] = $line;
        }

        return [$lines, $reported];
    }

    /**
     * Where a source with no bookmark starts.
     *
     * Deliberately short by default: a new source should not spend its first
     * run pulling a month of history out of a domain controller. Raising
     * `initial_lookback` is a conscious act with a visible cost.
     */
    private function startOf(IngestSource $source, DateTimeImmutable $now): DateTimeImmutable
    {
        $bookmark = $source->bookmarkTime();
        if ($bookmark !== null) {
            return $bookmark;
        }

        $seconds = max(60, (int) $source->setting('initial_lookback', self::DEFAULT_INITIAL_LOOKBACK));

        return $now->sub(new DateInterval('PT' . $seconds . 'S'));
    }

    /** @param array{stdout: string, stderr: string, exit_code: int, truncated: bool, receives: int} $result */
    private function describeScriptFailure(array $result, IngestSource $source): string
    {
        $stderr = trim($result['stderr']);

        if ($stderr === '') {
            return sprintf(
                'Die Abfrage auf %s endete mit Exit-Code %d ohne Fehlermeldung.',
                $source->targetHost ?? $source->name,
                $result['exit_code'],
            );
        }

        // The two failures that actually happen in the field, both with a fix
        // that is not obvious from the Windows wording.
        if (str_contains($stderr, 'No events were found') || str_contains($stderr, 'Es wurden keine')) {
            return 'Der Kanal ' . $source->channel() . ' existiert auf dem Host nicht oder ist leer.';
        }

        if (str_contains($stderr, 'Attempted to perform an unauthorized operation')
            || str_contains($stderr, 'Zugriff verweigert')
            || str_contains($stderr, 'Access is denied')) {
            return 'Das Konto darf den Kanal ' . $source->channel() . ' nicht lesen. '
                . 'Für "Security" genügt Mitgliedschaft in "Event Log Readers" nicht immer — '
                . 'siehe docs/winrm.md.';
        }

        return mb_substr($stderr, 0, 1000);
    }

    private function min(DateTimeImmutable $a, DateTimeImmutable $b): DateTimeImmutable
    {
        return $a < $b ? $a : $b;
    }

    private function humanise(int $seconds): string
    {
        return match (true) {
            $seconds < 120   => $seconds . ' s',
            $seconds < 7200  => intdiv($seconds, 60) . ' min',
            $seconds < 172800 => intdiv($seconds, 3600) . ' h',
            default          => intdiv($seconds, 86400) . ' Tage',
        };
    }
}
