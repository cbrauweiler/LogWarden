<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Builds the PowerShell that runs on the Windows host and returns NDJSON.
 *
 * Why a command and not a WS-Management event-log enumeration: the same code
 * path has to serve the DNS analytic aggregation described in docs/dns.md,
 * where the whole point is that the reduction happens on the domain
 * controller and only the result crosses the network. An enumeration can
 * filter but not aggregate.
 *
 * The cost of that decision is that the collector account needs remote shell
 * access, which is more than read access to a channel. docs/winrm.md describes
 * the JEA endpoint that narrows it back down.
 */
final class EventLogQuery
{
    /**
     * A time window, not a record count.
     *
     * The obvious design — "give me the next N events after my bookmark" — is
     * wrong on Windows, and quietly so. Get-WinEvent returns newest first, so
     * -MaxEvents selects the N *newest* matches. A collector that is 10,000
     * events behind with a cap of 5,000 would receive the newest 5,000, move
     * its bookmark to the end of those, and never come back for the 5,000 in
     * between. The gap would never show up as an error.
     *
     * Bounding by time instead makes the result complete by construction: the
     * window either came back whole, or it hit the cap and is retried smaller.
     */
    public const DEFAULT_WINDOW_SECONDS = 900;

    /**
     * Events can be written to the channel a moment after the timestamp they
     * carry. Ending the window slightly in the past keeps the collector from
     * declaring a window complete that is still being filled.
     */
    public const DEFAULT_LAG_SECONDS = 20;

    /** @param list<int> $eventIds */
    public function __construct(
        private readonly string $channel,
        private readonly array $eventIds = [],
        private readonly bool $includeMessage = false,
        private readonly int $maxEvents = 5000,
    ) {
    }

    public function script(DateTimeImmutable $from, DateTimeImmutable $to): string
    {
        $utc  = new DateTimeZone('UTC');
        $ids  = $this->eventIds === [] ? '' : implode(',', array_map('intval', $this->eventIds));

        // Round-trip format with an explicit UTC marker. Handing PowerShell a
        // local-time string would resolve it against the *host's* time zone,
        // which is the one thing about a remote machine that must never be
        // assumed.
        $fromStr = $from->setTimezone($utc)->format('Y-m-d\TH:i:s.u\Z');
        $toStr   = $to->setTimezone($utc)->format('Y-m-d\TH:i:s.u\Z');

        $filter = "@{ LogName = " . self::psString($this->channel)
            . "; StartTime = \$from; EndTime = \$to }";

        $idLine = $ids === '' ? '' : "\$filter['Id'] = @($ids)\n";

        $messageLine = $this->includeMessage
            ? "    \$o['m'] = \$e.Message\n"
            : '';

        return <<<PS
            \$ErrorActionPreference = 'Stop'
            \$ProgressPreference = 'SilentlyContinue'
            # The shell is already told to use code page 65001, but a
            # PowerShell host without a real console throws on this assignment
            # rather than ignoring it — so it is help when it works, never a
            # failure when it does not.
            try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

            \$from = [datetime]::Parse({$this->quoted($fromStr)}, \$null, 'RoundtripKind')
            \$to   = [datetime]::Parse({$this->quoted($toStr)}, \$null, 'RoundtripKind')

            \$filter = {$filter}
            {$idLine}
            # Get-WinEvent reports "nothing matched" as an error rather than as
            # an empty result, so every quiet poll would look like a failed
            # collection. Telling them apart by message text would break on a
            # German host; FullyQualifiedErrorId is culture-independent.
            \$events = @(Get-WinEvent -FilterHashtable \$filter -MaxEvents {$this->maxEvents} -ErrorAction SilentlyContinue -ErrorVariable ev)

            if (\$ev -and \$events.Count -eq 0) {
                \$fq = [string]\$ev[0].FullyQualifiedErrorId
                if (\$fq -notlike 'NoMatchingEventsFound*') {
                    Write-Error -Message \$ev[0].Exception.Message -ErrorAction Continue
                    exit 2
                }
            }

            # Oldest first, so a run that is cut short still leaves the bookmark
            # on a complete prefix of the window.
            foreach (\$e in (\$events | Sort-Object -Property RecordId)) {
                \$x = [xml]\$e.ToXml()
                \$d = [ordered]@{}
                foreach (\$n in \$x.Event.EventData.Data) {
                    # Get-WinEvent's own .Properties collection drops the field
                    # names, which is exactly the half that carries the meaning
                    # (TargetUserName, LogonType, IpAddress). The XML keeps them.
                    if (\$n.Name) { \$d[\$n.Name] = [string]\$n.'#text' }
                }
                # Not every channel uses EventData. Event 1102 (security log
                # cleared) and the DNS server channels put their fields under
                # UserData, one level deeper, and reading only EventData would
                # deliver those events stripped of everything that matters.
                if (\$x.Event.UserData) {
                    foreach (\$u in \$x.Event.UserData.ChildNodes) {
                        foreach (\$f in \$u.ChildNodes) {
                            if (\$f.Name -and -not \$d.Contains(\$f.Name)) {
                                \$d[\$f.Name] = [string]\$f.'#text'
                            }
                        }
                    }
                }
                \$o = [ordered]@{}
                \$o['r'] = \$e.RecordId
                \$o['t'] = \$e.TimeCreated.ToUniversalTime().ToString('o')
                \$o['i'] = \$e.Id
                \$o['p'] = \$e.ProviderName
                \$o['c'] = \$e.MachineName
                \$o['l'] = \$e.LevelDisplayName
                \$o['d'] = \$d
            {$messageLine}    \$o | ConvertTo-Json -Compress -Depth 4
            }

            Write-Output "##LW-COUNT:\$(\$events.Count)"
            PS;
    }

    /**
     * A script that reports which event ids a channel actually contains.
     *
     * docs/dns.md promised this rather than a guessed list: the DNS audit
     * range differs between server versions, and a catalogue written from
     * documentation is a hypothesis until a real channel confirms it. The
     * output is a count per id with one example line, which is enough to
     * decide what to collect.
     */
    public static function discoveryScript(string $channel, int $sample = 5000): string
    {
        $literal = self::psString($channel);

        return <<<PS
            \$ErrorActionPreference = 'Stop'
            \$ProgressPreference = 'SilentlyContinue'
            try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

            \$events = @(Get-WinEvent -LogName {$literal} -MaxEvents {$sample} -ErrorAction SilentlyContinue -ErrorVariable ev)

            if (\$ev -and \$events.Count -eq 0) {
                \$fq = [string]\$ev[0].FullyQualifiedErrorId
                if (\$fq -notlike 'NoMatchingEventsFound*') {
                    Write-Error -Message \$ev[0].Exception.Message -ErrorAction Continue
                    exit 2
                }
            }

            foreach (\$g in (\$events | Group-Object Id | Sort-Object Count -Descending)) {
                \$first = \$g.Group[0]
                \$o = [ordered]@{}
                \$o['i'] = [int]\$g.Name
                \$o['n'] = \$g.Count
                \$o['l'] = \$first.LevelDisplayName
                # Erste Zeile der Meldung: genug, um die ID zu erkennen, ohne
                # den gesamten Erklärtext über das Netz zu schicken.
                \$msg = \$first.Message
                if (\$msg) { \$o['m'] = (\$msg -split "`r?`n")[0] } else { \$o['m'] = '' }
                \$x = [xml]\$first.ToXml()
                \$f = @()
                foreach (\$n in \$x.Event.EventData.Data) { if (\$n.Name) { \$f += \$n.Name } }
                if (\$x.Event.UserData) {
                    foreach (\$u in \$x.Event.UserData.ChildNodes) {
                        foreach (\$c in \$u.ChildNodes) { if (\$c.Name) { \$f += \$c.Name } }
                    }
                }
                \$o['f'] = \$f
                \$o | ConvertTo-Json -Compress -Depth 3
            }

            Write-Output "##LW-COUNT:\$(\$events.Count)"
            PS;
    }

    /**
     * -EncodedCommand takes base64 of UTF-16LE.
     *
     * It exists to sidestep quoting entirely: the script travels as one opaque
     * token, so nothing in it — quotes, ampersands, pipes, newlines — can be
     * reinterpreted by cmd.exe or by the SOAP layer on the way.
     */
    public static function encode(string $script): string
    {
        $utf16 = mb_convert_encoding($script, 'UTF-16LE', 'UTF-8');

        return base64_encode($utf16);
    }

    /** @return list<string> */
    public static function powershellArguments(string $script): array
    {
        return [
            '-NoProfile',
            '-NonInteractive',
            '-NoLogo',
            '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', self::encode($script),
        ];
    }

    private function quoted(string $value): string
    {
        return self::psString($value);
    }

    /** Single-quoted PowerShell literal: the only escape inside is '' for '. */
    private static function psString(string $value): string
    {
        return "'" . str_replace("'", "''", $value) . "'";
    }
}
