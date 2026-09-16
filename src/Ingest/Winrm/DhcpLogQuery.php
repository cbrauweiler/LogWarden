<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Builds the PowerShell that reads the DHCP audit log off the server.
 *
 * Three things about that file make it awkward, and all three are handled on
 * the Windows side because that is where the answers are:
 *
 * 1. **The file names are localised.** The server writes one file per weekday,
 *    named with the *short day name of its own locale* — `DhcpSrvLog-Mon.log`
 *    on English, `DhcpSrvLog-Mo.log` on German. Computing the name from here
 *    would work in a lab and fail in half of Europe, so the directory is
 *    enumerated instead and files are chosen by their modification time.
 *
 * 2. **The dates are localised too**, and ambiguous: `05/06/26` is the fifth of
 *    June or the sixth of May depending on the install. The server knows its
 *    own culture, so it resolves each row to an ISO timestamp before sending.
 *
 * 3. **The file is ANSI**, not UTF-8. A host name with an umlaut arrives as a
 *    different byte than the one PostgreSQL is about to be told is UTF-8.
 */
final class DhcpLogQuery
{
    public const DEFAULT_PATH = 'C:\\Windows\\System32\\dhcp';

    /** @param list<string> $eventIds */
    public function __construct(
        private readonly string $path = self::DEFAULT_PATH,
        private readonly array $eventIds = [],
        private readonly int $maxLines = 200000,
        private readonly bool $ipv6 = false,
    ) {
    }

    public function script(DateTimeImmutable $from, DateTimeImmutable $to): string
    {
        $utc     = new DateTimeZone('UTC');
        $fromStr = $from->setTimezone($utc)->format('Y-m-d\TH:i:s.u\Z');
        $toStr   = $to->setTimezone($utc)->format('Y-m-d\TH:i:s.u\Z');

        $pattern = $this->ipv6 ? 'DhcpV6SrvLog-*.log' : 'DhcpSrvLog-*.log';

        // Always defined, so the filter line below reads the same either way.
        $idFilter = '$wanted = @(' . implode(',', array_map(
            static fn (string $id): string => "'" . str_pad(trim($id), 2, '0', STR_PAD_LEFT) . "'",
            $this->eventIds,
        )) . ')';

        return <<<PS
            \$ErrorActionPreference = 'Stop'
            \$ProgressPreference = 'SilentlyContinue'
            try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

            \$from = [datetime]::Parse({$this->psString($fromStr)}, \$null, 'RoundtripKind')
            \$to   = [datetime]::Parse({$this->psString($toStr)}, \$null, 'RoundtripKind')
            \$dir  = {$this->psString($this->path)}
            {$idFilter}
            if (-not (Test-Path -LiteralPath \$dir)) {
                Write-Error -Message "Verzeichnis nicht gefunden: \$dir" -ErrorAction Continue
                exit 2
            }

            # Die Datei ist ANSI. Ohne die richtige Codepage wird aus jedem
            # Umlaut im Hostnamen ein anderes Byte, als PostgreSQL gleich als
            # UTF-8 zugesichert bekommt.
            try {
                \$cp  = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
                \$enc = [System.Text.Encoding]::GetEncoding(\$cp)
            } catch {
                \$enc = [System.Text.Encoding]::UTF8
            }

            # Dateinamen nicht berechnen, sondern finden: der Wochentag im Namen
            # ist lokalisiert. Ein Tag Reserve, weil die Datei nach dem letzten
            # Schreibvorgang noch Zeilen aus dem Fenster enthalten kann.
            \$files = @(Get-ChildItem -LiteralPath \$dir -Filter '{$pattern}' -File -ErrorAction SilentlyContinue |
                Where-Object { \$_.LastWriteTimeUtc -ge \$from.AddDays(-1) } |
                Sort-Object LastWriteTimeUtc)

            \$host_name = [System.Net.Dns]::GetHostEntry(\$env:COMPUTERNAME).HostName
            \$emitted   = 0
            \$scanned   = 0
            \$headerSent = \$false

            foreach (\$f in \$files) {
                \$lines = \$enc.GetString([System.IO.File]::ReadAllBytes(\$f.FullName)) -split "`r?`n"

                foreach (\$line in \$lines) {
                    \$scanned++

                    if (\$emitted -ge {$this->maxLines}) { break }

                    # Kopfzeile einmal mitschicken: die Spaltenzahl hat sich
                    # zwischen Windows-Versionen geändert, positionsbasiertes
                    # Parsen würde auf der jeweils anderen alles verschieben.
                    if (-not \$headerSent -and \$line -match '^ID,\\s*Date,\\s*Time,') {
                        \$h = [ordered]@{}
                        \$h['h'] = \$line.Trim()
                        \$h | ConvertTo-Json -Compress
                        \$headerSent = \$true
                        continue
                    }

                    if (\$line -notmatch '^\\s*\\d{1,2},') { continue }

                    \$parts = \$line -split ','
                    if (\$parts.Count -lt 3) { continue }

                    \$id = \$parts[0].Trim().PadLeft(2, '0')
                    if (\$wanted -and (\$wanted -notcontains \$id)) { continue }

                    # Die Kultur des Servers entscheidet, nicht unsere Vermutung.
                    try {
                        \$local = [datetime]::Parse((\$parts[1].Trim() + ' ' + \$parts[2].Trim()),
                                                    [System.Globalization.CultureInfo]::CurrentCulture)
                    } catch {
                        continue
                    }

                    \$utc = \$local.ToUniversalTime()
                    if (\$utc -lt \$from -or \$utc -ge \$to) { continue }

                    \$o = [ordered]@{}
                    \$o['l'] = \$line.TrimEnd()
                    \$o['t'] = \$utc.ToString('o')
                    \$o['c'] = \$host_name
                    \$o | ConvertTo-Json -Compress
                    \$emitted++
                }

                if (\$emitted -ge {$this->maxLines}) { break }
            }

            Write-Output "##LW-COUNT:\$emitted"
            PS;
    }

    /**
     * Prints the documentation block at the top of the newest log file.
     *
     * The DHCP server writes its own event-id list into every file it
     * produces, so a Windows version that added an id documents it there. That
     * makes this the DHCP equivalent of `--discover`: it asks the server
     * instead of trusting the catalogue.
     */
    public function headerScript(): string
    {
        $pattern = $this->ipv6 ? 'DhcpV6SrvLog-*.log' : 'DhcpSrvLog-*.log';

        return <<<PS
            \$ErrorActionPreference = 'Stop'
            try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

            \$dir = {$this->psString($this->path)}
            \$f = Get-ChildItem -LiteralPath \$dir -Filter '{$pattern}' -File -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1

            if (-not \$f) {
                Write-Error -Message "Keine Logdatei in \$dir" -ErrorAction Continue
                exit 2
            }

            try {
                \$cp  = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
                \$enc = [System.Text.Encoding]::GetEncoding(\$cp)
            } catch {
                \$enc = [System.Text.Encoding]::UTF8
            }

            Write-Output ("# " + \$f.FullName)

            foreach (\$line in (\$enc.GetString([System.IO.File]::ReadAllBytes(\$f.FullName)) -split "`r?`n")) {
                Write-Output \$line
                if (\$line -match '^ID,\\s*Date,\\s*Time,') { break }
            }
            PS;
    }

    private function psString(string $value): string
    {
        return "'" . str_replace("'", "''", $value) . "'";
    }
}
