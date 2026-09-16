<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use LogWarden\Core\Logger;
use Throwable;

/**
 * One remote command, from opening the shell to cleaning it up.
 *
 * Shells are a scarce resource on the target: WinRM allows a limited number
 * per user (`MaxShellsPerUser`, 30 by default) and a shell that is not deleted
 * occupies its slot until `IdleTimeout` expires. A collector that leaks one
 * shell per poll therefore stops working after half an hour — with a fault
 * that blames a quota rather than the leak. Hence the finally block.
 */
final class WinrmShell
{
    /**
     * Ceiling on collected stdout. A misconfigured query that selects a busy
     * channel without a filter would otherwise pull this process into swap.
     */
    private const DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024;

    public function __construct(
        private readonly WinrmClient $client,
        private readonly ?Logger $logger = null,
        private readonly int $operationTimeout = 60,
        private readonly int $maxOutputBytes = self::DEFAULT_MAX_OUTPUT,
    ) {
    }

    /**
     * Runs one command and returns its streams.
     *
     * @param list<string> $arguments
     * @return array{stdout: string, stderr: string, exit_code: int, truncated: bool, receives: int}
     */
    public function run(string $command, array $arguments = [], ?int $wallClockLimit = null): array
    {
        $envelope = new WsmanEnvelope($this->client->endpoint(), 512000, $this->operationTimeout);
        $limit    = $wallClockLimit ?? ($this->operationTimeout * 10);
        $deadline = microtime(true) + $limit;

        $shellId = $this->client->send($envelope->createShell())->shellId();
        if ($shellId === null) {
            throw new WinrmException('Der Host hat keine ShellId zurückgegeben');
        }

        $commandId = null;

        try {
            $commandId = $this->client->send($envelope->command($shellId, $command, $arguments))->commandId();
            if ($commandId === null) {
                throw new WinrmException('Der Host hat keine CommandId zurückgegeben');
            }

            return $this->collect($envelope, $shellId, $commandId, $deadline, $limit);
        } finally {
            $this->cleanup($envelope, $shellId, $commandId);
        }
    }

    /**
     * Pulls output until the command reports Done.
     *
     * @return array{stdout: string, stderr: string, exit_code: int, truncated: bool, receives: int}
     */
    private function collect(WsmanEnvelope $envelope, string $shellId, string $commandId, float $deadline, int $limit): array
    {
        $stdout    = '';
        $stderr    = '';
        $truncated = false;
        $receives  = 0;

        while (true) {
            if (microtime(true) > $deadline) {
                throw new WinrmException(sprintf(
                    'Das Remote-Kommando war nach %d s noch nicht fertig. Bei großen Abrufen '
                    . 'max_events senken oder das Abrufintervall verkürzen.',
                    $limit,
                ));
            }

            try {
                $response = $this->client->send($envelope->receive($shellId, $commandId));
                $receives++;
            } catch (WsmanFault $fault) {
                // Not an error: the command has simply produced nothing within
                // OperationTimeout. Windows expects the client to ask again,
                // and a long Get-WinEvent on a large channel routinely spends
                // its first minute searching before emitting a single line.
                if ($fault->isTimeout()) {
                    continue;
                }

                throw $fault;
            }

            $stdout .= $response->stream('stdout');
            $stderr .= $response->stream('stderr');

            if (strlen($stdout) > $this->maxOutputBytes) {
                // Cut on the last complete line: the consumer reads NDJSON and
                // half a JSON object is worse than one missing record.
                $cut       = strrpos(substr($stdout, 0, $this->maxOutputBytes), "\n");
                $stdout    = substr($stdout, 0, $cut === false ? $this->maxOutputBytes : $cut);
                $truncated = true;

                $this->logger?->warning('Ausgabe des Remote-Kommandos abgeschnitten', [
                    'limit_bytes' => $this->maxOutputBytes,
                    'hint'        => 'max_events der Quelle senken',
                ]);

                break;
            }

            if ($response->isDone()) {
                return [
                    'stdout'    => $stdout,
                    'stderr'    => $stderr,
                    'exit_code' => $response->exitCode() ?? 0,
                    'truncated' => false,
                    'receives'  => $receives,
                ];
            }
        }

        return [
            'stdout'    => $stdout,
            'stderr'    => $stderr,
            'exit_code' => 0,
            'truncated' => $truncated,
            'receives'  => $receives,
        ];
    }

    private function cleanup(WsmanEnvelope $envelope, string $shellId, ?string $commandId): void
    {
        // Best effort by design: the collection has either succeeded or failed
        // already, and a host that refuses the cleanup must not turn a good run
        // into a failed one. The shell expires on its own via IdleTimeout.
        try {
            if ($commandId !== null) {
                $this->client->send($envelope->signal($shellId, $commandId));
            }
        } catch (Throwable $e) {
            $this->logger?->debug('Signal an die Remote-Shell fehlgeschlagen', ['error' => $e->getMessage()]);
        }

        try {
            $this->client->send($envelope->deleteShell($shellId));
        } catch (Throwable $e) {
            $this->logger?->warning('Remote-Shell konnte nicht geschlossen werden', [
                'shell' => $shellId,
                'error' => $e->getMessage(),
                'hint'  => 'Sie läuft nach IdleTimeout selbst ab, belegt bis dahin aber einen Shell-Slot',
            ]);
        }
    }
}
