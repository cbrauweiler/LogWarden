<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use RuntimeException;

/**
 * A SOAP fault from the WinRM service.
 *
 * Windows answers most problems with HTTP 500 and a fault body, so the HTTP
 * status alone says almost nothing. The useful part is the MS-specific
 * `wsmanfault:WSManFault/@Code` and the WS-Management subcode; both are kept
 * here so callers can tell a timeout from a refusal without matching strings.
 */
final class WsmanFault extends RuntimeException
{
    /**
     * ERROR_WSMAN_OPERATION_TIMEDOUT. Not an error on Receive: it means the
     * command produced no output within OperationTimeout and the caller should
     * simply ask again. Treating it as a failure would abort every collection
     * that takes longer to start than the timeout.
     */
    public const OPERATION_TIMEOUT = 2150858793;

    /** The shell or command id is unknown — usually because the shell expired. */
    public const SHELL_NOT_FOUND = 2150858843;

    public const ACCESS_DENIED = 5;

    public function __construct(
        string $message,
        public readonly ?int $faultCode = null,
        public readonly ?string $subcode = null,
        public readonly ?string $detail = null,
        public readonly ?string $providerFault = null,
    ) {
        parent::__construct($message);
    }

    public function isTimeout(): bool
    {
        // The numeric code is the reliable signal in practice, the subcode is
        // the one the specification defines. Accept either: a host that
        // reports only one of them still gets a retry rather than an abort.
        return $this->faultCode === self::OPERATION_TIMEOUT
            || $this->subcode === 'TimedOut'
            || $this->subcode === 'OperationTimeout';
    }

    public function isShellGone(): bool
    {
        return $this->faultCode === self::SHELL_NOT_FOUND
            || $this->subcode === 'InvalidSelectors'
            || $this->subcode === 'DestinationUnreachable';
    }

    public function isAccessDenied(): bool
    {
        return $this->faultCode === self::ACCESS_DENIED || $this->subcode === 'AccessDenied';
    }

    /**
     * A sentence an administrator can act on, rather than the raw fault text —
     * which on Windows is frequently a 400-word paragraph about WS-Management
     * quotas when the actual problem is a missing group membership.
     */
    public function advice(): ?string
    {
        if ($this->isAccessDenied()) {
            return 'Das Konto darf sich am WinRM-Endpunkt nicht anmelden. '
                . 'Prüfen: Mitglied von "Remote Management Users" und lesender '
                . 'Zugriff auf den Kanal (siehe docs/winrm.md).';
        }

        if ($this->subcode === 'QuotaLimit') {
            return 'Das WinRM-Kontingent des Hosts ist erschöpft (MaxConcurrentOperationsPerUser '
                . 'oder MaxShellsPerUser). Entweder das Abrufintervall erhöhen oder die Grenze anheben.';
        }

        if ($this->isShellGone()) {
            return 'Die Remote-Shell ist abgelaufen, bevor der Abruf fertig war. '
                . 'Meist zu viele Events pro Lauf — max_events verkleinern.';
        }

        return null;
    }
}
