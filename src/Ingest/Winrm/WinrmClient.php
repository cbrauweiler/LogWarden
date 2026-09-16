<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use CurlHandle;
use LogWarden\Core\Logger;
use SensitiveParameter;

/**
 * HTTP transport for WinRM.
 *
 * One instance is one authenticated connection to one host. The curl handle is
 * kept for the life of the object on purpose: NTLM authenticates the *TCP
 * connection*, not the request. A fresh handle per SOAP call would repeat the
 * three-legged handshake for every Receive — and against a domain controller
 * under load that turns a 200 ms collection into several seconds of
 * negotiation, with a matching trail of 4624/4634 pairs in the very log being
 * collected.
 */
final class WinrmClient
{
    public const DEFAULT_PORT_HTTPS = 5986;
    public const DEFAULT_PORT_HTTP  = 5985;

    private ?CurlHandle $handle = null;

    private int $requests = 0;

    public function __construct(
        private readonly string $host,
        private readonly string $username,
        #[SensitiveParameter] private readonly string $password,
        private readonly array $options = [],
        private readonly ?Logger $logger = null,
    ) {
    }

    public function endpoint(): string
    {
        $tls  = (bool) ($this->options['tls'] ?? true);
        $port = (int) ($this->options['port'] ?? ($tls ? self::DEFAULT_PORT_HTTPS : self::DEFAULT_PORT_HTTP));
        $path = (string) ($this->options['path'] ?? '/wsman');

        return sprintf('%s://%s:%d%s', $tls ? 'https' : 'http', $this->host, $port, $path);
    }

    public function requestCount(): int
    {
        return $this->requests;
    }

    /**
     * Sends one SOAP envelope and returns the parsed response.
     *
     * @throws WinrmException on a transport problem
     * @throws WsmanFault     when the host answers with a SOAP fault
     */
    public function send(string $envelope): WsmanResponse
    {
        $handle = $this->handle ??= $this->createHandle();

        curl_setopt($handle, CURLOPT_POSTFIELDS, $envelope);

        $body = curl_exec($handle);
        $this->requests++;

        if ($body === false) {
            $errno = curl_errno($handle);
            throw new WinrmException($this->describeCurlError($errno, curl_error($handle)));
        }

        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        // 401 never carries a fault body worth parsing, and the WWW-Authenticate
        // negotiation has already failed by the time curl gives up.
        if ($status === 401) {
            throw new WinrmException(
                'Anmeldung am WinRM-Endpunkt abgelehnt (HTTP 401). Benutzername, Passwort '
                . 'oder Authentifizierungsverfahren prüfen — bei NTLM muss der Name die Form '
                . 'DOMAENE\\benutzer oder benutzer@domaene haben.',
            );
        }

        // Windows answers faults with 500 and a SOAP body, so the body is
        // parsed for 500 as well; parse() raises the fault it finds.
        if ($status !== 200 && $status !== 500) {
            throw new WinrmException(sprintf(
                'Unerwartete Antwort vom WinRM-Endpunkt: HTTP %d%s',
                $status,
                $status === 404 ? ' — kein WinRM-Listener unter ' . $this->endpoint() : '',
            ));
        }

        if (trim((string) $body) === '') {
            throw new WinrmException('Leere Antwort vom WinRM-Endpunkt (HTTP ' . $status . ')');
        }

        return WsmanResponse::parse((string) $body);
    }

    /**
     * Checks that something at the endpoint speaks WS-Management, without
     * authenticating. Separates "no listener / wrong port / firewall" from
     * "wrong credentials", which are two entirely different fixes.
     *
     * @return array{vendor: ?string, version: ?string}
     */
    public function identify(): array
    {
        $envelope = new WsmanEnvelope($this->endpoint());
        $response = $this->send($envelope->identify());

        return [
            'vendor'  => $response->productVendor(),
            'version' => $response->protocolVersion(),
        ];
    }

    public function close(): void
    {
        if ($this->handle !== null) {
            curl_close($this->handle);
            $this->handle = null;
        }
    }

    public function __destruct()
    {
        $this->close();
    }

    private function createHandle(): CurlHandle
    {
        $handle = curl_init($this->endpoint());
        if ($handle === false) {
            throw new WinrmException('curl konnte nicht initialisiert werden');
        }

        $authMode = (string) ($this->options['auth'] ?? 'ntlm');
        $tls      = (bool) ($this->options['tls'] ?? true);

        curl_setopt_array($handle, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/soap+xml;charset=UTF-8',
                'User-Agent: LogWarden-WinRM/1.0',
                // Windows answers "Expect: 100-continue" with a delay of up to
                // a second on some builds; curl adds it for larger bodies.
                'Expect:',
            ],
            CURLOPT_HTTPAUTH       => $this->authFlag($authMode),
            CURLOPT_USERPWD        => $this->username . ':' . $this->password,
            CURLOPT_CONNECTTIMEOUT => (int) ($this->options['connect_timeout'] ?? 10),
            // Must exceed the SOAP OperationTimeout: a Receive legitimately
            // blocks on the host until output appears or that timeout expires,
            // and cutting it off locally would look like a network failure.
            CURLOPT_TIMEOUT        => (int) ($this->options['read_timeout'] ?? 90),
            CURLOPT_FORBID_REUSE   => false,
            CURLOPT_FRESH_CONNECT  => false,
        ]);

        if ($tls) {
            $verify = (bool) ($this->options['tls_verify'] ?? true);

            curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, $verify);
            curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, $verify ? 2 : 0);

            if (!empty($this->options['ca_file'])) {
                curl_setopt($handle, CURLOPT_CAINFO, (string) $this->options['ca_file']);
            }

            if (!$verify) {
                // Loud, because the usual reason is the self-signed certificate
                // `winrm quickconfig` generates, and that leaves the credentials
                // of a domain account open to anyone on the path.
                $this->logger?->warning('WinRM ohne Zertifikatsprüfung', [
                    'host' => $this->host,
                    'hint' => 'ca_file setzen oder ein Zertifikat der eigenen CA auf dem Host hinterlegen',
                ]);
            }
        }

        if ($authMode === 'basic' && !$tls) {
            throw new WinrmException(
                'Basic-Authentifizierung über HTTP würde das Passwort im Klartext senden. '
                . 'Entweder TLS aktivieren oder auth=ntlm verwenden.',
            );
        }

        return $handle;
    }

    private function authFlag(string $mode): int
    {
        return match ($mode) {
            'ntlm'     => CURLAUTH_NTLM,
            'kerberos' => CURLAUTH_NEGOTIATE,
            'basic'    => CURLAUTH_BASIC,
            default    => throw new WinrmException('Unbekanntes Authentifizierungsverfahren: ' . $mode),
        };
    }

    /**
     * curl's own messages are accurate but assume the reader knows curl. The
     * three failures below are the ones a WinRM setup actually hits, and each
     * has a specific fix worth naming.
     */
    private function describeCurlError(int $errno, string $message): string
    {
        $endpoint = $this->endpoint();

        return match ($errno) {
            CURLE_COULDNT_CONNECT => sprintf(
                '%s nicht erreichbar. Läuft der WinRM-Listener (winrm enumerate winrm/config/listener) '
                . 'und lässt die Firewall den Port durch?',
                $endpoint,
            ),
            CURLE_SSL_CACERT, CURLE_PEER_FAILED_VERIFICATION => sprintf(
                'TLS-Zertifikat von %s nicht überprüfbar: %s. Entweder das CA-Zertifikat in ca_file '
                . 'hinterlegen oder auf dem Host ein Zertifikat der eigenen CA einrichten.',
                $this->host,
                $message,
            ),
            CURLE_OPERATION_TIMEDOUT => sprintf(
                'Zeitüberschreitung gegenüber %s nach %d s. Bei großen Abrufen max_events senken.',
                $endpoint,
                (int) ($this->options['read_timeout'] ?? 90),
            ),
            CURLE_COULDNT_RESOLVE_HOST => sprintf('Hostname %s nicht auflösbar.', $this->host),
            default => sprintf('Verbindung zu %s fehlgeschlagen: %s', $endpoint, $message),
        };
    }
}
