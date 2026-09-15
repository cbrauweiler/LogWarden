<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Syslog;

use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Core\Logger;
use LogWarden\Event\EventWriter;
use LogWarden\Event\NormalizerInterface;
use RuntimeException;
use Throwable;

/**
 * Single-process syslog listener for UDP, TCP and TCP/TLS.
 *
 * One event loop over stream_select rather than a process or thread per
 * connection: a handful of FortiGates at a few thousand events per second fits
 * comfortably in one PHP process, and staying single-process keeps the batch
 * writer's buffer coherent without any shared state.
 */
final class SyslogServer
{
    private const IDLE_TIMEOUT   = 300.0;   // seconds before an idle TCP client is reaped
    private const MAX_CLIENTS    = 256;
    private const SELECT_TIMEOUT = 250000;  // microseconds

    /** @var array<string, resource> */
    private array $listeners = [];

    /** @var array<string, array{stream: resource, peer: string, buffer: string, tls_pending: bool, last: float}> */
    private array $clients = [];

    private bool $running = false;

    private int $received = 0;
    private int $normalized = 0;
    private int $skipped = 0;
    private int $rejected = 0;
    private int $malformed = 0;
    private float $lastStats;

    /** @param list<NormalizerInterface> $normalizers */
    public function __construct(
        private readonly array $settings,
        private readonly EventWriter $writer,
        private readonly Logger $logger,
        private readonly array $normalizers,
        private readonly SyslogParser $parser = new SyslogParser(),
        private readonly ?PeerFilter $peerFilter = null,
    ) {
        $this->lastStats = microtime(true);
    }

    public function run(): void
    {
        $this->openListeners();
        $this->running = true;
        $this->installSignalHandlers();

        $this->logger->info('Syslog listener ready', [
            'listeners'   => array_keys($this->listeners),
            'normalizers' => count($this->normalizers),
        ]);

        while ($this->running) {
            $this->tick();
        }

        $this->shutdown();
    }

    public function stop(): void
    {
        $this->running = false;
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    private function openListeners(): void
    {
        $udp = $this->settings['udp'] ?? [];
        if (($udp['enabled'] ?? false) === true) {
            $this->listeners['udp'] = $this->bind(
                sprintf('udp://%s:%d', $udp['bind'] ?? '0.0.0.0', (int) ($udp['port'] ?? 514)),
                STREAM_SERVER_BIND,
            );
        }

        $tcp = $this->settings['tcp'] ?? [];
        if (($tcp['enabled'] ?? false) === true) {
            $this->listeners['tcp'] = $this->bind(
                sprintf('tcp://%s:%d', $tcp['bind'] ?? '0.0.0.0', (int) ($tcp['port'] ?? 514)),
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
            );
        }

        $tls = $this->settings['tls'] ?? [];
        if (($tls['enabled'] ?? false) === true) {
            $this->listeners['tls'] = $this->bind(
                sprintf('tcp://%s:%d', $tls['bind'] ?? '0.0.0.0', (int) ($tls['port'] ?? 6514)),
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
                $this->tlsContext($tls),
            );
        }

        if ($this->listeners === []) {
            throw new RuntimeException('No syslog listener enabled; check the syslog section of your config.');
        }
    }

    /** @return resource */
    private function bind(string $address, int $flags, mixed $context = null)
    {
        $context ??= stream_context_create();

        $stream = @stream_socket_server($address, $errno, $errstr, $flags, $context);
        if ($stream === false) {
            throw new RuntimeException("Cannot bind {$address}: {$errstr} ({$errno})");
        }

        stream_set_blocking($stream, false);
        $this->logger->info('Listening', ['address' => $address]);

        return $stream;
    }

    /** @param array<string, mixed> $tls */
    private function tlsContext(array $tls): mixed
    {
        $certFile = $tls['cert_file'] ?? null;
        if (!is_string($certFile) || !is_file($certFile)) {
            throw new RuntimeException('syslog.tls.cert_file must point to a PEM file containing certificate and key.');
        }

        $options = [
            'local_cert'        => $certFile,
            'allow_self_signed' => false,
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            // TLS 1.2 is the floor; FortiOS negotiates 1.3 where available.
            'crypto_method'     => STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            'ciphers'           => 'HIGH:!SSLv3:!TLSv1:!aNULL:!eNULL:!MD5:!RC4',
            'disable_compression' => true,
        ];

        // Requiring client certificates turns the listener from "anyone on the
        // network" into mutual authentication, which is the only way to make
        // syslog ingestion trustworthy.
        if (!empty($tls['ca_file'])) {
            $options['cafile']            = $tls['ca_file'];
            $options['verify_peer']       = true;
            $options['capture_peer_cert'] = true;
        }

        return stream_context_create(['ssl' => $options]);
    }

    private function installSignalHandlers(): void
    {
        if (!function_exists('pcntl_async_signals')) {
            return;
        }

        pcntl_async_signals(true);
        pcntl_signal(SIGTERM, fn () => $this->stop());
        pcntl_signal(SIGINT, fn () => $this->stop());
    }

    // -----------------------------------------------------------------------
    // Event loop
    // -----------------------------------------------------------------------

    private function tick(): void
    {
        $read   = $this->listeners;
        foreach ($this->clients as $id => $client) {
            $read['client:' . $id] = $client['stream'];
        }

        $write  = null;
        $except = null;

        // stream_select warns when a signal interrupts it; the handler has
        // already set $running, so a quiet return is the correct response.
        $ready = @stream_select($read, $write, $except, 0, self::SELECT_TIMEOUT);

        if ($ready === false) {
            $this->writer->flushIfDue();

            return;
        }

        if ($ready > 0) {
            foreach ($read as $key => $stream) {
                match (true) {
                    $key === 'udp'                => $this->readDatagram($stream),
                    $key === 'tcp', $key === 'tls' => $this->acceptClient($stream, $key === 'tls'),
                    default                        => $this->readClient(substr((string) $key, 7)),
                };
            }
        }

        $this->writer->flushIfDue();
        $this->reapIdleClients();
        $this->reportStats();
    }

    /** @param resource $stream */
    private function readDatagram($stream): void
    {
        $maxBytes = (int) ($this->settings['max_message_bytes'] ?? 65535);

        // Drain the socket: one datagram per select would cap UDP throughput at
        // roughly four events per loop iteration.
        for ($i = 0; $i < 512; $i++) {
            $peer    = '';
            $payload = @stream_socket_recvfrom($stream, $maxBytes, 0, $peer);

            if ($payload === false || $payload === '') {
                return;
            }

            $this->handleLine($payload, $this->peerAddress($peer));
        }
    }

    /** @param resource $stream */
    private function acceptClient($stream, bool $tls): void
    {
        $peer   = '';
        $client = @stream_socket_accept($stream, 0, $peer);

        if ($client === false) {
            return;
        }

        $address = $this->peerAddress($peer);

        if ($this->peerFilter !== null && !$this->peerFilter->allows($address)) {
            $this->rejected++;
            fclose($client);

            return;
        }

        if (count($this->clients) >= self::MAX_CLIENTS) {
            $this->logger->warning('Client limit reached, refusing connection', ['peer' => $address]);
            fclose($client);

            return;
        }

        stream_set_blocking($client, false);

        $id = bin2hex(random_bytes(6));
        $this->clients[$id] = [
            'stream'      => $client,
            'peer'        => $address ?? 'unknown',
            'buffer'      => '',
            // The handshake is driven from the read loop so a client that
            // stalls mid-handshake cannot block ingestion from everyone else.
            'tls_pending' => $tls,
            'last'        => microtime(true),
        ];

        $this->logger->debug('Client connected', ['peer' => $address, 'tls' => $tls]);
    }

    private function readClient(string $id): void
    {
        $client = $this->clients[$id] ?? null;
        if ($client === null) {
            return;
        }

        $this->clients[$id]['last'] = microtime(true);

        if ($client['tls_pending']) {
            $result = @stream_socket_enable_crypto($client['stream'], true, STREAM_CRYPTO_METHOD_TLS_SERVER);

            if ($result === true) {
                $this->clients[$id]['tls_pending'] = false;
                $this->logger->debug('TLS handshake complete', ['peer' => $client['peer']]);
            } elseif ($result === false) {
                $this->logger->warning('TLS handshake failed', ['peer' => $client['peer']]);
                $this->closeClient($id);
            }

            return;   // 0 means "needs more data"; try again on the next tick
        }

        $chunk = @fread($client['stream'], 65536);

        if ($chunk === false || ($chunk === '' && feof($client['stream']))) {
            $this->closeClient($id);

            return;
        }

        if ($chunk === '') {
            return;
        }

        $this->clients[$id]['buffer'] .= $chunk;
        $this->drainBuffer($id);
    }

    /**
     * Extracts complete frames. RFC 6587 allows two framings on TCP and
     * FortiOS uses either depending on configuration, so both are supported:
     * octet counting ("123 <189>...") and newline termination.
     */
    private function drainBuffer(string $id): void
    {
        $maxBytes = (int) ($this->settings['max_message_bytes'] ?? 65535);

        while (true) {
            $buffer = $this->clients[$id]['buffer'];
            if ($buffer === '') {
                return;
            }

            if (preg_match('/^(\d{1,9}) /', $buffer, $m) === 1) {
                $length = (int) $m[1];
                $offset = strlen($m[0]);

                if ($length > $maxBytes) {
                    $this->logger->warning('Oversized frame, dropping client', [
                        'peer'   => $this->clients[$id]['peer'],
                        'length' => $length,
                    ]);
                    $this->malformed++;
                    $this->closeClient($id);

                    return;
                }

                if (strlen($buffer) < $offset + $length) {
                    return;   // frame still incomplete
                }

                $this->clients[$id]['buffer'] = substr($buffer, $offset + $length);
                $this->handleLine(substr($buffer, $offset, $length), $this->clients[$id]['peer']);

                continue;
            }

            $newline = strpos($buffer, "\n");

            if ($newline === false) {
                if (strlen($buffer) > $maxBytes) {
                    $this->logger->warning('Unterminated frame exceeded limit, dropping client', [
                        'peer' => $this->clients[$id]['peer'],
                    ]);
                    $this->malformed++;
                    $this->closeClient($id);
                }

                return;
            }

            $this->clients[$id]['buffer'] = substr($buffer, $newline + 1);
            $line = rtrim(substr($buffer, 0, $newline), "\r");

            if ($line !== '') {
                $this->handleLine($line, $this->clients[$id]['peer']);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Processing
    // -----------------------------------------------------------------------

    private function handleLine(string $line, ?string $peer): void
    {
        $this->received++;

        if ($this->peerFilter !== null && !$this->peerFilter->allows($peer)) {
            $this->rejected++;

            return;
        }

        $line = rtrim($line, "\r\n\0");
        if ($line === '') {
            return;
        }

        $receivedAt = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $message    = $this->parser->parse($line, $peer, $receivedAt);
        $context    = ['syslog' => $message, 'peer' => $peer, 'received_at' => $receivedAt];

        foreach ($this->normalizers as $normalizer) {
            try {
                if (!$normalizer->supports($line, $context)) {
                    continue;
                }

                $events = $normalizer->normalize($line, $context);

                if ($events === []) {
                    $this->skipped++;   // recognised, but not a category we store

                    return;
                }

                foreach ($events as $event) {
                    $this->writer->add($event);
                    $this->normalized++;
                }

                return;
            } catch (Throwable $e) {
                // One malformed line must never take the listener down.
                $this->malformed++;
                $this->logger->warning('Normalizer failed', [
                    'normalizer' => $normalizer::class,
                    'peer'       => $peer,
                    'error'      => $e->getMessage(),
                    'line'       => substr($line, 0, 500),
                ]);

                return;
            }
        }

        $this->skipped++;
        $this->logger->debug('No normalizer matched', ['peer' => $peer, 'line' => substr($line, 0, 200)]);
    }

    // -----------------------------------------------------------------------
    // Housekeeping
    // -----------------------------------------------------------------------

    private function reapIdleClients(): void
    {
        $now = microtime(true);

        foreach ($this->clients as $id => $client) {
            if (($now - $client['last']) > self::IDLE_TIMEOUT) {
                $this->logger->debug('Reaping idle client', ['peer' => $client['peer']]);
                $this->closeClient($id);
            }
        }
    }

    private function closeClient(string $id): void
    {
        $client = $this->clients[$id] ?? null;
        if ($client === null) {
            return;
        }

        // A partial frame left in the buffer is a truncated message; logging it
        // is more useful than storing half an event.
        if (trim($client['buffer']) !== '') {
            $this->logger->debug('Discarding partial frame from closing client', [
                'peer'  => $client['peer'],
                'bytes' => strlen($client['buffer']),
            ]);
        }

        @fclose($client['stream']);
        unset($this->clients[$id]);
    }

    private function reportStats(): void
    {
        $now = microtime(true);
        if (($now - $this->lastStats) < 60.0) {
            return;
        }

        $elapsed = $now - $this->lastStats;
        $this->lastStats = $now;

        $this->logger->info('Throughput', [
            'received'   => $this->received,
            'normalized' => $this->normalized,
            'skipped'    => $this->skipped,
            'rejected'   => $this->rejected,
            'malformed'  => $this->malformed,
            'eps'        => round($this->received / max($elapsed, 0.001), 1),
            'clients'    => count($this->clients),
            'writer'     => $this->writer->stats(),
        ]);

        $this->received = $this->normalized = $this->skipped = $this->rejected = $this->malformed = 0;
    }

    private function shutdown(): void
    {
        $this->logger->info('Shutting down, flushing buffered events', [
            'pending' => $this->writer->pending(),
        ]);

        foreach (array_keys($this->clients) as $id) {
            $this->closeClient($id);
        }

        foreach ($this->listeners as $stream) {
            @fclose($stream);
        }

        $this->writer->flush();
        $this->logger->info('Stopped', ['writer' => $this->writer->stats()]);
    }

    /**
     * stream_socket_recvfrom hands back "ip:port", and IPv6 peers arrive as
     * "[2001:db8::1]:514".
     */
    private function peerAddress(string $peer): ?string
    {
        if ($peer === '') {
            return null;
        }

        if ($peer[0] === '[') {
            $end = strpos($peer, ']');

            return $end === false ? null : substr($peer, 1, $end - 1);
        }

        $colon = strrpos($peer, ':');

        return $colon === false ? $peer : substr($peer, 0, $colon);
    }
}
