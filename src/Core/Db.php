<?php

declare(strict_types=1);

namespace LogWarden\Core;

use PDO;
use PDOException;
use PDOStatement;
use Throwable;

/**
 * Thin PDO wrapper for PostgreSQL.
 *
 * Connects lazily and reconnects once when the server went away, which matters
 * for the ingestion daemons: they run for weeks and must survive a database
 * restart without losing the process.
 */
final class Db
{
    private ?PDO $pdo = null;

    /**
     * Tracked here rather than asked of PDO: on a dead pgsql connection
     * PDO::inTransaction() reports true, because libpq's transaction status
     * becomes PQTRANS_UNKNOWN. Trusting it would disable reconnect exactly
     * when reconnect is needed.
     */
    private bool $inTransaction = false;

    public function __construct(
        private readonly array $settings,
        private readonly ?Logger $logger = null,
    ) {
    }

    public static function fromConfig(Config $config, ?Logger $logger = null): self
    {
        return new self($config->section('db'), $logger);
    }

    public function pdo(): PDO
    {
        return $this->pdo ??= $this->connect();
    }

    private function connect(): PDO
    {
        $dsn = sprintf(
            'pgsql:host=%s;port=%d;dbname=%s',
            $this->settings['host'] ?? '127.0.0.1',
            (int) ($this->settings['port'] ?? 5432),
            $this->settings['name'] ?? 'logwarden',
        );

        $pdo = new PDO($dsn, $this->settings['user'] ?? 'logwarden', $this->settings['password'] ?? '', [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // Real prepared statements: the event writer sends large multi-row
            // INSERTs and emulation would re-parse them on every batch.
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_STRINGIFY_FETCHES  => false,
        ]);

        $pdo->exec("SET TIME ZONE 'UTC'");

        $timeout = (int) ($this->settings['statement_timeout_ms'] ?? 0);
        if ($timeout > 0) {
            $pdo->exec('SET statement_timeout = ' . $timeout);
        }

        return $pdo;
    }

    /**
     * Run a query, transparently reconnecting once if the connection dropped.
     *
     * @param array<string|int, mixed> $params
     */
    public function query(string $sql, array $params = []): PDOStatement
    {
        try {
            return $this->run($sql, $params);
        } catch (PDOException $e) {
            if (!$this->isConnectionLoss($e)) {
                throw $e;
            }

            // Never retry mid-transaction: the reconnect would open a fresh one
            // and silently drop every statement issued before the connection
            // dropped. The caller has to replay the whole unit of work.
            if ($this->inTransaction) {
                $this->pdo = null;
                $this->inTransaction = false;
                throw $e;
            }

            $this->logger?->warning('Database connection lost, reconnecting', ['sqlstate' => $e->getCode()]);
            $this->pdo = null;

            return $this->run($sql, $params);
        }
    }

    private function run(string $sql, array $params): PDOStatement
    {
        $stmt = $this->pdo()->prepare($sql);
        $stmt->execute($params === [] ? null : $params);

        return $stmt;
    }

    /** @return list<array<string, mixed>> */
    public function fetchAll(string $sql, array $params = []): array
    {
        return $this->query($sql, $params)->fetchAll();
    }

    /** @return array<string, mixed>|null */
    public function fetchRow(string $sql, array $params = []): ?array
    {
        $row = $this->query($sql, $params)->fetch();

        return $row === false ? null : $row;
    }

    public function fetchValue(string $sql, array $params = [], mixed $default = null): mixed
    {
        $value = $this->query($sql, $params)->fetchColumn();

        return $value === false ? $default : $value;
    }

    public function execute(string $sql, array $params = []): int
    {
        return $this->query($sql, $params)->rowCount();
    }

    /**
     * @template T
     * @param callable(self): T $work
     * @return T
     */
    public function transaction(callable $work): mixed
    {
        $pdo = $this->pdo();
        $pdo->beginTransaction();
        $this->inTransaction = true;

        try {
            $result = $work($this);
            $pdo->commit();
            $this->inTransaction = false;

            return $result;
        } catch (Throwable $e) {
            $this->inTransaction = false;

            try {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
            } catch (PDOException) {
                // The connection is gone; there is nothing left to roll back.
                $this->pdo = null;
            }

            throw $e;
        }
    }

    public function ping(): bool
    {
        try {
            $this->query('SELECT 1');

            return true;
        } catch (PDOException) {
            return false;
        }
    }

    public function disconnect(): void
    {
        $this->pdo = null;
        $this->inTransaction = false;
    }

    /**
     * SQLSTATE class 08 is "connection exception"; 57P01/57P02/57P03 are the
     * admin shutdown / crash / cannot-connect-now codes PostgreSQL sends on
     * restart. Everything else is a real query error and must not be retried.
     */
    private function isConnectionLoss(PDOException $e): bool
    {
        $state = (string) $e->getCode();

        if (str_starts_with($state, '08') || in_array($state, ['57P01', '57P02', '57P03'], true)) {
            return true;
        }

        // PDO reports some socket-level failures with SQLSTATE HY000 only.
        return $state === 'HY000'
            && (bool) preg_match('/server closed the connection|no connection to the server|terminating connection/i', $e->getMessage());
    }
}
