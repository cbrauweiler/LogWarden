<?php

declare(strict_types=1);

namespace LogWarden\Search;

use DateTimeImmutable;
use DateTimeZone;
use LogWarden\Event\SourceType;

/**
 * A search, parsed from request parameters and back again.
 *
 * Every filter round-trips through the query string so a search is a link:
 * pasting one into a ticket or a chat gives the next person exactly the view
 * you were looking at.
 */
final class SearchCriteria
{
    public const PRESETS = [
        '15m' => ['label' => '15 Minuten', 'minutes' => 15],
        '1h'  => ['label' => '1 Stunde',   'minutes' => 60],
        '24h' => ['label' => '24 Stunden', 'minutes' => 1440],
        '7d'  => ['label' => '7 Tage',     'minutes' => 10080],
        '30d' => ['label' => '30 Tage',    'minutes' => 43200],
    ];

    public const PAGE_SIZES = [50, 100, 250];

    /** Beyond this the count is reported as "more than", not counted exactly. */
    public const COUNT_CAP = 10000;

    private function __construct(
        public readonly DateTimeImmutable $from,
        public readonly DateTimeImmutable $to,
        public readonly string $preset,
        /** @var list<string> */
        public readonly array $sourceTypes,
        public readonly ?string $username,
        public readonly ?string $host,
        public readonly ?string $ip,
        public readonly bool $ipValid,
        public readonly string $ipField,
        public readonly ?string $eventType,
        public readonly ?string $result,
        public readonly ?string $query,
        public readonly int $limit,
        public readonly ?string $cursorTs,
        public readonly ?int $cursorId,
    ) {
    }

    /** @param array<string, mixed> $params */
    public static function fromArray(array $params): self
    {
        $utc    = new DateTimeZone('UTC');
        $preset = (string) ($params['preset'] ?? '24h');

        if ($preset === 'custom') {
            $from = self::parseDate($params['from'] ?? null, $utc) ?? new DateTimeImmutable('-24 hours', $utc);
            $to   = self::parseDate($params['to'] ?? null, $utc)   ?? new DateTimeImmutable('now', $utc);

            // A reversed range returns nothing and looks like a bug rather than
            // a typo, so swap instead.
            if ($from > $to) {
                [$from, $to] = [$to, $from];
            }
        } else {
            if (!isset(self::PRESETS[$preset])) {
                $preset = '24h';
            }
            $to   = new DateTimeImmutable('now', $utc);
            $from = $to->modify('-' . self::PRESETS[$preset]['minutes'] . ' minutes');
        }

        $valid  = array_map(static fn (SourceType $t): string => $t->value, SourceType::cases());
        $source = $params['source'] ?? [];
        $source = is_array($source) ? $source : [$source];
        $source = array_values(array_intersect(array_map('strval', $source), $valid));

        $result = (string) ($params['result'] ?? '');
        $limit  = (int) ($params['limit'] ?? 100);
        $ip     = self::cleanup($params['ip'] ?? null);

        return new self(
            from:        $from,
            to:          $to,
            preset:      $preset,
            sourceTypes: $source,
            username:    self::cleanup($params['username'] ?? null),
            host:        self::cleanup($params['host'] ?? null),
            ip:          $ip,
            // Kept even when invalid so the field still shows what was typed;
            // the query drops it and the page says why. Letting it through
            // would reach PostgreSQL's inet cast and surface as a 500.
            ipValid:     $ip === null || self::isAddressOrNetwork($ip),
            ipField:     self::oneOf($params['ipfield'] ?? null, ['any', 'src', 'dst'], 'any'),
            eventType:   self::cleanup($params['event_type'] ?? null),
            result:      in_array($result, ['success', 'fail', 'info'], true) ? $result : null,
            query:       self::cleanup($params['q'] ?? null),
            limit:       in_array($limit, self::PAGE_SIZES, true) ? $limit : 100,
            cursorTs:    self::cleanup($params['cts'] ?? null),
            cursorId:    isset($params['cid']) ? (int) $params['cid'] : null,
        );
    }

    /**
     * Query string for this search. `$overrides` replaces individual values,
     * which is how paging and "remove this filter" links are built.
     *
     * @param array<string, mixed> $overrides
     */
    public function toQueryString(array $overrides = []): string
    {
        $params = array_filter([
            'preset'     => $this->preset,
            'from'       => $this->preset === 'custom' ? $this->from->format('Y-m-d\TH:i') : null,
            'to'         => $this->preset === 'custom' ? $this->to->format('Y-m-d\TH:i') : null,
            'username'   => $this->username,
            'host'       => $this->host,
            'ip'         => $this->ip,
            'ipfield'    => $this->ipField === 'any' ? null : $this->ipField,
            'event_type' => $this->eventType,
            'result'     => $this->result,
            'q'          => $this->query,
            'limit'      => $this->limit === 100 ? null : $this->limit,
        ], static fn (mixed $v): bool => $v !== null && $v !== '');

        if ($this->sourceTypes !== []) {
            $params['source'] = $this->sourceTypes;
        }

        foreach ($overrides as $key => $value) {
            if ($value === null || $value === '' || $value === []) {
                unset($params[$key]);
                continue;
            }
            $params[$key] = $value;
        }

        return http_build_query($params);
    }

    /** True when nothing but the time range is set. */
    public function isEmpty(): bool
    {
        return $this->sourceTypes === []
            && $this->username === null
            && $this->host === null
            && $this->ip === null
            && $this->eventType === null
            && $this->result === null
            && $this->query === null;
    }

    /** @return list<array{key:string, label:string, value:string}> */
    public function activeFilters(): array
    {
        $active = [];

        if ($this->sourceTypes !== []) {
            $labels = array_map(
                static fn (string $t): string => SourceType::from($t)->label(),
                $this->sourceTypes,
            );
            $active[] = ['key' => 'source', 'label' => 'Quelle', 'value' => implode(', ', $labels)];
        }

        foreach ([
            'username'   => ['Konto', $this->username],
            'host'       => ['System', $this->host],
            'ip'         => ['IP', $this->ip],
            'event_type' => ['Event-Typ', $this->eventType],
            'result'     => ['Ergebnis', $this->result],
            'q'          => ['Volltext', $this->query],
        ] as $key => [$label, $value]) {
            if ($value !== null) {
                $active[] = ['key' => $key, 'label' => $label, 'value' => $value];
            }
        }

        return $active;
    }

    public function rangeDays(): float
    {
        return ($this->to->getTimestamp() - $this->from->getTimestamp()) / 86400;
    }

    public static function isAddressOrNetwork(string $value): bool
    {
        if (!str_contains($value, '/')) {
            return filter_var($value, FILTER_VALIDATE_IP) !== false;
        }

        [$address, $bits] = explode('/', $value, 2);

        if (filter_var($address, FILTER_VALIDATE_IP) === false || !ctype_digit($bits)) {
            return false;
        }

        $max = str_contains($address, ':') ? 128 : 32;

        return (int) $bits >= 0 && (int) $bits <= $max;
    }

    /** @param list<string> $allowed */
    private static function oneOf(mixed $value, array $allowed, string $default): string
    {
        return is_string($value) && in_array($value, $allowed, true) ? $value : $default;
    }

    private static function cleanup(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : mb_substr($value, 0, 200);
    }

    private static function parseDate(mixed $value, DateTimeZone $tz): ?DateTimeImmutable
    {
        if (!is_string($value) || trim($value) === '') {
            return null;
        }

        try {
            return new DateTimeImmutable($value, $tz);
        } catch (\Exception) {
            return null;
        }
    }
}
