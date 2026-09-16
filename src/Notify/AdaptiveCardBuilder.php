<?php

declare(strict_types=1);

namespace LogWarden\Notify;

/**
 * Builds the Adaptive Card payload Teams expects.
 *
 * Card version 1.4: Teams renders it reliably on desktop, web and mobile, and
 * 1.5 features buy nothing here.
 *
 * A note on branding: Teams enforces its own theme, so the corporate colours
 * configured in LogWarden cannot cross into the card. Severity therefore uses
 * the card's own semantic keywords, which is the right call anyway — they
 * follow the reader's Teams theme and stay legible in dark mode. Only the
 * product name travels.
 */
final class AdaptiveCardBuilder
{
    private const SEVERITY_LABELS = [
        1 => 'Info',
        2 => 'Niedrig',
        3 => 'Mittel',
        4 => 'Hoch',
        5 => 'Kritisch',
    ];

    /**
     * Card colour keywords, not brand colours — they follow the reader's Teams
     * theme instead of fighting it.
     */
    private const SEVERITY_STYLE = [
        1 => ['container' => 'accent',    'text' => 'accent'],
        2 => ['container' => 'accent',    'text' => 'accent'],
        3 => ['container' => 'warning',   'text' => 'warning'],
        4 => ['container' => 'warning',   'text' => 'warning'],
        5 => ['container' => 'attention', 'text' => 'attention'],
    ];

    /**
     * @param array<string, mixed> $alert
     * @param array<string, mixed> $branding
     * @return array<string, mixed>
     */
    public function alertCard(array $alert, array $branding): array
    {
        $severity = max(1, min(5, (int) ($alert['severity'] ?? 3)));
        $style    = self::SEVERITY_STYLE[$severity];
        $product  = (string) ($branding['product_name'] ?? 'LogWarden');
        $evidence = $this->decodeEvidence($alert);

        $body = [
            $this->header($product, $severity, $style, (string) ($alert['title'] ?? 'Alert')),
            [
                'type'  => 'TextBlock',
                'text'  => (string) ($alert['summary'] ?? ''),
                'wrap'  => true,
                'spacing' => 'Medium',
            ],
            [
                'type'  => 'FactSet',
                'facts' => $this->facts($alert, $evidence),
                'spacing' => 'Medium',
            ],
        ];

        $origins = $this->originBlock($evidence);
        if ($origins !== null) {
            $body[] = $origins;
        }

        $card = [
            '$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
            'type'    => 'AdaptiveCard',
            'version' => '1.4',
            'msteams' => ['width' => 'Full'],
            'body'    => $body,
        ];

        $url = $this->alertUrl($alert, $branding);
        if ($url !== null) {
            $card['actions'] = [[
                'type'  => 'Action.OpenUrl',
                'title' => 'In ' . $product . ' öffnen',
                'url'   => $url,
            ]];
        }

        return $card;
    }

    /** @return array<string, mixed> */
    public function testCard(array $branding, string $channelName): array
    {
        $product = (string) ($branding['product_name'] ?? 'LogWarden');

        return [
            '$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
            'type'    => 'AdaptiveCard',
            'version' => '1.4',
            'msteams' => ['width' => 'Full'],
            'body'    => [
                [
                    'type'  => 'Container',
                    'style' => 'good',
                    'bleed' => true,
                    'items' => [
                        ['type' => 'TextBlock', 'text' => $product, 'size' => 'Small', 'weight' => 'Bolder', 'isSubtle' => true],
                        ['type' => 'TextBlock', 'text' => 'Testnachricht', 'size' => 'Large', 'weight' => 'Bolder', 'wrap' => true],
                    ],
                ],
                [
                    'type' => 'TextBlock',
                    'text' => "Der Kanal **{$channelName}** ist korrekt eingerichtet. "
                        . 'Echte Alerts erscheinen im selben Format.',
                    'wrap' => true,
                    'spacing' => 'Medium',
                ],
                [
                    'type'  => 'FactSet',
                    'facts' => [
                        ['title' => 'Gesendet', 'value' => gmdate('d.m.Y H:i:s') . ' UTC'],
                        ['title' => 'Kanal',    'value' => $channelName],
                    ],
                ],
            ],
        ];
    }

    /**
     * Teams accepts the card inside a message envelope; both the legacy
     * connector and the Power Automate workflow endpoint read the same shape.
     *
     * @param array<string, mixed> $card
     * @return array<string, mixed>
     */
    public function envelope(array $card): array
    {
        return [
            'type'        => 'message',
            'attachments' => [[
                'contentType' => 'application/vnd.microsoft.card.adaptive',
                'contentUrl'  => null,
                'content'     => $card,
            ]],
        ];
    }

    // -----------------------------------------------------------------------

    /** @return array<string, mixed> */
    private function header(string $product, int $severity, array $style, string $title): array
    {
        return [
            'type'  => 'Container',
            'style' => $style['container'],
            'bleed' => true,
            'items' => [
                [
                    'type'    => 'ColumnSet',
                    'columns' => [
                        [
                            'type'  => 'Column',
                            'width' => 'stretch',
                            'items' => [[
                                'type'     => 'TextBlock',
                                'text'     => $product,
                                'size'     => 'Small',
                                'weight'   => 'Bolder',
                                'isSubtle' => true,
                            ]],
                        ],
                        [
                            'type'  => 'Column',
                            'width' => 'auto',
                            'items' => [[
                                'type'   => 'TextBlock',
                                'text'   => self::SEVERITY_LABELS[$severity],
                                'size'   => 'Small',
                                'weight' => 'Bolder',
                                'color'  => $style['text'],
                                // Colour is never the only signal: the word is
                                // right there, and it survives a colourblind
                                // reader and a monochrome notification preview.
                            ]],
                        ],
                    ],
                ],
                [
                    'type'   => 'TextBlock',
                    'text'   => $title,
                    'size'   => 'Large',
                    'weight' => 'Bolder',
                    'wrap'   => true,
                ],
            ],
        ];
    }

    /**
     * @param array<string, mixed> $alert
     * @param array<string, mixed> $evidence
     * @return list<array{title:string, value:string}>
     */
    private function facts(array $alert, array $evidence): array
    {
        $facts = [];

        $add = static function (string $title, mixed $value) use (&$facts): void {
            if ($value !== null && $value !== '' && $value !== []) {
                $facts[] = ['title' => $title, 'value' => (string) $value];
            }
        };

        $add('Regel',      $alert['rule_name'] ?? null);
        $add('Konto',      $alert['entity_user'] ?? null);
        $add('Quell-IP',   $alert['entity_ip'] ?? null);
        $add('System',     $alert['entity_host'] ?? null);
        $add('Events',     $alert['event_count'] ?? null);

        $peak = (int) ($evidence['peak_count'] ?? 0);
        if ($peak > (int) ($alert['event_count'] ?? 0)) {
            $add('Höchststand', $peak);
        }

        if (!empty($evidence['by_source']) && is_array($evidence['by_source'])) {
            $parts = [];
            foreach ($evidence['by_source'] as $source => $count) {
                $parts[] = "{$source}: {$count}";
            }
            $add('Quellen', implode(' · ', $parts));
        }

        $add('Ausgelöst', $alert['triggered_label'] ?? null);

        return $facts;
    }

    /**
     * "Twelve attempts from one address" and "twelve from twelve addresses"
     * need different responses, and that is exactly the judgement the person
     * reading the chat message has to make.
     *
     * @param array<string, mixed> $evidence
     * @return array<string, mixed>|null
     */
    private function originBlock(array $evidence): ?array
    {
        $origins = $evidence['by_origin'] ?? null;
        if (!is_array($origins) || $origins === []) {
            return null;
        }

        $lines = [];
        foreach (array_slice($origins, 0, 4) as $origin) {
            if (!is_array($origin)) {
                continue;
            }
            $lines[] = sprintf(
                '- **%s** → %s · %d Versuche',
                $origin['src_ip'] ?? 'unbekannt',
                $origin['target_host'] ?? '—',
                (int) ($origin['count'] ?? 0),
            );
        }

        if ($lines === []) {
            return null;
        }

        if (count($origins) > 4) {
            $lines[] = '- … und ' . (count($origins) - 4) . ' weitere';
        }

        return [
            'type'    => 'Container',
            'spacing' => 'Medium',
            'items'   => [
                ['type' => 'TextBlock', 'text' => 'Herkunft', 'weight' => 'Bolder', 'size' => 'Small'],
                ['type' => 'TextBlock', 'text' => implode("\n\n", $lines), 'wrap' => true],
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function decodeEvidence(array $alert): array
    {
        $evidence = $alert['evidence'] ?? null;

        if (is_array($evidence)) {
            return $evidence;
        }

        $decoded = json_decode((string) $evidence, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Only produced when a base URL is configured, and only for https or a
     * plain host — a card that links somewhere unexpected is worse than a card
     * with no link.
     */
    private function alertUrl(array $alert, array $branding): ?string
    {
        $base = trim((string) ($branding['base_url'] ?? ''));
        $id   = (int) ($alert['id'] ?? 0);

        if ($base === '' || $id <= 0) {
            return null;
        }

        $parts = parse_url($base);
        if ($parts === false || !isset($parts['host']) || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)) {
            return null;
        }

        return rtrim($base, '/') . '/alert?id=' . $id;
    }
}
