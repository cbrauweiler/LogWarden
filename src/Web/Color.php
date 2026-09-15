<?php

declare(strict_types=1);

namespace LogWarden\Web;

/**
 * Colour maths for the corporate-identity settings.
 *
 * A brand colour is chosen for the logo, not for legibility, so the theme
 * cannot simply paint white text on it. Everything here exists to derive a
 * readable palette from whatever hex the customer supplies, and to tell them
 * when their choice is going to be hard to read.
 */
final class Color
{
    /** @return array{0:int,1:int,2:int}|null */
    public static function parse(string $hex): ?array
    {
        $hex = ltrim(trim($hex), '#');

        if (strlen($hex) === 3) {
            $hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
        }

        if (preg_match('/^[0-9a-fA-F]{6}$/', $hex) !== 1) {
            return null;
        }

        return [
            (int) hexdec(substr($hex, 0, 2)),
            (int) hexdec(substr($hex, 2, 2)),
            (int) hexdec(substr($hex, 4, 2)),
        ];
    }

    public static function isValid(string $hex): bool
    {
        return self::parse($hex) !== null;
    }

    public static function normalize(string $hex, string $fallback): string
    {
        $rgb = self::parse($hex);

        return $rgb === null ? $fallback : sprintf('#%02x%02x%02x', ...$rgb);
    }

    /** WCAG 2.1 relative luminance. */
    public static function luminance(string $hex): float
    {
        $rgb = self::parse($hex) ?? [0, 0, 0];

        $channels = array_map(static function (int $value): float {
            $c = $value / 255;

            return $c <= 0.04045 ? $c / 12.92 : (($c + 0.055) / 1.055) ** 2.4;
        }, $rgb);

        return 0.2126 * $channels[0] + 0.7152 * $channels[1] + 0.0722 * $channels[2];
    }

    public static function contrast(string $a, string $b): float
    {
        $la = self::luminance($a);
        $lb = self::luminance($b);

        return (max($la, $lb) + 0.05) / (min($la, $lb) + 0.05);
    }

    /**
     * Foreground for text sitting on $background: whichever of near-black and
     * white has more contrast. A pale brand colour therefore gets dark text
     * rather than unreadable white.
     */
    public static function inkOn(string $background): string
    {
        return self::contrast($background, '#ffffff') >= self::contrast($background, '#11110f')
            ? '#ffffff'
            : '#11110f';
    }

    public static function mix(string $a, string $b, float $weight): string
    {
        $ca = self::parse($a) ?? [0, 0, 0];
        $cb = self::parse($b) ?? [0, 0, 0];
        $weight = max(0.0, min(1.0, $weight));

        return sprintf(
            '#%02x%02x%02x',
            (int) round($ca[0] * (1 - $weight) + $cb[0] * $weight),
            (int) round($ca[1] * (1 - $weight) + $cb[1] * $weight),
            (int) round($ca[2] * (1 - $weight) + $cb[2] * $weight),
        );
    }

    /**
     * A brand colour also has to work as a *text* colour (links, active nav) on
     * the page surface. Where it does not, step it toward the surface's
     * opposite until it clears the 4.5:1 body-text threshold.
     */
    public static function readableOn(string $brand, string $surface, float $target = 4.5): string
    {
        if (self::contrast($brand, $surface) >= $target) {
            return $brand;
        }

        $towards = self::luminance($surface) > 0.5 ? '#000000' : '#ffffff';
        $best    = $brand;

        for ($step = 1; $step <= 20; $step++) {
            $candidate = self::mix($brand, $towards, $step * 0.05);
            $best      = $candidate;

            if (self::contrast($candidate, $surface) >= $target) {
                return $candidate;
            }
        }

        return $best;
    }

    /** @return array{ratio: float, level: string} */
    public static function rate(string $foreground, string $background): array
    {
        $ratio = self::contrast($foreground, $background);

        return [
            'ratio' => round($ratio, 2),
            'level' => match (true) {
                $ratio >= 7.0 => 'AAA',
                $ratio >= 4.5 => 'AA',
                $ratio >= 3.0 => 'AA Large',
                default       => 'fail',
            },
        ];
    }
}
