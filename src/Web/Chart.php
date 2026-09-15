<?php

declare(strict_types=1);

namespace LogWarden\Web;

/**
 * Inline-SVG stacked bar chart for event volume over time.
 *
 * Hand-rolled rather than pulling in a charting library: the whole frontend is
 * server-rendered, and a bar chart is a few dozen rectangles. It also means the
 * chart renders with JavaScript disabled and prints correctly.
 *
 * Mark rules applied here: 2px surface-coloured gap between stacked segments,
 * 4px rounded ends on the top of each stack, recessive grid, native <title>
 * tooltips, and a table view alongside (three of the five series colours sit
 * below 3:1 on the light surface, so a non-colour reading has to exist).
 */
final class Chart
{
    private const WIDTH      = 1000;
    private const HEIGHT     = 230;
    private const PAD_LEFT   = 46;
    private const PAD_RIGHT  = 10;
    private const PAD_TOP    = 14;
    private const PAD_BOTTOM = 26;
    private const SEG_GAP    = 2;
    private const CORNER     = 4;

    /**
     * @param list<string>              $buckets ISO-ish bucket keys
     * @param array<string, list<int>>  $series  source_type => value per bucket
     * @param array<string, string>     $labels  source_type => display label
     * @param array<string, string>     $colors  source_type => CSS variable name
     */
    public static function stackedBars(
        array $buckets,
        array $series,
        array $labels,
        array $colors,
        int $max,
    ): string {
        if ($buckets === []) {
            return '<p class="muted" style="padding:0 var(--card-pad) var(--card-pad)">Noch keine Events im gewählten Zeitraum.</p>';
        }

        $plotWidth  = self::WIDTH - self::PAD_LEFT - self::PAD_RIGHT;
        $plotHeight = self::HEIGHT - self::PAD_TOP - self::PAD_BOTTOM;
        $baseline   = self::PAD_TOP + $plotHeight;

        $count     = count($buckets);
        $slotWidth = $plotWidth / $count;
        $barWidth  = max(2.0, min(34.0, $slotWidth * 0.72));

        // A y-axis that ends on a round number reads better than one that ends
        // on the raw maximum.
        $scaleMax = self::niceCeiling($max);

        $svg = sprintf(
            '<svg class="chart" viewBox="0 0 %d %d" role="img" preserveAspectRatio="none" '
            . 'aria-label="Event-Volumen pro Stunde, gestapelt nach Quelle" height="%d">',
            self::WIDTH,
            self::HEIGHT,
            self::HEIGHT,
        );

        // --- grid and y ticks ---
        foreach ([0.0, 0.5, 1.0] as $fraction) {
            $y     = self::PAD_TOP + $plotHeight * (1 - $fraction);
            $value = (int) round($scaleMax * $fraction);

            $svg .= sprintf(
                '<line class="chart__%s" x1="%s" y1="%s" x2="%d" y2="%s" />',
                $fraction === 0.0 ? 'base' : 'grid',
                self::PAD_LEFT,
                self::fmt($y),
                self::WIDTH - self::PAD_RIGHT,
                self::fmt($y),
            );
            $svg .= sprintf(
                '<text class="chart__ytick" x="%d" y="%s" text-anchor="end">%s</text>',
                self::PAD_LEFT - 8,
                self::fmt($y + 3.5),
                View::e(View::number($value)),
            );
        }

        // --- bars ---
        $orderedTypes = array_keys($labels);

        foreach ($buckets as $index => $bucket) {
            $x       = self::PAD_LEFT + $slotWidth * $index + ($slotWidth - $barWidth) / 2;
            $cursor  = $baseline;
            $total   = 0;

            foreach ($orderedTypes as $type) {
                $total += $series[$type][$index] ?? 0;
            }

            // Walk top-down so the last drawn segment is the one that needs
            // rounded corners; drawing bottom-up would round the wrong end.
            $segments = [];
            foreach ($orderedTypes as $type) {
                $value = $series[$type][$index] ?? 0;
                if ($value > 0) {
                    $segments[] = [$type, $value];
                }
            }

            foreach ($segments as $position => [$type, $value]) {
                $height = $scaleMax > 0 ? ($value / $scaleMax) * $plotHeight : 0.0;
                if ($height <= 0) {
                    continue;
                }

                $isTop  = $position === count($segments) - 1;
                $top    = $cursor - $height;
                $drawn  = $height;

                // The gap is carved out of the segment below it so the stack's
                // total height still encodes the real total faithfully.
                if (!$isTop) {
                    $drawn = max(0.5, $height - self::SEG_GAP / 2);
                }

                $title = sprintf(
                    '%s — %s: %s Events',
                    self::bucketLabel($bucket, true),
                    $labels[$type],
                    View::number($value),
                );

                $svg .= sprintf(
                    '<path class="chart__seg" fill="var(%s)" d="%s"><title>%s</title></path>',
                    $colors[$type],
                    $isTop
                        ? self::roundedTopPath($x, $top, $barWidth, $drawn)
                        : self::rectPath($x, $top, $barWidth, $drawn),
                    View::e($title),
                );

                $cursor = $top;
            }

            if ($segments === []) {
                // A hover target for empty buckets, so "nothing happened here"
                // is readable rather than just absent.
                $svg .= sprintf(
                    '<rect x="%s" y="%d" width="%s" height="%s" fill="transparent"><title>%s: keine Events</title></rect>',
                    self::fmt($x),
                    self::PAD_TOP,
                    self::fmt($barWidth),
                    self::fmt($plotHeight),
                    View::e(self::bucketLabel($bucket, true)),
                );
            }
        }

        // --- x ticks: a handful, never one per bar ---
        $every = max(1, (int) ceil($count / 8));
        foreach ($buckets as $index => $bucket) {
            if ($index % $every !== 0) {
                continue;
            }

            $svg .= sprintf(
                '<text class="chart__tick" x="%s" y="%d" text-anchor="middle">%s</text>',
                self::fmt(self::PAD_LEFT + $slotWidth * $index + $slotWidth / 2),
                self::HEIGHT - 8,
                View::e(self::bucketLabel($bucket, false)),
            );
        }

        return $svg . '</svg>';
    }

    /**
     * @param array<string, list<int>> $series
     * @param array<string, string>    $labels
     * @param array<string, string>    $colors
     */
    public static function legend(array $series, array $labels, array $colors): string
    {
        $html = '<div class="legend">';

        foreach ($labels as $type => $label) {
            $total = array_sum($series[$type] ?? []);

            $html .= sprintf(
                '<span class="legend__item"><span class="legend__swatch" style="background:var(%s)"></span>'
                . '%s <span class="legend__value">%s</span></span>',
                $colors[$type],
                View::e($label),
                View::e(View::number($total)),
            );
        }

        return $html . '</div>';
    }

    private static function rectPath(float $x, float $y, float $w, float $h): string
    {
        return sprintf(
            'M%s %sh%sv%sh-%sZ',
            self::fmt($x), self::fmt($y), self::fmt($w), self::fmt($h), self::fmt($w),
        );
    }

    /** Rounded top corners only; the bar stays anchored to the baseline. */
    private static function roundedTopPath(float $x, float $y, float $w, float $h): string
    {
        $r = min(self::CORNER, $w / 2, $h);

        return sprintf(
            'M%s %sv-%sa%s %s 0 0 1 %s -%sh%sa%s %s 0 0 1 %s %sv%sZ',
            self::fmt($x), self::fmt($y + $h),
            self::fmt($h - $r),
            self::fmt($r), self::fmt($r), self::fmt($r), self::fmt($r),
            self::fmt($w - 2 * $r),
            self::fmt($r), self::fmt($r), self::fmt($r), self::fmt($r),
            self::fmt($h - $r),
        );
    }

    private static function niceCeiling(int $max): int
    {
        if ($max <= 0) {
            return 1;
        }

        $magnitude = 10 ** max(0, (int) floor(log10($max)) );

        foreach ([1, 2, 2.5, 5, 10] as $step) {
            $candidate = (int) ceil($max / ($magnitude * $step)) * (int) ($magnitude * $step);
            if ($candidate >= $max && $candidate > 0) {
                return $candidate;
            }
        }

        return $max;
    }

    private static function bucketLabel(string $bucket, bool $withDate): string
    {
        $time = substr($bucket, 11, 5);
        $date = substr($bucket, 8, 2) . '.' . substr($bucket, 5, 2) . '.';

        return $withDate ? "{$date} {$time}" : $time;
    }

    private static function fmt(float $value): string
    {
        return rtrim(rtrim(number_format($value, 2, '.', ''), '0'), '.');
    }
}
