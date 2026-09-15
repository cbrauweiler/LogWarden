<?php

declare(strict_types=1);

namespace LogWarden\Web;

use LogWarden\Core\Db;
use RuntimeException;

/**
 * Corporate identity: reads and writes the branding row and turns it into the
 * small stylesheet that overrides the design system's brand tokens.
 *
 * Only chrome is themeable. Status colours (alert severity) and the categorical
 * series colours are fixed in app.css: they encode meaning and are validated as
 * an ordered set for colour-vision deficiency, so letting them be re-picked
 * would trade a readable console for a matching one.
 */
final class Branding
{
    public const DEFAULTS = [
        'product_name'     => 'LogWarden',
        'org_name'         => null,
        'login_subtitle'   => null,
        'footer_text'      => null,
        'color_primary'    => '#3d63dd',
        'color_accent'     => '#0d9488',
        'color_sidebar'    => '#0f172a',
        'font_stack'       => 'system',
        'radius_scale'     => 'medium',
        'density'          => 'comfortable',
        'default_theme'    => 'auto',
        'allow_user_theme' => true,
        'revision'         => 1,
    ];

    /**
     * Self-hostable stacks only — LogWarden must not reach out to a font CDN
     * from an air-gapped SOC network.
     */
    public const FONT_STACKS = [
        'system'    => ['label' => 'System (empfohlen)', 'stack' => 'system-ui, -apple-system, "Segoe UI", sans-serif'],
        'segoe'     => ['label' => 'Segoe UI',            'stack' => '"Segoe UI", system-ui, sans-serif'],
        'helvetica' => ['label' => 'Helvetica / Arial',   'stack' => '"Helvetica Neue", Helvetica, Arial, sans-serif'],
        'verdana'   => ['label' => 'Verdana (gut lesbar)', 'stack' => 'Verdana, Geneva, system-ui, sans-serif'],
    ];

    public const RADIUS_SCALES = [
        'sharp'  => ['label' => 'Kantig', 'sm' => '2px', 'md' => '3px',  'lg' => '4px'],
        'medium' => ['label' => 'Weich',  'sm' => '5px', 'md' => '9px',  'lg' => '14px'],
        'round'  => ['label' => 'Rund',   'sm' => '8px', 'md' => '14px', 'lg' => '22px'],
    ];

    public const DENSITIES = [
        'compact'     => ['label' => 'Kompakt',   'row' => '0.35rem', 'card' => '1rem'],
        'comfortable' => ['label' => 'Normal',    'row' => '0.6rem',  'card' => '1.25rem'],
    ];

    public const ASSET_SLOTS = ['logo_light', 'logo_dark', 'logo_mark', 'favicon'];

    private const MAX_ASSET_BYTES = 2 * 1024 * 1024;

    private const ALLOWED_MIME = [
        'image/svg+xml' => 'svg',
        'image/png'     => 'png',
        'image/jpeg'    => 'jpg',
        'image/webp'    => 'webp',
        'image/x-icon'  => 'ico',
    ];

    /** @var array<string, mixed>|null */
    private ?array $cache = null;

    public function __construct(private readonly Db $db)
    {
    }

    /** @return array<string, mixed> */
    public function load(): array
    {
        if ($this->cache !== null) {
            return $this->cache;
        }

        $row = $this->db->fetchRow('SELECT * FROM branding WHERE id = 1');

        // A missing row must not take the whole UI down; the defaults are a
        // perfectly usable theme.
        $row ??= self::DEFAULTS;
        $row['allow_user_theme'] = filter_var($row['allow_user_theme'] ?? true, FILTER_VALIDATE_BOOL);

        return $this->cache = $row + self::DEFAULTS;
    }

    /**
     * @param array<string, mixed> $input
     * @return list<string> validation errors; empty means saved
     */
    public function save(array $input, string $actor): array
    {
        $errors  = [];
        $current = $this->load();

        $name = trim((string) ($input['product_name'] ?? ''));
        if ($name === '') {
            $errors[] = 'Produktname darf nicht leer sein.';
        } elseif (mb_strlen($name) > 60) {
            $errors[] = 'Produktname ist auf 60 Zeichen begrenzt.';
        }

        $colors = [];
        foreach (['color_primary' => 'Primärfarbe', 'color_accent' => 'Akzentfarbe', 'color_sidebar' => 'Navigationsfarbe'] as $key => $label) {
            $value = trim((string) ($input[$key] ?? ''));
            if (!Color::isValid($value)) {
                $errors[] = "{$label}: '{$value}' ist kein gültiger Hex-Farbwert (z. B. #3d63dd).";
                continue;
            }
            $colors[$key] = Color::normalize($value, (string) $current[$key]);
        }

        $font    = (string) ($input['font_stack'] ?? 'system');
        $radius  = (string) ($input['radius_scale'] ?? 'medium');
        $density = (string) ($input['density'] ?? 'comfortable');
        $theme   = (string) ($input['default_theme'] ?? 'auto');

        if (!isset(self::FONT_STACKS[$font]))       { $errors[] = 'Unbekannte Schriftart gewählt.'; }
        if (!isset(self::RADIUS_SCALES[$radius]))   { $errors[] = 'Unbekannte Eckenform gewählt.'; }
        if (!isset(self::DENSITIES[$density]))      { $errors[] = 'Unbekannte Dichte gewählt.'; }
        if (!in_array($theme, ['auto', 'light', 'dark'], true)) { $errors[] = 'Unbekannter Standard-Modus gewählt.'; }

        if ($errors !== []) {
            return $errors;
        }

        $this->db->execute(
            'UPDATE branding SET
                product_name     = ?,
                org_name         = ?,
                login_subtitle   = ?,
                footer_text      = ?,
                color_primary    = ?,
                color_accent     = ?,
                color_sidebar    = ?,
                font_stack       = ?,
                radius_scale     = ?,
                density          = ?,
                default_theme    = ?,
                allow_user_theme = ?,
                revision         = revision + 1,
                updated_at       = now(),
                updated_by       = ?
             WHERE id = 1',
            [
                $name,
                self::nullIfBlank($input['org_name'] ?? null),
                self::nullIfBlank($input['login_subtitle'] ?? null),
                self::nullIfBlank($input['footer_text'] ?? null),
                $colors['color_primary'],
                $colors['color_accent'],
                $colors['color_sidebar'],
                $font,
                $radius,
                $density,
                $theme,
                !empty($input['allow_user_theme']) ? 'true' : 'false',
                $actor,
            ],
        );

        $this->audit($actor, 'branding.update', ['colors' => $colors, 'font' => $font, 'theme' => $theme]);
        $this->cache = null;

        return [];
    }

    // -----------------------------------------------------------------------
    // Theme stylesheet
    // -----------------------------------------------------------------------

    /**
     * Derived tokens for a given brand colour.
     *
     * @return array<string, string>
     */
    public function tokens(?array $branding = null): array
    {
        $branding ??= $this->load();

        $brand   = Color::normalize((string) $branding['color_primary'], self::DEFAULTS['color_primary']);
        $accent  = Color::normalize((string) $branding['color_accent'],  self::DEFAULTS['color_accent']);
        $sidebar = Color::normalize((string) $branding['color_sidebar'], self::DEFAULTS['color_sidebar']);

        return [
            'brand'           => $brand,
            // Button label colour follows the brand's luminance, so a pale
            // brand gets dark text instead of invisible white.
            'brand_ink'       => Color::inkOn($brand),
            // As link/active text the brand has to clear 4.5:1 against the page
            // surface; step it until it does rather than shipping grey-on-grey.
            'brand_text'      => Color::readableOn($brand, '#fcfcfb'),
            'brand_text_dark' => Color::readableOn($brand, '#1a1a19'),
            'brand_hover'     => Color::mix($brand, Color::luminance($brand) > 0.5 ? '#000000' : '#ffffff', 0.12),
            'brand_subtle'    => Color::mix($brand, '#ffffff', 0.90),
            'brand_subtle_dark' => Color::mix($brand, '#1a1a19', 0.82),
            'accent'          => $accent,
            'sidebar'         => $sidebar,
            'sidebar_ink'     => Color::inkOn($sidebar),
        ];
    }

    public function themeCss(): string
    {
        $branding = $this->load();
        $t        = $this->tokens($branding);

        $font    = self::FONT_STACKS[$branding['font_stack']] ?? self::FONT_STACKS['system'];
        $radius  = self::RADIUS_SCALES[$branding['radius_scale']] ?? self::RADIUS_SCALES['medium'];
        $density = self::DENSITIES[$branding['density']] ?? self::DENSITIES['comfortable'];

        [$r, $g, $b] = Color::parse($t['brand']) ?? [61, 99, 221];

        return <<<CSS
        /* Generated from the branding settings — do not edit by hand.
           Revision {$branding['revision']}. */
        :root {
            --brand:        {$t['brand']};
            --brand-ink:    {$t['brand_ink']};
            --brand-text:   {$t['brand_text']};
            --brand-hover:  {$t['brand_hover']};
            --brand-subtle: {$t['brand_subtle']};
            --brand-ring:   rgba({$r}, {$g}, {$b}, 0.35);
            --accent:       {$t['accent']};
            --sidebar:      {$t['sidebar']};
            --sidebar-ink:  {$t['sidebar_ink']};

            --font-ui: {$font['stack']};

            --radius-sm: {$radius['sm']};
            --radius-md: {$radius['md']};
            --radius-lg: {$radius['lg']};

            --row-pad:  {$density['row']};
            --card-pad: {$density['card']};
        }

        /* The brand as link text needs a different step on the dark surface. */
        @media (prefers-color-scheme: dark) {
            :root:where(:not([data-theme="light"])) {
                --brand-text:   {$t['brand_text_dark']};
                --brand-subtle: {$t['brand_subtle_dark']};
            }
        }
        :root[data-theme="dark"] {
            --brand-text:   {$t['brand_text_dark']};
            --brand-subtle: {$t['brand_subtle_dark']};
        }
        CSS;
    }

    // -----------------------------------------------------------------------
    // Assets
    // -----------------------------------------------------------------------

    /** @return array{mime_type:string, data:string, checksum:string}|null */
    public function asset(string $slot): ?array
    {
        if (!in_array($slot, self::ASSET_SLOTS, true)) {
            return null;
        }

        $row = $this->db->fetchRow(
            'SELECT mime_type, checksum, data FROM branding_assets WHERE slot = ?',
            [$slot],
        );

        if ($row === null) {
            return null;
        }

        return [
            'mime_type' => (string) $row['mime_type'],
            'checksum'  => (string) $row['checksum'],
            'data'      => self::toBinary($row['data']),
        ];
    }

    /** @return array<string, array{mime_type:string, byte_size:int, checksum:string}> */
    public function assetIndex(): array
    {
        $index = [];

        foreach ($this->db->fetchAll('SELECT slot, mime_type, byte_size, checksum FROM branding_assets') as $row) {
            $index[(string) $row['slot']] = [
                'mime_type' => (string) $row['mime_type'],
                'byte_size' => (int) $row['byte_size'],
                'checksum'  => (string) $row['checksum'],
            ];
        }

        return $index;
    }

    /**
     * @param array{tmp_name?:string, size?:int, error?:int, name?:string} $upload
     * @return list<string> validation errors; empty means stored
     */
    public function putAsset(string $slot, array $upload, string $actor): array
    {
        if (!in_array($slot, self::ASSET_SLOTS, true)) {
            return ['Unbekannter Logo-Platz.'];
        }

        $error = $upload['error'] ?? UPLOAD_ERR_NO_FILE;
        if ($error === UPLOAD_ERR_NO_FILE) {
            return [];   // nothing selected for this slot, not an error
        }
        if ($error !== UPLOAD_ERR_OK) {
            return ['Upload fehlgeschlagen (PHP-Fehlercode ' . $error . ').'];
        }

        $tmp = (string) ($upload['tmp_name'] ?? '');
        if ($tmp === '' || !is_uploaded_file($tmp)) {
            return ['Upload konnte nicht gelesen werden.'];
        }

        $size = (int) ($upload['size'] ?? 0);
        if ($size <= 0 || $size > self::MAX_ASSET_BYTES) {
            return ['Datei ist leer oder größer als 2 MB.'];
        }

        $data = (string) file_get_contents($tmp);
        $mime = self::detectMime($data);

        if ($mime === null) {
            return ['Nur SVG, PNG, JPEG, WebP und ICO werden akzeptiert.'];
        }

        // An SVG is a document, not a picture: it can carry script and external
        // references, and it renders in the browser's own origin. Reject the
        // dangerous constructs rather than hoping the CSP catches them.
        if ($mime === 'image/svg+xml') {
            $svgErrors = self::inspectSvg($data);
            if ($svgErrors !== []) {
                return $svgErrors;
            }
        }

        $this->db->execute(
            'INSERT INTO branding_assets (slot, mime_type, byte_size, checksum, data, updated_at)
             VALUES (?, ?, ?, ?, ?, now())
             ON CONFLICT (slot) DO UPDATE
                SET mime_type = EXCLUDED.mime_type,
                    byte_size = EXCLUDED.byte_size,
                    checksum  = EXCLUDED.checksum,
                    data      = EXCLUDED.data,
                    updated_at = now()',
            [$slot, $mime, strlen($data), hash('sha256', $data), $data],
        );

        $this->bumpRevision();
        $this->audit($actor, 'branding.asset.upload', ['slot' => $slot, 'mime' => $mime, 'bytes' => strlen($data)]);

        return [];
    }

    public function deleteAsset(string $slot, string $actor): void
    {
        if (!in_array($slot, self::ASSET_SLOTS, true)) {
            return;
        }

        $this->db->execute('DELETE FROM branding_assets WHERE slot = ?', [$slot]);
        $this->bumpRevision();
        $this->audit($actor, 'branding.asset.delete', ['slot' => $slot]);
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private function bumpRevision(): void
    {
        $this->db->execute('UPDATE branding SET revision = revision + 1, updated_at = now() WHERE id = 1');
        $this->cache = null;
    }

    private function audit(string $actor, string $action, array $details): void
    {
        $this->db->execute(
            'INSERT INTO audit_log (user_id, username, action, target, details)
             VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?, ?)',
            [$actor, $actor, $action, 'branding', json_encode($details, JSON_UNESCAPED_UNICODE)],
        );
    }

    private static function detectMime(string $data): ?string
    {
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mime  = $finfo->buffer($data) ?: '';

        // finfo reports SVG as text/xml or image/svg+xml depending on build.
        if (in_array($mime, ['text/xml', 'application/xml', 'text/plain'], true)
            && preg_match('/<svg[\s>]/i', substr($data, 0, 2048)) === 1
        ) {
            $mime = 'image/svg+xml';
        }

        return isset(self::ALLOWED_MIME[$mime]) ? $mime : null;
    }

    /** @return list<string> */
    private static function inspectSvg(string $data): array
    {
        $errors = [];

        if (preg_match('/<script[\s>]/i', $data) === 1) {
            $errors[] = 'SVG enthält <script> und wurde abgelehnt.';
        }
        if (preg_match('/\son[a-z]+\s*=/i', $data) === 1) {
            $errors[] = 'SVG enthält Event-Handler-Attribute (onload, onclick …) und wurde abgelehnt.';
        }
        if (preg_match('/<(foreignObject|iframe|embed|object)[\s>]/i', $data) === 1) {
            $errors[] = 'SVG enthält eingebettete Fremdinhalte und wurde abgelehnt.';
        }
        if (preg_match('/<!(DOCTYPE|ENTITY)/i', $data) === 1) {
            $errors[] = 'SVG enthält eine DTD bzw. Entities (XXE-Risiko) und wurde abgelehnt.';
        }
        if (preg_match('/(href|xlink:href)\s*=\s*["\']\s*(?!#|data:image\/)/i', $data) === 1) {
            $errors[] = 'SVG verweist auf externe Ressourcen und wurde abgelehnt.';
        }

        return $errors;
    }

    private static function nullIfBlank(mixed $value): ?string
    {
        $value = trim((string) $value);

        return $value === '' ? null : mb_substr($value, 0, 200);
    }

    private static function toBinary(mixed $value): string
    {
        if (is_resource($value)) {
            return (string) stream_get_contents($value);
        }

        $value = (string) $value;

        if (str_starts_with($value, '\\x')) {
            $decoded = hex2bin(substr($value, 2));
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return $value;
    }
}
