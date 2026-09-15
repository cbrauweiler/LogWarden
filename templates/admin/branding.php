<?php
/**
 * Corporate identity settings.
 *
 * @var array $branding
 * @var array $tokens
 * @var array $contrast
 * @var array $assets
 * @var array $fonts
 * @var array $radii
 * @var array $densities
 * @var array $flash
 * @var array $errors
 */

use LogWarden\Web\Csrf;
use LogWarden\Web\View;

$e = static fn (mixed $v): string => View::e($v);

$slots = [
    'logo_light' => ['label' => 'Logo (helle Navigation)', 'hint' => 'Wird in der Seitenleiste gezeigt. SVG empfohlen, max. 2 MB.', 'dark' => true],
    'logo_dark'  => ['label' => 'Logo (heller Hintergrund)', 'hint' => 'Für Login-Seite und Druckansicht.', 'dark' => false],
    'logo_mark'  => ['label' => 'Bildmarke (quadratisch)', 'hint' => 'Kompakte Variante, z. B. für Teams-Karten.', 'dark' => false],
    'favicon'    => ['label' => 'Favicon', 'hint' => 'ICO oder PNG, 32×32 oder 64×64.', 'dark' => false],
];
?>

<?php foreach ($flash as $message): ?>
    <div class="notice notice--ok" role="status">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 12 5 5L20 6"/></svg>
        <div><?= $e($message) ?></div>
    </div>
<?php endforeach; ?>

<?php if ($errors !== []): ?>
    <div class="notice notice--critical" role="alert">
        <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
             stroke-linecap="round" aria-hidden="true"><path d="M12 8v5M12 16h.01"/><circle cx="12" cy="12" r="9"/></svg>
        <div>
            <strong>Nicht gespeichert:</strong>
            <ul style="margin:0.3rem 0 0; padding-left:1.1rem">
                <?php foreach ($errors as $error): ?><li><?= $e($error) ?></li><?php endforeach; ?>
            </ul>
        </div>
    </div>
<?php endif; ?>

<form method="post" action="/settings/branding" enctype="multipart/form-data" class="stack" data-branding-form>
    <?= Csrf::field() ?>

    <section class="card">
        <div class="card__head">
            <div>
                <h2>Identität</h2>
                <p class="card__hint">Name und Beschriftungen, die im gesamten Frontend erscheinen.</p>
            </div>
        </div>
        <div class="card__body">
            <div class="grid-2">
                <div class="field">
                    <label class="field__label" for="product_name">Produktname</label>
                    <input class="input" id="product_name" name="product_name" maxlength="60" required
                           value="<?= $e($branding['product_name']) ?>" data-preview-name>
                    <span class="field__hint">Erscheint in der Seitenleiste und im Browser-Titel.</span>
                </div>
                <div class="field">
                    <label class="field__label" for="org_name">Organisation</label>
                    <input class="input" id="org_name" name="org_name" maxlength="200"
                           value="<?= $e($branding['org_name'] ?? '') ?>"
                           placeholder="z. B. Muster GmbH">
                    <span class="field__hint">Optionale Unterzeile unter dem Produktnamen.</span>
                </div>
                <div class="field">
                    <label class="field__label" for="login_subtitle">Untertitel auf der Login-Seite</label>
                    <input class="input" id="login_subtitle" name="login_subtitle" maxlength="200"
                           value="<?= $e($branding['login_subtitle'] ?? '') ?>"
                           placeholder="Anmeldung mit Ihrem Windows-Konto">
                </div>
                <div class="field">
                    <label class="field__label" for="footer_text">Fußzeile in der Seitenleiste</label>
                    <input class="input" id="footer_text" name="footer_text" maxlength="200"
                           value="<?= $e($branding['footer_text'] ?? '') ?>"
                           placeholder="IT-Security · interne Nutzung">
                </div>
            </div>
        </div>
    </section>

    <section class="card">
        <div class="card__head">
            <div>
                <h2>Farben</h2>
                <p class="card__hint">
                    Steuern die Chrome-Elemente: Navigation, Buttons, Links, Fokusrahmen.
                </p>
            </div>
            <button class="btn btn--ghost" type="submit" name="reset_colors" value="1">Auf Standard zurücksetzen</button>
        </div>
        <div class="card__body">
            <div class="colorlayout">
                <div class="grid-3">
                    <div class="field">
                        <label class="field__label" for="color_primary">Primärfarbe</label>
                        <div class="colorfield">
                            <input type="color" id="color_primary_swatch" value="<?= $e($branding['color_primary']) ?>"
                                   data-sync="color_primary" aria-label="Primärfarbe wählen">
                            <input class="input" id="color_primary" name="color_primary" maxlength="7" required
                                   pattern="#[0-9a-fA-F]{6}" value="<?= $e($branding['color_primary']) ?>"
                                   data-preview-brand>
                        </div>
                        <span class="field__hint">Buttons, aktive Navigation, Fokusrahmen.</span>
                    </div>
                    <div class="field">
                        <label class="field__label" for="color_sidebar">Navigationsfarbe</label>
                        <div class="colorfield">
                            <input type="color" id="color_sidebar_swatch" value="<?= $e($branding['color_sidebar']) ?>"
                                   data-sync="color_sidebar" aria-label="Navigationsfarbe wählen">
                            <input class="input" id="color_sidebar" name="color_sidebar" maxlength="7" required
                                   pattern="#[0-9a-fA-F]{6}" value="<?= $e($branding['color_sidebar']) ?>"
                                   data-preview-sidebar>
                        </div>
                        <span class="field__hint">Hintergrund der linken Seitenleiste.</span>
                    </div>
                    <div class="field">
                        <label class="field__label" for="color_accent">Akzentfarbe</label>
                        <div class="colorfield">
                            <input type="color" id="color_accent_swatch" value="<?= $e($branding['color_accent']) ?>"
                                   data-sync="color_accent" aria-label="Akzentfarbe wählen">
                            <input class="input" id="color_accent" name="color_accent" maxlength="7" required
                                   pattern="#[0-9a-fA-F]{6}" value="<?= $e($branding['color_accent']) ?>">
                        </div>
                        <span class="field__hint">Sekundäre Hervorhebungen.</span>
                    </div>

                    <div class="field" style="grid-column: 1 / -1; margin-bottom: 0">
                        <span class="field__label">Kontrastprüfung</span>
                        <dl class="contrast-readout">
                            <?php foreach ($contrast as $check): ?>
                                <div>
                                    <dt><?= $e($check['label']) ?></dt>
                                    <dd class="<?= $check['level'] === 'fail' ? 'is-fail' : 'is-pass' ?>">
                                        <?= $e(number_format($check['ratio'], 2, ',', '.')) ?>:1
                                        · <?= $e($check['level'] === 'fail' ? 'unzureichend' : $check['level']) ?>
                                    </dd>
                                    <dd class="muted" style="font-weight:400"><?= $e($check['note']) ?></dd>
                                </div>
                            <?php endforeach; ?>
                        </dl>
                    </div>
                </div>

                <div class="field" style="margin-bottom:0">
                    <span class="field__label">Vorschau</span>
                    <div class="preview" data-preview
                         style="--preview-brand: <?= $e($tokens['brand']) ?>;
                                --preview-brand-ink: <?= $e($tokens['brand_ink']) ?>;
                                --preview-brand-text: <?= $e($tokens['brand_text']) ?>;
                                --preview-sidebar: <?= $e($tokens['sidebar']) ?>;">
                        <div class="preview__bar">
                            <span class="preview__mark" data-preview-mark><?= $e(mb_strtoupper(mb_substr($branding['product_name'], 0, 2))) ?></span>
                            <span data-preview-title><?= $e($branding['product_name']) ?></span>
                        </div>
                        <div class="preview__body">
                            <span class="preview__btn">Alert quittieren</span>
                            <a class="preview__link" href="#" onclick="return false">Zur Detailansicht</a>
                        </div>
                    </div>
                    <span class="field__hint">Aktualisiert sich live beim Ändern der Farben.</span>
                </div>
            </div>

            <div class="notice" style="margin-top:0.5rem">
                <svg class="notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
                     stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>
                <div>
                    <strong>Nicht anpassbar:</strong> Schweregrad-Farben von Alerts und die Farbskala der
                    Diagramme. Beide kodieren Bedeutung und sind als Satz auf Farbfehlsichtigkeit geprüft —
                    frei wählbar würden sie aus einer lesbaren Konsole eine passende machen.
                </div>
            </div>
        </div>

    </section>

    <section class="card">
        <div class="card__head">
            <div>
                <h2>Logos</h2>
                <p class="card__hint">SVG, PNG, JPEG, WebP oder ICO, jeweils bis 2 MB.</p>
            </div>
        </div>
        <div class="card__body">
            <div class="logoslots">
                <?php foreach ($slots as $slot => $meta): ?>
                    <div class="logoslot">
                        <span class="logoslot__name"><?= $e($meta['label']) ?></span>
                        <div class="logoslot__preview <?= $meta['dark'] ? 'logoslot__preview--dark' : '' ?>">
                            <?php if (isset($assets[$slot])): ?>
                                <img src="/branding/logo?slot=<?= $e($slot) ?>&amp;v=<?= $e($branding['revision']) ?>"
                                     alt="<?= $e($meta['label']) ?>">
                            <?php else: ?>
                                <span>kein Logo hinterlegt</span>
                            <?php endif; ?>
                        </div>
                        <label class="visually-hidden" for="file_<?= $e($slot) ?>"><?= $e($meta['label']) ?> hochladen</label>
                        <input type="file" id="file_<?= $e($slot) ?>" name="<?= $e($slot) ?>"
                               accept="image/svg+xml,image/png,image/jpeg,image/webp,image/x-icon">
                        <span class="field__hint"><?= $e($meta['hint']) ?></span>
                        <?php if (isset($assets[$slot])): ?>
                            <button class="btn btn--danger" type="submit"
                                    name="delete_<?= $e($slot) ?>" value="1">Entfernen</button>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </section>

    <section class="card">
        <div class="card__head">
            <div>
                <h2>Typografie und Darstellung</h2>
                <p class="card__hint">
                    Nur lokal verfügbare Schriftfamilien — LogWarden lädt keine Web-Fonts nach.
                </p>
            </div>
        </div>
        <div class="card__body">
            <div class="grid-2">
                <div class="field">
                    <label class="field__label" for="font_stack">Schriftfamilie</label>
                    <select class="select" id="font_stack" name="font_stack">
                        <?php foreach ($fonts as $key => $font): ?>
                            <option value="<?= $e($key) ?>" <?= $branding['font_stack'] === $key ? 'selected' : '' ?>>
                                <?= $e($font['label']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="field">
                    <label class="field__label" for="radius_scale">Eckenform</label>
                    <select class="select" id="radius_scale" name="radius_scale">
                        <?php foreach ($radii as $key => $radius): ?>
                            <option value="<?= $e($key) ?>" <?= $branding['radius_scale'] === $key ? 'selected' : '' ?>>
                                <?= $e($radius['label']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="field">
                    <label class="field__label" for="density">Informationsdichte</label>
                    <select class="select" id="density" name="density">
                        <?php foreach ($densities as $key => $density): ?>
                            <option value="<?= $e($key) ?>" <?= $branding['density'] === $key ? 'selected' : '' ?>>
                                <?= $e($density['label']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <span class="field__hint">Kompakt zeigt mehr Tabellenzeilen pro Bildschirm.</span>
                </div>
                <div class="field">
                    <label class="field__label" for="default_theme">Standard-Modus</label>
                    <select class="select" id="default_theme" name="default_theme">
                        <option value="auto"  <?= $branding['default_theme'] === 'auto'  ? 'selected' : '' ?>>Systemeinstellung folgen</option>
                        <option value="light" <?= $branding['default_theme'] === 'light' ? 'selected' : '' ?>>Immer hell</option>
                        <option value="dark"  <?= $branding['default_theme'] === 'dark'  ? 'selected' : '' ?>>Immer dunkel</option>
                    </select>
                </div>
            </div>

            <label class="row" style="gap:0.5rem; cursor:pointer">
                <input type="checkbox" name="allow_user_theme" value="1"
                       <?= !empty($branding['allow_user_theme']) ? 'checked' : '' ?>>
                <span>Benutzer dürfen zwischen hell und dunkel umschalten</span>
            </label>
        </div>

        <div class="actions">
            <button class="btn btn--primary" type="submit">Speichern</button>
            <a class="btn btn--ghost" href="/settings/branding">Verwerfen</a>
            <span class="muted" style="margin-left:auto">
                Revision <?= $e($branding['revision']) ?><?php if (!empty($branding['updated_by'])): ?>
                    · zuletzt geändert von <?= $e($branding['updated_by']) ?>
                <?php endif; ?>
            </span>
        </div>
    </section>
</form>
