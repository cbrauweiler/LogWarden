<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Web\Branding;
use LogWarden\Web\Color;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\View;

/**
 * Corporate identity settings: colours, logos, typography and shape.
 */
final class BrandingController
{
    public function __construct(
        private readonly Branding $branding,
        private readonly View $view,
        private readonly string $actor,
    ) {
    }

    public function show(array $flash = [], array $errors = []): Response
    {
        $current = $this->branding->load();

        return Response::html($this->view->page('admin/branding', [
            'title'     => 'Corporate Identity',
            'active'    => 'branding',
            'branding'  => $current,
            'tokens'    => $this->branding->tokens($current),
            'contrast'  => $this->contrastReport($current),
            'assets'    => $this->branding->assetIndex(),
            'fonts'     => Branding::FONT_STACKS,
            'radii'     => Branding::RADIUS_SCALES,
            'densities' => Branding::DENSITIES,
            'flash'     => $flash,
            'errors'    => $errors,
        ]));
    }

    public function save(): Response
    {
        if (!Csrf::check($_POST['_csrf'] ?? null)) {
            return $this->show([], ['Sicherheits-Token abgelaufen. Bitte erneut absenden.']);
        }

        if (isset($_POST['reset_colors'])) {
            $_POST['color_primary'] = Branding::DEFAULTS['color_primary'];
            $_POST['color_accent']  = Branding::DEFAULTS['color_accent'];
            $_POST['color_sidebar'] = Branding::DEFAULTS['color_sidebar'];
        }

        $errors = $this->branding->save($_POST, $this->actor);

        foreach (Branding::ASSET_SLOTS as $slot) {
            if (isset($_POST['delete_' . $slot])) {
                $this->branding->deleteAsset($slot, $this->actor);
                continue;
            }

            if (isset($_FILES[$slot]) && is_array($_FILES[$slot])) {
                $errors = array_merge($errors, $this->branding->putAsset($slot, $_FILES[$slot], $this->actor));
            }
        }

        if ($errors !== []) {
            return $this->show([], $errors);
        }

        // Redirect after POST so a refresh does not re-submit the form.
        return Response::redirect('/settings/branding?saved=1');
    }

    /**
     * Shown next to the colour pickers. A brand colour is chosen for a logo,
     * not for a button label, so the person picking it needs to be told when
     * the result is going to be hard to read.
     *
     * @return list<array{label:string, ratio:float, level:string, note:string}>
     */
    private function contrastReport(array $branding): array
    {
        $tokens = $this->branding->tokens($branding);

        $button  = Color::rate($tokens['brand_ink'], $tokens['brand']);
        $link    = Color::rate($tokens['brand_text'], '#fcfcfb');
        $sidebar = Color::rate($tokens['sidebar_ink'], $tokens['sidebar']);

        $adjusted = strcasecmp($tokens['brand_text'], $tokens['brand']) !== 0;

        return [
            [
                'label' => 'Button-Text auf Primärfarbe',
                'ratio' => $button['ratio'],
                'level' => $button['level'],
                'note'  => 'Schriftfarbe automatisch gewählt: ' . $tokens['brand_ink'],
            ],
            [
                'label' => 'Link-/Aktivfarbe auf hellem Hintergrund',
                'ratio' => $link['ratio'],
                'level' => $link['level'],
                'note'  => $adjusted
                    ? 'Für Fließtext auf ' . $tokens['brand_text'] . ' abgedunkelt; Flächen nutzen weiter die Originalfarbe.'
                    : 'Originalfarbe erfüllt AA und wird unverändert verwendet.',
            ],
            [
                'label' => 'Navigationstext auf Navigationsfarbe',
                'ratio' => $sidebar['ratio'],
                'level' => $sidebar['level'],
                'note'  => 'Schriftfarbe automatisch gewählt: ' . $tokens['sidebar_ink'],
            ],
        ];
    }
}
