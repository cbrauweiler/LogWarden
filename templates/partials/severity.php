<?php
/**
 * Severity badge. Colour, icon and word together — a status colour never
 * carries the meaning on its own.
 *
 * @var int $severity
 */

use LogWarden\Alerting\AlertQuery;
use LogWarden\Web\View;

$class = AlertQuery::severityClass($severity);
$label = AlertQuery::SEVERITY_LABELS[$severity] ?? (string) $severity;

$icon = match ($class) {
    'critical' => '<path d="M12 8v5M12 16h.01"/><path d="M10.3 3.9 2.4 17.5A1.9 1.9 0 0 0 4 20.4h16a1.9 1.9 0 0 0 1.6-2.9L13.7 3.9a1.9 1.9 0 0 0-3.4 0z"/>',
    'serious'  => '<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>',
    'warning'  => '<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>',
    default    => '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
};
?>
<span class="sev sev--<?= View::e($class) ?>">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><?= $icon ?></svg>
    <?= View::e($label) ?>
</span>
