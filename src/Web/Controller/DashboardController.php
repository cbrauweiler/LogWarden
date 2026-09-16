<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Alerting\AlertQuery;
use LogWarden\Search\EventStats;
use LogWarden\Event\SourceType;
use LogWarden\Web\Response;
use LogWarden\Web\View;

final class DashboardController
{
    public function __construct(
        private readonly EventStats $stats,
        private readonly AlertQuery $alerts,
        private readonly View $view,
    ) {
    }

    public function show(): Response
    {
        $hours  = (int) ($_GET['hours'] ?? 24);
        $hours  = in_array($hours, [6, 24, 72, 168], true) ? $hours : 24;
        $bucket = $hours > 48 ? '6 hours' : '1 hour';

        $volume = $this->stats->volume($hours, $bucket);

        return Response::html($this->view->page('dashboard', [
            'title'        => 'Dashboard',
            'active'       => 'dashboard',
            'hours'        => $hours,
            'headline'     => $this->stats->headline($hours),
            'alertCounters' => $this->alerts->counters(),
            'openAlerts'    => $this->alerts->list(['status' => 'new', 'limit' => 5]),
            'volume'       => $volume,
            'labels'       => EventStats::sourceLabels(),
            // From the registry, not a constant: a plugin declares its own
            // colour, and a source keeps it however the filters change.
            'colors'       => SourceType::colors(),
            'topFailing'   => $this->stats->topFailingUsers($hours),
            'recent'       => $this->stats->recentEvents(),
            'ingestHealth' => $this->stats->ingestHealth(),
        ]));
    }
}
