<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Search\EventStats;
use LogWarden\Web\Response;
use LogWarden\Web\View;

final class DashboardController
{
    /** Fixed assignment: a source keeps its colour however the filters change. */
    private const SERIES_COLORS = [
        'ad'             => '--series-1',
        'dns'            => '--series-2',
        'dhcp'           => '--series-3',
        'fortigate_vpn'  => '--series-4',
        'fortigate_auth' => '--series-5',
    ];

    public function __construct(
        private readonly EventStats $stats,
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
            'volume'       => $volume,
            'labels'       => EventStats::sourceLabels(),
            'colors'       => self::SERIES_COLORS,
            'topFailing'   => $this->stats->topFailingUsers($hours),
            'recent'       => $this->stats->recentEvents(),
            'ingestHealth' => $this->stats->ingestHealth(),
        ]));
    }
}
