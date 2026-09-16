<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Alerting\AlertQuery;
use LogWarden\Alerting\AlertRepository;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\View;

final class AlertController
{
    public function __construct(
        private readonly AlertQuery $query,
        private readonly AlertRepository $alerts,
        private readonly View $view,
        private readonly string $actor,
    ) {
    }

    public function index(): Response
    {
        $status = (string) ($_GET['status'] ?? 'new');
        if (!in_array($status, ['new', 'ack', 'closed', 'all'], true)) {
            $status = 'new';
        }

        $severity = (int) ($_GET['severity'] ?? 0);
        $search   = trim((string) ($_GET['q'] ?? ''));

        return Response::html($this->view->page('alerts', [
            'title'    => 'Alerts',
            'active'   => 'alerts',
            'status'   => $status,
            'severity' => $severity,
            'search'   => $search,
            'counters' => $this->query->counters(),
            'alerts'   => $this->query->list([
                'status'   => $status,
                'severity' => $severity,
                'q'        => $search === '' ? null : $search,
            ]),
            'rules' => $this->query->rules(),
            'flash' => isset($_GET['acked']) ? ['Alert quittiert.'] : [],
        ]));
    }

    public function show(): Response
    {
        $id    = (int) ($_GET['id'] ?? 0);
        $alert = $id > 0 ? $this->query->find($id) : null;

        if ($alert === null) {
            return Response::notFound('Alert not found');
        }

        $events = $this->query->events($id);

        return Response::html($this->view->page('alert', [
            'title'  => 'Alert #' . $id,
            'active' => 'alerts',
            'alert'  => $alert,
            'events' => $events,
            // An alert older than its source events is expected once retention
            // has run; saying so beats an unexplained empty table.
            'eventsPruned' => $events === [] && (int) $alert['event_count'] > 0,
            'evidence'     => json_decode((string) $alert['evidence'], true) ?: [],
        ]));
    }

    public function acknowledge(): Response
    {
        if (!Csrf::check($_POST['_csrf'] ?? null)) {
            return Response::redirect('/alerts');
        }

        $id   = (int) ($_POST['id'] ?? 0);
        $note = trim((string) ($_POST['note'] ?? ''));

        if ($id <= 0) {
            return Response::redirect('/alerts');
        }

        if (($_POST['action'] ?? '') === 'close') {
            $this->alerts->close($id, $this->actor, $note === '' ? null : $note);
        } else {
            $this->alerts->acknowledge($id, $this->actor, $note === '' ? null : $note);
        }

        $back = ($_POST['back'] ?? '') === 'detail' ? "/alert?id={$id}" : '/alerts?acked=1';

        return Response::redirect($back);
    }
}
