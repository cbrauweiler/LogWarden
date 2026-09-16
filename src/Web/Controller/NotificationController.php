<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Core\Db;
use LogWarden\Notify\Dispatcher;
use LogWarden\Notify\ChannelFactory;
use LogWarden\Security\SecretBox;
use LogWarden\Web\Csrf;
use LogWarden\Web\Response;
use LogWarden\Web\View;
use Throwable;

/**
 * Manages notification channels and which rule reports to which of them.
 */
final class NotificationController
{
    public function __construct(
        private readonly Db $db,
        private readonly SecretBox $secrets,
        private readonly Dispatcher $dispatcher,
        private readonly ChannelFactory $factory,
        private readonly View $view,
        private readonly string $actor,
    ) {
    }

    public function show(array $flash = [], array $errors = []): Response
    {
        return Response::html($this->view->page('admin/notifications', [
            'title'    => 'Benachrichtigungen',
            'active'   => 'notifications',
            'channels' => $this->channels(),
            'rules'    => $this->db->fetchAll('SELECT id, name, rule_key, severity, enabled FROM rules ORDER BY name'),
            'routing'  => $this->routing(),
            'flash'    => $flash,
            'errors'   => $errors,
        ]));
    }

    public function save(): Response
    {
        if (!Csrf::check($_POST['_csrf'] ?? null)) {
            return $this->show([], ['Sicherheits-Token abgelaufen. Bitte erneut absenden.']);
        }

        try {
            return match ((string) ($_POST['action'] ?? '')) {
                'save_channel'   => $this->saveChannel(),
                'delete_channel' => $this->deleteChannel(),
                'set_webhook'    => $this->setWebhook(),
                'test_channel'   => $this->testChannel(),
                'save_routing'   => $this->saveRouting(),
                default          => $this->show([], ['Unbekannte Aktion.']),
            };
        } catch (Throwable $e) {
            return $this->show([], [$e->getMessage()]);
        }
    }

    // -----------------------------------------------------------------------

    private function saveChannel(): Response
    {
        $id   = (int) ($_POST['channel_id'] ?? 0);
        $name = trim((string) ($_POST['name'] ?? ''));
        $type = (string) ($_POST['type'] ?? 'teams_workflow');
        $min  = max(1, min(5, (int) ($_POST['min_severity'] ?? 1)));
        $on   = !empty($_POST['enabled']);

        $errors = [];
        if ($name === '') {
            $errors[] = 'Name darf nicht leer sein.';
        } elseif (mb_strlen($name) > 80) {
            $errors[] = 'Name ist auf 80 Zeichen begrenzt.';
        }
        if (!in_array($type, ['teams_webhook', 'teams_workflow'], true)) {
            $errors[] = 'Unbekannter Kanaltyp.';
        }

        if ($errors !== []) {
            return $this->show([], $errors);
        }

        if ($id > 0) {
            $this->db->execute(
                'UPDATE notification_channels SET name = ?, type = ?, min_severity = ?, enabled = ? WHERE id = ?',
                [$name, $type, $min, $on ? 'true' : 'false', $id],
            );
            $this->audit('notification.channel.update', $name, ['id' => $id, 'type' => $type]);

            return Response::redirect('/settings/notifications?saved=1');
        }

        $exists = $this->db->fetchValue('SELECT 1 FROM notification_channels WHERE name = ?', [$name]);
        if ($exists !== null) {
            return $this->show([], ["Ein Kanal namens '{$name}' existiert bereits."]);
        }

        $newId = (int) $this->db->fetchValue(
            'INSERT INTO notification_channels (name, type, min_severity, enabled)
             VALUES (?, ?, ?, ?) RETURNING id',
            [$name, $type, $min, $on ? 'true' : 'false'],
        );

        $this->audit('notification.channel.create', $name, ['id' => $newId, 'type' => $type]);

        return Response::redirect('/settings/notifications?created=' . $newId);
    }

    private function deleteChannel(): Response
    {
        $id = (int) ($_POST['channel_id'] ?? 0);
        $channel = $this->db->fetchRow('SELECT name, secret_ref FROM notification_channels WHERE id = ?', [$id]);

        if ($channel === null) {
            return $this->show([], ['Kanal nicht gefunden.']);
        }

        // Remove the stored webhook alongside the channel: leaving a live
        // credential behind for a channel nobody can see is how secrets rot.
        if (!empty($channel['secret_ref'])) {
            $this->secrets->delete((string) $channel['secret_ref']);
        }

        $this->db->execute('DELETE FROM notification_channels WHERE id = ?', [$id]);
        $this->audit('notification.channel.delete', (string) $channel['name'], ['id' => $id]);

        return Response::redirect('/settings/notifications?deleted=1');
    }

    private function setWebhook(): Response
    {
        $id  = (int) ($_POST['channel_id'] ?? 0);
        $url = trim((string) ($_POST['webhook_url'] ?? ''));

        $channel = $this->db->fetchRow('SELECT id, name, type, secret_ref FROM notification_channels WHERE id = ?', [$id]);

        if ($channel === null) {
            return $this->show([], ['Kanal nicht gefunden.']);
        }

        if ($url === '') {
            return $this->show([], ['Keine URL eingegeben.']);
        }

        // Validate before storing, so a typo surfaces here rather than as a
        // failed delivery during an incident. Goes through the factory so the
        // configured notify.allow_private_targets applies.
        $this->factory->assertUsableUrl((string) $channel['type'], $url);

        $ref = $channel['secret_ref']
            ?: 'teams.' . trim((string) preg_replace('/[^a-z0-9]+/', '-', mb_strtolower((string) $channel['name'])), '-');

        $this->secrets->put($ref, $url);
        $this->db->execute('UPDATE notification_channels SET secret_ref = ? WHERE id = ?', [$ref, $id]);

        // The URL itself is the credential and is never logged, only its
        // reference name and host.
        $this->audit('notification.webhook.set', (string) $channel['name'], [
            'id'   => $id,
            'ref'  => $ref,
            'host' => parse_url($url, PHP_URL_HOST),
        ]);

        return Response::redirect('/settings/notifications?webhook=1');
    }

    private function testChannel(): Response
    {
        $id     = (int) ($_POST['channel_id'] ?? 0);
        $result = $this->dispatcher->test($id);

        $this->audit('notification.channel.test', (string) $id, ['ok' => $result['ok']]);

        return $result['ok']
            ? $this->show([$result['message']])
            : $this->show([], [$result['message']]);
    }

    private function saveRouting(): Response
    {
        $selected = $_POST['route'] ?? [];
        $pairs    = [];

        if (is_array($selected)) {
            foreach ($selected as $value) {
                if (preg_match('/^(\d+):(\d+)$/', (string) $value, $m) === 1) {
                    $pairs[] = [(int) $m[1], (int) $m[2]];
                }
            }
        }

        $this->db->transaction(function (Db $db) use ($pairs): void {
            $db->execute('DELETE FROM rule_channels');

            foreach ($pairs as [$ruleId, $channelId]) {
                $db->execute(
                    'INSERT INTO rule_channels (rule_id, channel_id) VALUES (?, ?) ON CONFLICT DO NOTHING',
                    [$ruleId, $channelId],
                );
            }
        });

        $this->audit('notification.routing.update', 'rule_channels', ['pairs' => count($pairs)]);

        return Response::redirect('/settings/notifications?routing=1');
    }

    // -----------------------------------------------------------------------

    /** @return list<array<string, mixed>> */
    private function channels(): array
    {
        return $this->db->fetchAll(
            "SELECT c.id, c.name, c.type, c.enabled, c.min_severity, c.secret_ref,
                    c.sent_total, c.failed_total, c.last_error,
                    to_char(c.last_success_at, 'DD.MM. HH24:MI') AS last_success_label,
                    to_char(c.last_error_at,   'DD.MM. HH24:MI') AS last_error_label,
                    count(rc.rule_id) AS rule_count
               FROM notification_channels c
               LEFT JOIN rule_channels rc ON rc.channel_id = c.id
              GROUP BY c.id
              ORDER BY c.name"
        );
    }

    /** @return array<string, bool> keyed "ruleId:channelId" */
    private function routing(): array
    {
        $map = [];

        foreach ($this->db->fetchAll('SELECT rule_id, channel_id FROM rule_channels') as $row) {
            $map[$row['rule_id'] . ':' . $row['channel_id']] = true;
        }

        return $map;
    }

    private function audit(string $action, string $target, array $details): void
    {
        $this->db->execute(
            'INSERT INTO audit_log (user_id, username, action, target, details)
             VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?, ?)',
            [$this->actor, $this->actor, $action, $target, json_encode($details, JSON_UNESCAPED_UNICODE)],
        );
    }
}
