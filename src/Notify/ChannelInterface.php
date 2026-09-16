<?php

declare(strict_types=1);

namespace LogWarden\Notify;

/**
 * Contract for a notification transport.
 *
 * Kept small on purpose: a channel formats and delivers one alert. Deciding
 * *whether* to deliver — cooldown, severity threshold, retry backoff — belongs
 * to the dispatcher, so a second transport does not have to reimplement it.
 */
interface ChannelInterface
{
    public static function type(): string;

    /**
     * @param array<string, mixed> $alert    Row from `alerts`, plus rule_name
     * @param array<string, mixed> $channel  Row from `notification_channels`
     * @param array<string, mixed> $branding Product name and base URL for links
     */
    public function send(array $alert, array $channel, array $branding, string $secret): NotificationResult;

    /**
     * Same transport, fixed content — used by the "send test" button so an
     * administrator can prove the webhook works before an incident depends
     * on it.
     */
    public function sendTest(array $channel, array $branding, string $secret): NotificationResult;
}
