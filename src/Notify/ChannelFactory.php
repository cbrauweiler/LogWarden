<?php

declare(strict_types=1);

namespace LogWarden\Notify;

use LogWarden\Core\Config;
use RuntimeException;

/**
 * Maps a channel's stored type to a transport.
 *
 * Same reasoning as the rule registry: the type column is configuration data,
 * so it selects from a fixed set rather than naming a class to instantiate.
 */
final class ChannelFactory
{
    /** @var array<string, ChannelInterface> */
    private array $channels;

    public function __construct(?string $proxy = null, bool $allowPrivateTargets = false)
    {
        $teams = new TeamsWebhookChannel(
            proxy: $proxy,
            allowPrivateTargets: $allowPrivateTargets,
        );

        // Both Teams endpoint generations take the same payload; only the
        // success status differs, and the transport accepts any 2xx.
        $this->channels = [
            'teams_webhook'  => $teams,
            'teams_workflow' => $teams,
        ];
    }

    public static function fromConfig(Config $config): self
    {
        return new self(
            proxy: $config->get('notify.proxy') ?: null,
            allowPrivateTargets: (bool) $config->get('notify.allow_private_targets', false),
        );
    }

    /**
     * Composition root for callers that supply their own transports — the
     * tests use it to drive the dispatcher without touching the network.
     *
     * @param array<string, ChannelInterface> $channels
     */
    public static function withChannels(array $channels): self
    {
        $factory = new self();
        $factory->channels = $channels;

        return $factory;
    }

    public function get(string $type): ChannelInterface
    {
        return $this->channels[$type]
            ?? throw new RuntimeException("Unbekannter Kanaltyp '{$type}'.");
    }

    public function has(string $type): bool
    {
        return isset($this->channels[$type]);
    }

    /**
     * Validates a webhook URL with the same rules the transport applies, so
     * the UI and the CLI cannot drift from what actually gets sent — and so
     * both honour notify.allow_private_targets instead of hardcoding it.
     *
     * @throws RuntimeException when the URL is unusable
     */
    public function assertUsableUrl(string $type, string $url): void
    {
        $channel = $this->get($type);

        if ($channel instanceof TeamsWebhookChannel) {
            $channel->assertUsableUrl($url);
        }
    }

    /** @return list<string> */
    public function types(): array
    {
        return array_keys($this->channels);
    }
}
