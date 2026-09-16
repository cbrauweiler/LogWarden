<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Windows;

use LogWarden\Event\NormalizerInterface;
use LogWarden\Ingest\IngestSource;

/**
 * Picks the normaliser for a Windows source.
 *
 * The collector used to hand everything to AdNormalizer, which meant the DNS
 * audit channel came out as "Ereignis 542" with no user attached: the fields
 * it looks for (LogonType, SubStatus, TargetUserName) simply are not there.
 * The channel decides, not the transport.
 */
final class WindowsNormalizerFactory
{
    public static function for(IngestSource $source): NormalizerInterface
    {
        $host    = $source->targetHost ?? $source->name;
        $channel = $source->channel();

        if (DnsEventCatalog::isDnsChannel($channel)) {
            return new DnsNormalizer(
                $host,
                $channel,
                (bool) $source->setting('include_routine', true),
            );
        }

        return new AdNormalizer(
            $host,
            $channel,
            $source->sourceType,
            (bool) $source->setting('include_computer_accounts', false),
            (bool) $source->setting('include_system_accounts', false),
        );
    }
}
