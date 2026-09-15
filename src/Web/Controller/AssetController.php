<?php

declare(strict_types=1);

namespace LogWarden\Web\Controller;

use LogWarden\Web\Branding;
use LogWarden\Web\Response;

/**
 * Serves the generated theme stylesheet and the uploaded branding images.
 *
 * Both carry an ETag derived from the branding revision or the file checksum,
 * so browsers revalidate cheaply and a colour change is visible immediately
 * rather than after a cache expiry.
 */
final class AssetController
{
    public function __construct(private readonly Branding $branding)
    {
    }

    public function themeCss(): Response
    {
        $css  = $this->branding->themeCss();
        $etag = '"' . substr(hash('sha256', $css), 0, 16) . '"';

        if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $etag) {
            return new Response('', 304, ['ETag' => $etag, 'Cache-Control' => 'no-cache']);
        }

        return Response::css($css, [
            'ETag'          => $etag,
            'Cache-Control' => 'no-cache',
        ]);
    }

    public function logo(): Response
    {
        $slot  = (string) ($_GET['slot'] ?? '');
        $asset = $this->branding->asset($slot);

        if ($asset === null) {
            return Response::notFound('No such branding asset');
        }

        $etag = '"' . substr($asset['checksum'], 0, 16) . '"';

        if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $etag) {
            return new Response('', 304, ['ETag' => $etag, 'Cache-Control' => 'no-cache']);
        }

        return new Response($asset['data'], 200, [
            'Content-Type'   => $asset['mime_type'],
            'Content-Length' => (string) strlen($asset['data']),
            'ETag'           => $etag,
            'Cache-Control'  => 'no-cache',
            // An uploaded SVG renders in this origin; the sandbox keeps it from
            // doing anything beyond drawing, on top of the upload-time checks.
            'Content-Security-Policy' => "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            'X-Content-Type-Options'  => 'nosniff',
        ]);
    }
}
