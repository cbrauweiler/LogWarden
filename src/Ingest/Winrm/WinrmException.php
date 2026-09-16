<?php

declare(strict_types=1);

namespace LogWarden\Ingest\Winrm;

use RuntimeException;

/** Transport-level failure: DNS, TCP, TLS, HTTP status, unparseable body. */
class WinrmException extends RuntimeException
{
}
