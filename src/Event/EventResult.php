<?php

declare(strict_types=1);

namespace LogWarden\Event;

enum EventResult: string
{
    case Success = 'success';
    case Fail    = 'fail';
    case Info    = 'info';
}
