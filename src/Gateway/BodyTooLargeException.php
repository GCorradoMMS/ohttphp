<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway;

use RuntimeException;

/**
 * Internal marker thrown when a target response body exceeds the
 * configured size limit.
 */
final class BodyTooLargeException extends RuntimeException
{
}
