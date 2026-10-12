<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway\Target;

use Gcorradomms\Ohttphp\Exception\OhttphpException;

/**
 * Thrown when a target URI is rejected by the gateway's target access
 * policy. The exception message is safe to encapsulate for the client but
 * must not echo full internal diagnostics.
 */
final class TargetPolicyViolationException extends OhttphpException
{
}
