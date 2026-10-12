<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Exception;

/**
 * Thrown when an encapsulated request cannot be opened by the gateway.
 *
 * Gateways must treat every failure covered by this exception uniformly:
 * the exception message is safe to log but callers SHOULD NOT emit
 * exception details to clients, to avoid creating a decryption oracle.
 */
final class RequestDecapsulationException extends OhttphpException
{
}
