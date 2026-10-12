<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Ohttp;

/**
 * Result of encapsulating a request: the context needed to process the
 * response, and the Encapsulated Request to send to the relay.
 */
final class Encapsulation
{
    public function __construct(
        public readonly OhttpContext $context,
        public readonly string $encapsulatedRequest,
    ) {
    }
}
