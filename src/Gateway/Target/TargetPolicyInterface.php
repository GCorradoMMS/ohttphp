<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway\Target;

use Psr\Http\Message\UriInterface;

/**
 * Access policy for target resources reachable by the gateway.
 *
 * Implementations must throw TargetPolicyViolationException when a URI is
 * not allowed. The policy is a security boundary: the gateway must not
 * forward a request to a target that has not been accepted by the policy.
 */
interface TargetPolicyInterface
{
    /**
     * @throws TargetPolicyViolationException When the target is not allowed
     */
    public function enforce(UriInterface $uri): void;
}
