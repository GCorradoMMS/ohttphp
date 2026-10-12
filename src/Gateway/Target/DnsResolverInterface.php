<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway\Target;

/**
 * Resolves host names to IP addresses for target policy validation.
 *
 * Implementations return every address they can find (A and AAAA); an
 * empty list means the host could not be resolved.
 */
interface DnsResolverInterface
{
    /**
     * @return list<string> Binary IP addresses (output of inet_pton)
     */
    public function resolve(string $host): array;
}
