<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests;

use Gcorradomms\Ohttphp\Gateway\Target\DnsResolverInterface;
use Gcorradomms\Ohttphp\Gateway\Target\IpAddress;

use function array_key_exists;

/**
 * DNS resolver test double backed by a fixed host -> address map.
 */
final class StubDnsResolver implements DnsResolverInterface
{
    /**
     * @param array<string, list<string>> $map Textual IP addresses per host
     */
    public function __construct(private readonly array $map = [])
    {
    }

    public function resolve(string $host): array
    {
        $addresses = [];
        foreach ($this->map[strtolower($host)] ?? [] as $ip) {
            $binary = IpAddress::fromText($ip);
            if ($binary !== null) {
                $addresses[] = $binary;
            }
        }

        return $addresses;
    }
}
