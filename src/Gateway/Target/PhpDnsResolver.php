<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway\Target;

use function array_unique;
use function array_values;
use function count;
use function dns_get_record;
use function filter_var;
use function gethostbyname;
use function inet_pton;
use function is_array;
use function strtolower;

use const FILTER_VALIDATE_IP;

/**
 * Default DNS resolver backed by PHP's DNS functions. Resolves both A and
 * AAAA records and accepts IP literals directly.
 */
final class PhpDnsResolver implements DnsResolverInterface
{
    public function resolve(string $host): array
    {
        $host = strtolower($host);

        // IP literals resolve to themselves.
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $binary = IpAddress::fromText($host);

            return $binary === null ? [] : [$binary];
        }

        $addresses = [];
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                $ip = $record['ip'] ?? null;
                $ipv6 = $record['ipv6'] ?? null;
                foreach ([$ip, $ipv6] as $candidate) {
                    if (!is_string($candidate)) {
                        continue;
                    }
                    $binary = IpAddress::fromText($candidate);
                    if ($binary !== null) {
                        $addresses[] = $binary;
                    }
                }
            }
        }

        // Fallback for systems or resolvers where dns_get_record is
        // unavailable or returns nothing (covers A records only).
        if (count($addresses) === 0) {
            $resolved = @gethostbyname($host);
            if ($resolved !== $host && filter_var($resolved, FILTER_VALIDATE_IP) !== false) {
                $binary = IpAddress::fromText($resolved);
                if ($binary !== null) {
                    $addresses[] = $binary;
                }
            }
        }

        /** @var list<string> */
        return array_values(array_unique($addresses));
    }
}
