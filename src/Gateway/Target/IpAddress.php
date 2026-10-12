<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway\Target;

use function inet_pton;
use function ord;
use function strlen;
use function substr;

/**
 * Binary IP address range classification used by target policies.
 *
 * All comparisons operate on the packed binary form produced by
 * inet_pton(); IPv4 and IPv6 (including IPv4-mapped IPv6 addresses) are
 * treated consistently.
 */
final class IpAddress
{
    private function __construct()
    {
    }

    /**
     * Parse a textual IP address into its packed binary representation.
     */
    public static function fromText(string $address): ?string
    {
        $binary = @inet_pton($address);

        return $binary === false ? null : $binary;
    }

    /**
     * Whether the address is a globally reachable public address. Loopback,
     * private, shared, link-local, multicast, reserved, documentation, and
     * translation ranges are not globally reachable. IPv4-mapped IPv6,
     * NAT64, and 6to4 addresses are evaluated against the embedded IPv4
     * address where one exists.
     */
    public static function isGloballyReachable(string $binary): bool
    {
        return match (strlen($binary)) {
            4 => self::isGloballyReachableV4($binary),
            16 => self::isGloballyReachableV6($binary),
            default => false,
        };
    }

    private static function isGloballyReachableV4(string $addr): bool
    {
        $restricted = [
            ['0.0.0.0', 8],        // this network
            ['10.0.0.0', 8],       // private
            ['100.64.0.0', 10],    // carrier-grade NAT
            ['127.0.0.0', 8],      // loopback
            ['169.254.0.0', 16],   // link-local (incl. cloud metadata)
            ['172.16.0.0', 12],    // private
            ['192.0.0.0', 24],     // IETF protocol assignments
            ['192.0.2.0', 24],     // TEST-NET-1
            ['192.88.99.0', 24],   // 6to4 relay anycast (deprecated)
            ['192.168.0.0', 16],   // private
            ['198.18.0.0', 15],    // benchmarking
            ['198.51.100.0', 24],  // TEST-NET-2
            ['203.0.113.0', 24],   // TEST-NET-3
            ['224.0.0.0', 4],      // multicast
            ['240.0.0.0', 4],      // reserved (incl. broadcast)
        ];
        foreach ($restricted as [$network, $bits]) {
            $networkBinary = self::fromText($network);
            if ($networkBinary !== null && self::prefixMatches($addr, $networkBinary, $bits)) {
                return false;
            }
        }

        return true;
    }

    private static function isGloballyReachableV6(string $addr): bool
    {
        // IPv4-mapped IPv6 (::ffff:0:0/96): evaluate the embedded IPv4.
        $mappedPrefix = self::fromText('::ffff:0.0.0.0');
        if ($mappedPrefix !== null && self::prefixMatches($addr, $mappedPrefix, 96)) {
            return self::isGloballyReachableV4(substr($addr, 12, 4));
        }
        // NAT64 well-known prefix (64:ff9b::/96): evaluate embedded IPv4.
        $nat64Prefix = self::fromText('64:ff9b::0.0.0.0');
        if ($nat64Prefix !== null && self::prefixMatches($addr, $nat64Prefix, 96)) {
            return self::isGloballyReachableV4(substr($addr, 12, 4));
        }

        $restricted = [
            ['::', 128],                  // unspecified
            ['::1', 128],                 // loopback
            ['64:ff9b::', 96],            // NAT64 (non-well-known part)
            ['100::', 64],                // discard-only
            ['2001::', 32],               // Teredo (deprecated)
            ['2001:db8::', 32],           // documentation
            ['2002::', 16],               // 6to4 (deprecated)
            ['fc00::', 7],                // unique local
            ['fe80::', 10],               // link-local
            ['ff00::', 8],                // multicast
        ];
        foreach ($restricted as [$network, $bits]) {
            $networkBinary = self::fromText($network);
            if ($networkBinary !== null && self::prefixMatches($addr, $networkBinary, $bits)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Compare the first $bits bits of two packed addresses.
     */
    private static function prefixMatches(string $addr, string $network, int $bits): bool
    {
        $whole = $bits >> 3;
        $remainder = $bits & 7;
        if (strlen($addr) !== strlen($network)) {
            return false;
        }
        if (substr($addr, 0, $whole) !== substr($network, 0, $whole)) {
            return false;
        }
        if ($remainder === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $remainder)) & 0xFF;

        return (ord($addr[$whole]) & $mask) === (ord($network[$whole]) & $mask);
    }
}
