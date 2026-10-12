<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway\Target;

use Psr\Http\Message\UriInterface;

use function array_map;
use function count;
use function in_array;
use function rtrim;
use function strtolower;

/**
 * Default-deny target policy with an exact host allowlist, scheme and
 * port restrictions, and resolution of every host name to validate the
 * addresses it points at.
 *
 * By default, no destination that resolves to a loopback, private,
 * link-local (including cloud metadata), multicast, or reserved address
 * is permitted, for both IPv4 and IPv6 (including IPv4-mapped and NAT64
 * embedded IPv4). Host names that cannot be resolved are rejected
 * (fail closed).
 *
 * The $allowPrivateAddresses opt-in exists solely for local development
 * (for example, a gateway on 127.0.0.1 talking to a target on 127.0.0.1).
 * It must not be enabled in production.
 *
 * DNS rebinding note: validation happens immediately before the request
 * is forwarded, but a generic PSR-18 client performs its own resolution
 * and cannot pin the validated address. Operators MUST therefore also
 * enforce egress restrictions at the network level as defense in depth.
 */
final class AllowlistTargetPolicy implements TargetPolicyInterface
{
    /** @var list<string> */
    private readonly array $allowedHosts;

    /**
     * @param list<string> $allowedHosts Exact host names or IP literals,
     *     compared case-insensitively; a trailing dot is ignored
     * @param list<string> $allowedSchemes Allowed URI schemes (lowercase)
     * @param list<int>|null $allowedPorts Allowed explicit ports; null
     *     permits any port, including scheme-default ports
     * @param bool $allowPrivateAddresses Development-only opt-in that
     *     skips address-range checks
     * @param DnsResolverInterface|null $resolver Defaults to PhpDnsResolver
     */
    public function __construct(
        array $allowedHosts,
        private readonly array $allowedSchemes = ['https'],
        private readonly ?array $allowedPorts = null,
        private readonly bool $allowPrivateAddresses = false,
        private readonly ?DnsResolverInterface $resolver = null,
    ) {
        $this->allowedHosts = array_map(
            static fn (string $host): string => strtolower(rtrim($host, '.')),
            $allowedHosts
        );
    }

    /**
     * Development-only policy for local end-to-end testing: permits HTTP
     * and HTTPS targets on the given loopback hosts and ports.
     *
     * @param list<string> $hosts
     * @param list<int> $ports
     */
    public static function forLocalDevelopment(array $hosts, array $ports): self
    {
        return new self($hosts, ['http', 'https'], $ports, true, new PhpDnsResolver());
    }

    public function enforce(UriInterface $uri): void
    {
        $scheme = strtolower($uri->getScheme());
        if (!in_array($scheme, $this->allowedSchemes, true)) {
            throw new TargetPolicyViolationException('Target URI scheme is not allowed');
        }

        if ($uri->getUserInfo() !== '') {
            throw new TargetPolicyViolationException('Target URI must not contain credentials');
        }

        $host = strtolower(rtrim($uri->getHost(), '.'));
        if ($host === '') {
            throw new TargetPolicyViolationException('Target URI has no host');
        }
        if (!in_array($host, $this->allowedHosts, true)) {
            throw new TargetPolicyViolationException('Target host is not allowed');
        }

        if ($this->allowedPorts !== null) {
            $effectivePort = $uri->getPort() ?? self::defaultPort($scheme);
            if ($effectivePort === null || !in_array($effectivePort, $this->allowedPorts, true)) {
                throw new TargetPolicyViolationException('Target port is not allowed');
            }
        }

        $resolver = $this->resolver ?? new PhpDnsResolver();
        $addresses = $resolver->resolve($host);
        if (count($addresses) === 0) {
            throw new TargetPolicyViolationException('Target host could not be resolved');
        }

        if (!$this->allowPrivateAddresses) {
            foreach ($addresses as $address) {
                if (!IpAddress::isGloballyReachable($address)) {
                    throw new TargetPolicyViolationException('Target host resolves to a prohibited address');
                }
            }
        }
    }

    private static function defaultPort(string $scheme): ?int
    {
        return match ($scheme) {
            'http', 'ws' => 80,
            'https', 'wss' => 443,
            default => null,
        };
    }
}
