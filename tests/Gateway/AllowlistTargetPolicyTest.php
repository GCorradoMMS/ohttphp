<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\Gateway;

use Gcorradomms\Ohttphp\Gateway\Target\AllowlistTargetPolicy;
use Gcorradomms\Ohttphp\Gateway\Target\IpAddress;
use Gcorradomms\Ohttphp\Gateway\Target\TargetPolicyViolationException;
use Gcorradomms\Ohttphp\Tests\StubDnsResolver;
use Nyholm\Psr7\Uri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AllowlistTargetPolicyTest extends TestCase
{
    private const PUBLIC_HOSTS = ['93.184.216.34', '2606:4700:4700::1111'];

    /**
     * @param list<string> $hosts
     * @param array<string, list<string>> $map
     */
    private function policy(array $hosts = ['target.example'], array $map = ['target.example' => ['93.184.216.34']]): AllowlistTargetPolicy
    {
        return new AllowlistTargetPolicy($hosts, ['https'], null, false, new StubDnsResolver($map));
    }

    public function testAllowsAllowlistedHostOnAllowedScheme(): void
    {
        $policy = $this->policy();

        $policy->enforce(new Uri('https://target.example/resource?q=1'));

        self::addToAssertionCount(1);
    }

    public function testRejectsUnknownHost(): void
    {
        $policy = $this->policy(['target.example']);

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce(new Uri('https://other.example/'));
    }

    public function testHostMatchingIgnoresCaseAndTrailingDot(): void
    {
        $policy = $this->policy(['target.example']);

        $policy->enforce(new Uri('https://TARGET.EXAMPLE./'));
        $policy->enforce(new Uri('https://target.example.:443/'));

        self::addToAssertionCount(1);
    }

    public function testRejectsDisallowedScheme(): void
    {
        $policy = $this->policy();

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce(new Uri('http://target.example/'));
    }

    public function testRejectsUserInfo(): void
    {
        $policy = $this->policy();

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce(new Uri('https://user:pass@target.example/'));
    }

    public function testRejectsMissingHost(): void
    {
        $policy = $this->policy();
        $uri = (new Uri())->withScheme('https')->withPath('/path');

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce($uri);
    }

    public function testRejectsDisallowedExplicitPort(): void
    {
        $policy = new AllowlistTargetPolicy(
            ['target.example'],
            ['https'],
            [8443],
            false,
            new StubDnsResolver(['target.example' => ['93.184.216.34']])
        );

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce(new Uri('https://target.example:9443/'));
    }

    public function testAllowsExplicitlyAllowedPort(): void
    {
        $policy = new AllowlistTargetPolicy(
            ['target.example'],
            ['https'],
            [8443],
            false,
            new StubDnsResolver(['target.example' => ['93.184.216.34']])
        );

        $policy->enforce(new Uri('https://target.example:8443/'));

        self::addToAssertionCount(1);
    }

    public function testRejectsUnresolvableHost(): void
    {
        $policy = $this->policy(['missing.example'], []);

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce(new Uri('https://missing.example/'));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function provideProhibitedAddresses(): array
    {
        return [
            'IPv4 loopback' => ['127.0.0.1'],
            'IPv4 private 10/8' => ['10.1.2.3'],
            'IPv4 private 172.16/12' => ['172.16.0.9'],
            'IPv4 private 192.168/16' => ['192.168.1.1'],
            'IPv4 CGNAT' => ['100.64.0.1'],
            'IPv4 link-local / cloud metadata' => ['169.254.169.254'],
            'IPv4 unspecified' => ['0.0.0.0'],
            'IPv4 multicast' => ['224.0.0.1'],
            'IPv4 broadcast range' => ['255.255.255.255'],
            'IPv4 documentation' => ['203.0.113.99'],
            'IPv6 loopback' => ['::1'],
            'IPv6 unspecified' => ['::'],
            'IPv6 link-local' => ['fe80::1'],
            'IPv6 unique local' => ['fd00::1'],
            'IPv6 multicast' => ['ff02::1'],
            'IPv6 documentation' => ['2001:db8::1'],
            'IPv4-mapped IPv6 loopback' => ['::ffff:127.0.0.1'],
            'IPv4-mapped IPv6 private' => ['::ffff:192.168.0.5'],
        ];
    }

    /**
     * An allowlisted host that resolves to any prohibited address must be
     * rejected: host string checks alone are insufficient.
     */
    #[DataProvider('provideProhibitedAddresses')]
    public function testRejectsHostResolvingToProhibitedAddress(string $address): void
    {
        $policy = $this->policy(['target.example'], ['target.example' => [$address]]);

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce(new Uri('https://target.example/'));
    }

    public function testAcceptsHostResolvingToPublicAddresses(): void
    {
        $policy = $this->policy(['target.example'], ['target.example' => self::PUBLIC_HOSTS]);

        $policy->enforce(new Uri('https://target.example/'));

        self::addToAssertionCount(1);
    }

    public function testDevelopmentOptInAllowsLoopback(): void
    {
        $policy = AllowlistTargetPolicy::forLocalDevelopment(['127.0.0.1'], [8003]);

        $policy->enforce(new Uri('http://127.0.0.1:8003/hello?name=world'));

        self::addToAssertionCount(1);
    }

    public function testDevelopmentOptInStillEnforcesAllowlist(): void
    {
        $policy = AllowlistTargetPolicy::forLocalDevelopment(['127.0.0.1'], [8003]);

        $this->expectException(TargetPolicyViolationException::class);
        $policy->enforce(new Uri('http://127.0.0.1:9999/'));
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function provideAddressClassification(): array
    {
        return [
            'public v4' => ['93.184.216.34', true],
            'private v4' => ['10.0.0.1', false],
            'mapped public v6' => ['::ffff:93.184.216.34', true],
            'mapped private v6' => ['::ffff:10.0.0.1', false],
            'public v6' => ['2606:4700:4700::1111', true],
        ];
    }

    #[DataProvider('provideAddressClassification')]
    public function testAddressClassification(string $address, bool $expectedReachable): void
    {
        $binary = IpAddress::fromText($address);
        $this->assertNotNull($binary);
        $this->assertSame($expectedReachable, IpAddress::isGloballyReachable($binary));
    }
}
