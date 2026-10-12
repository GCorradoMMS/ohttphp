<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests;

use Gcorradomms\Ohttphp\Exception\RelayException;
use Gcorradomms\Ohttphp\Exception\UnsupportedAlgorithmException;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Gcorradomms\Ohttphp\OhttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function ord;
use function str_repeat;

final class OhttpClientIntegrationTest extends TestCase
{
    private Psr17Factory $factory;

    protected function setUp(): void
    {
        $this->factory = new Psr17Factory();
    }

    private function createClient(ClientInterface $relay): OhttpClient
    {
        return new OhttpClient(
            $relay,
            $this->factory,
            $this->factory,
            $this->factory,
            $this->factory,
        );
    }

    /**
     * @return array<string, array{KemId, KdfId, AeadId}>
     */
    public static function provideSuites(): array
    {
        return [
            'X25519 + HKDF-SHA256 + AES-128-GCM' => [KemId::DhkemX25519HkdfSha256, KdfId::HkdfSha256, AeadId::Aes128Gcm],
            'X25519 + HKDF-SHA256 + ChaCha20Poly1305' => [KemId::DhkemX25519HkdfSha256, KdfId::HkdfSha256, AeadId::ChaCha20Poly1305],
            'P-256 + HKDF-SHA256 + AES-128-GCM' => [KemId::DhkemP256HkdfSha256, KdfId::HkdfSha256, AeadId::Aes128Gcm],
            'P-256 + HKDF-SHA512 + AES-256-GCM' => [KemId::DhkemP256HkdfSha256, KdfId::HkdfSha512, AeadId::Aes256Gcm],
            'P-384 + HKDF-SHA256 + AES-128-GCM' => [KemId::DhkemP384HkdfSha256, KdfId::HkdfSha256, AeadId::Aes128Gcm],
            'P-521 + HKDF-SHA512 + AES-256-GCM' => [KemId::DhkemP521HkdfSha512, KdfId::HkdfSha512, AeadId::Aes256Gcm],
        ];
    }

    /**
     * Full round trip through an in-process relay + gateway for every
     * supported HPKE suite combination.
     */
    #[DataProvider('provideSuites')]
    public function testFullExchange(KemId $kemId, KdfId $kdfId, AeadId $aeadId): void
    {
        $relay = FakeRelay::create($kemId, $kdfId, $aeadId);
        $client = $this->createClient($relay);

        $targetRequest = new Request(
            'POST',
            'https://target.example.net/search?q=ohttp',
            ['Content-Type' => 'application/json', 'Accept' => 'application/json'],
            '{"query":"ohttp"}'
        );

        $response = $client->send(
            $targetRequest,
            new KeyConfigCollection([$relay->keyConfig()]),
            FakeRelay::RELAY_URI
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('200 response for POST /search?q=ohttp', (string) $response->getBody());
    }

    public function testGetRequestRoundTrip(): void
    {
        $relay = FakeRelay::create();
        $client = $this->createClient($relay);

        $targetRequest = new Request('GET', 'https://example.com/hello.txt');

        $response = $client->send(
            $targetRequest,
            new KeyConfigCollection([$relay->keyConfig()]),
            FakeRelay::RELAY_URI
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('200 response for GET /hello.txt', (string) $response->getBody());
    }

    public function testSelectsFirstSupportedConfiguration(): void
    {
        $relay = FakeRelay::create();
        $client = $this->createClient($relay);

        // A config advertising only unknown suites, followed by the real one.
        $unsupported = new \Gcorradomms\Ohttphp\KeyConfig\KeyConfig(
            2,
            \Gcorradomms\Ohttphp\KeyConfig\KemId::DhkemX25519HkdfSha256,
            str_repeat("\x01", 32),
            [new SymmetricSuite(0x00FF, 0x0003)]
        );

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://example.com/'),
            new KeyConfigCollection([$unsupported, $relay->keyConfig()])
        );

        $this->assertSame(1, ord($encapsulation->context->header()[0]));
    }

    public function testThrowsWhenNoSuiteIsSupported(): void
    {
        $relay = FakeRelay::create();
        $client = $this->createClient($relay);

        $unsupported = new \Gcorradomms\Ohttphp\KeyConfig\KeyConfig(
            2,
            \Gcorradomms\Ohttphp\KeyConfig\KemId::DhkemX25519HkdfSha256,
            str_repeat("\x01", 32),
            [new SymmetricSuite(0x00FF, 0x0003)]
        );

        $this->expectException(UnsupportedAlgorithmException::class);
        $client->encapsulate(
            new Request('GET', 'https://example.com/'),
            new KeyConfigCollection([$unsupported])
        );
    }

    public function testThrowsOnRelayErrorStatus(): void
    {
        $relay = FakeRelay::create();
        $failingRelay = new class() implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                return new Response(451, [], 'unavailable for legal reasons');
            }
        };
        $client = $this->createClient($failingRelay);

        $this->expectException(RelayException::class);
        $client->send(
            new Request('GET', 'https://example.com/'),
            new KeyConfigCollection([$relay->keyConfig()]),
            FakeRelay::RELAY_URI
        );
    }

    public function testThrowsWhenRelayResponseIsNotDecryptable(): void
    {
        $relay = FakeRelay::create();
        $tamperingRelay = new class() implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                // Well-formed length, garbage content: 16-byte nonce + junk.
                return new Response(200, ['Content-Type' => 'message/ohttp-res'], str_repeat("\x00", 48));
            }
        };
        $client = $this->createClient($tamperingRelay);

        $this->expectException(\Gcorradomms\Ohttphp\Exception\ResponseDecryptionException::class);
        $client->send(
            new Request('GET', 'https://example.com/'),
            new KeyConfigCollection([$relay->keyConfig()]),
            FakeRelay::RELAY_URI
        );
    }

    public function testThrowsWhenRelayClientFails(): void
    {
        $relay = FakeRelay::create();
        $brokenRelay = new class() implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                throw new class('connection refused') extends \RuntimeException implements ClientExceptionInterface {
                };
            }
        };
        $client = $this->createClient($brokenRelay);

        $this->expectException(RelayException::class);
        $client->send(
            new Request('GET', 'https://example.com/'),
            new KeyConfigCollection([$relay->keyConfig()]),
            FakeRelay::RELAY_URI
        );
    }

    public function testEncapsulateAndDecapsulateCanBeUsedSeparately(): void
    {
        $relay = FakeRelay::create();
        $client = $this->createClient($relay);

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://example.com/'),
            new KeyConfigCollection([$relay->keyConfig()])
        );

        $relayResponse = $relay->sendRequest(
            $this->factory->createRequest('POST', FakeRelay::RELAY_URI)
                ->withHeader('Content-Type', 'message/ohttp-req')
                ->withBody($this->factory->createStream($encapsulation->encapsulatedRequest))
        );

        $final = $client->decapsulateResponse($encapsulation->context, (string) $relayResponse->getBody());

        $this->assertSame(200, $final->getStatusCode());
        $this->assertSame('200 response for GET /', (string) $final->getBody());
    }

    public function testCurveSuiteWithP256EndToEnd(): void
    {
        // Explicit cross-check that non-X25519 KEMs interoperate end to end.
        $relay = FakeRelay::create(KemId::DhkemP256HkdfSha256);
        $client = $this->createClient($relay);

        $response = $client->send(
            new Request('GET', 'https://example.com/'),
            new KeyConfigCollection([$relay->keyConfig()]),
            FakeRelay::RELAY_URI
        );

        $this->assertSame(200, $response->getStatusCode());
    }
}
