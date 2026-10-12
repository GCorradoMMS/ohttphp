<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\Gateway;

use Gcorradomms\Ohttphp\Gateway\GatewayKeyConfigHandler;
use Gcorradomms\Ohttphp\Gateway\GatewayKeyPair;
use Gcorradomms\Ohttphp\Gateway\InMemoryGatewayKeyStore;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class GatewayKeyConfigHandlerTest extends TestCase
{
    private Psr17Factory $factory;

    private InMemoryGatewayKeyStore $store;

    private GatewayKeyConfigHandler $handler;

    protected function setUp(): void
    {
        $this->factory = new Psr17Factory();
        $this->store = new InMemoryGatewayKeyStore();
        $this->handler = new GatewayKeyConfigHandler($this->store, $this->factory, $this->factory);
    }

    /**
     * @return list<SymmetricSuite>
     */
    private function suites(): array
    {
        return [SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm)];
    }

    public function testServesApplicationOhttpKeysCollection(): void
    {
        $this->store->add(GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->suites()));

        $response = $this->handler->handle(new ServerRequest('GET', 'https://gateway.example/ohttp-keys'));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/ohttp-keys', $response->getHeaderLine('Content-Type'));

        // The published bytes parse back into exactly the active keys.
        $collection = KeyConfigCollection::fromEncoded((string) $response->getBody());
        $this->assertCount(1, $collection);
        $this->assertSame(1, $collection->toArray()[0]->keyId);
        $this->assertSame(KemId::DhkemX25519HkdfSha256, $collection->toArray()[0]->kemId);
    }

    public function testExcludesRetiredKeys(): void
    {
        $old = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->suites());
        $new = GatewayKeyPair::generate(2, KemId::DhkemX25519HkdfSha256, $this->suites());
        $this->store->add($old);
        $this->store->add($new);
        $this->store->retire(1);

        $response = $this->handler->handle(new ServerRequest('GET', 'https://gateway.example/ohttp-keys'));

        $collection = KeyConfigCollection::fromEncoded((string) $response->getBody());
        $this->assertCount(1, $collection);
        $this->assertSame(2, $collection->toArray()[0]->keyId);
    }

    public function testPublishedConfigurationContainsNoSecretMaterial(): void
    {
        $pair = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->suites());
        $this->store->add($pair);

        $response = $this->handler->handle(new ServerRequest('GET', 'https://gateway.example/ohttp-keys'));

        $body = (string) $response->getBody();
        $this->assertStringNotContainsString(bin2hex($pair->secretKey->bytes), bin2hex($body));
        $this->assertStringNotContainsString(base64_encode($pair->secretKey->bytes), $body);
    }

    public function testRejectsNonGetRequests(): void
    {
        $response = $this->handler->handle(new ServerRequest('POST', 'https://gateway.example/ohttp-keys'));

        $this->assertSame(405, $response->getStatusCode());
        $this->assertStringContainsString('GET', $response->getHeaderLine('Allow'));
    }

    public function testReportsServiceUnavailableWithoutKeys(): void
    {
        $response = $this->handler->handle(new ServerRequest('GET', 'https://gateway.example/ohttp-keys'));

        $this->assertSame(503, $response->getStatusCode());
    }
}
