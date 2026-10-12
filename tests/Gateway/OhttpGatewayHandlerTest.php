<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\Gateway;

use Gcorradomms\Ohttphp\Gateway\GatewayKeyPair;
use Gcorradomms\Ohttphp\Gateway\InMemoryGatewayKeyStore;
use Gcorradomms\Ohttphp\Gateway\OhttpGatewayHandler;
use Gcorradomms\Ohttphp\Gateway\Target\AllowlistTargetPolicy;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Gcorradomms\Ohttphp\OhttpClient;
use Gcorradomms\Ohttphp\Tests\CallbackHttpClient;
use Gcorradomms\Ohttphp\Tests\InMemoryLogger;
use Gcorradomms\Ohttphp\Tests\StubDnsResolver;
use GuzzleHttp\Client as GuzzleClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function base64_encode;
use function bin2hex;
use function json_decode;
use function strlen;
use function str_repeat;
use function substr;

/**
 * End-to-end tests of the production gateway handler through the real
 * OhttpClient public API, with genuine HPKE operations for every
 * supported KEM/KDF/AEAD combination.
 */
final class OhttpGatewayHandlerTest extends TestCase
{
    private Psr17Factory $factory;

    private InMemoryGatewayKeyStore $keyStore;

    private CallbackHttpClient $targetClient;

    private InMemoryLogger $logger;

    private OhttpGatewayHandler $handler;

    protected function setUp(): void
    {
        $this->factory = new Psr17Factory();
        $this->keyStore = new InMemoryGatewayKeyStore();
        $this->targetClient = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response(200, ['Content-Type' => 'text/plain'], 'hello from target')
        );
        $this->logger = new InMemoryLogger();
        $this->handler = $this->createHandler();
    }

    private function createHandler(?CallbackHttpClient $targetClient = null, ?int $maxTargetResponseSize = null): OhttpGatewayHandler
    {
        return new OhttpGatewayHandler(
            $this->keyStore,
            new AllowlistTargetPolicy(
                ['target.example'],
                ['https'],
                null,
                false,
                new StubDnsResolver(['target.example' => ['93.184.216.34']])
            ),
            $targetClient ?? $this->targetClient,
            $this->factory,
            $this->factory,
            $this->factory,
            $this->factory,
            65536,
            $maxTargetResponseSize ?? 1048576,
            $this->logger,
        );
    }

    private function createClient(): OhttpClient
    {
        return new OhttpClient(
            new GuzzleClient(['allow_redirects' => false]),
            $this->factory,
            $this->factory,
            $this->factory,
            $this->factory,
        );
    }

    private function addKey(KemId $kemId = KemId::DhkemX25519HkdfSha256, int $keyId = 1): GatewayKeyPair
    {
        $pair = GatewayKeyPair::generate(
            $keyId,
            $kemId,
            [
                SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm),
                SymmetricSuite::from(KdfId::HkdfSha256, AeadId::ChaCha20Poly1305),
                SymmetricSuite::from(KdfId::HkdfSha512, AeadId::Aes256Gcm),
            ]
        );
        $this->keyStore->add($pair);

        return $pair;
    }

    private function wrapEncapsulatedRequest(string $bytes): ServerRequestInterface
    {
        $serverRequest = new ServerRequest('POST', 'https://gateway.example/oblivious/request');
        $serverRequest = $serverRequest->withHeader('Content-Type', 'message/ohttp-req');

        return $serverRequest->withBody($this->factory->createStream($bytes));
    }

    /**
     * @return array<string, array{0: KemId, 1: KdfId, 2: AeadId}>
     */
    public static function provideSuites(): array
    {
        return [
            'X25519 + HKDF-SHA256 + AES-128-GCM' => [KemId::DhkemX25519HkdfSha256, KdfId::HkdfSha256, AeadId::Aes128Gcm],
            'X25519 + HKDF-SHA256 + ChaCha20Poly1305' => [KemId::DhkemX25519HkdfSha256, KdfId::HkdfSha256, AeadId::ChaCha20Poly1305],
            'P-256 + HKDF-SHA256 + AES-128-GCM' => [KemId::DhkemP256HkdfSha256, KdfId::HkdfSha256, AeadId::Aes128Gcm],
            'P-384 + HKDF-SHA256 + AES-128-GCM' => [KemId::DhkemP384HkdfSha256, KdfId::HkdfSha256, AeadId::Aes128Gcm],
            'P-521 + HKDF-SHA512 + AES-256-GCM' => [KemId::DhkemP521HkdfSha512, KdfId::HkdfSha512, AeadId::Aes256Gcm],
        ];
    }

    #[DataProvider('provideSuites')]
    public function testFullGetExchange(KemId $kemId, KdfId $kdfId, AeadId $aeadId): void
    {
        $pair = GatewayKeyPair::generate(1, $kemId, [SymmetricSuite::from($kdfId, $aeadId)]);
        $this->keyStore->add($pair);
        $client = $this->createClient();

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/hello?name=world'),
            new KeyConfigCollection([$pair->keyConfig()])
        );

        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));

        $this->assertSame(200, $gatewayResponse->getStatusCode());
        $this->assertSame('message/ohttp-res', $gatewayResponse->getHeaderLine('Content-Type'));

        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());
        $this->assertSame(200, $final->getStatusCode());
        $this->assertSame('hello from target', (string) $final->getBody());

        // The target saw the decoded request.
        $this->assertCount(1, $this->targetClient->requests);
        $forwarded = $this->targetClient->requests[0];
        $this->assertSame('GET', $forwarded->getMethod());
        $this->assertSame('target.example', $forwarded->getUri()->getHost());
        $this->assertSame('/hello?name=world', $forwarded->getRequestTarget());
    }

    public function testFullPostExchangePreservesBodyAndHeaders(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();

        $encapsulation = $client->encapsulate(
            new Request(
                'POST',
                'https://target.example/submit',
                ['Content-Type' => 'application/json', 'X-Custom' => 'e2e-value'],
                '{"payload":true}'
            ),
            new KeyConfigCollection([$pair->keyConfig()])
        );

        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));
        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());

        $this->assertSame(200, $final->getStatusCode());
        $forwarded = $this->targetClient->requests[0];
        $this->assertSame('POST', $forwarded->getMethod());
        $this->assertSame('application/json', $forwarded->getHeaderLine('content-type'));
        $this->assertSame('e2e-value', $forwarded->getHeaderLine('x-custom'));
        $this->assertSame('{"payload":true}', (string) $forwarded->getBody());
    }

    /**
     * @return array<array-key, list<int>>
     */
    public static function provideStatusCodes(): array
    {
        return [
            '200' => [200],
            '201' => [201],
            '204' => [204],
            '301' => [301],
            '400' => [400],
            '404' => [404],
            '500' => [500],
        ];
    }

    #[DataProvider('provideStatusCodes')]
    public function testPreservesTargetStatusCodes(int $status): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $this->targetClient = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response($status, ['X-From' => 'target'], "status $status")
        );
        $this->handler = $this->createHandler($this->targetClient);

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/thing'),
            new KeyConfigCollection([$pair->keyConfig()])
        );
        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));
        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());

        $this->assertSame($status, $final->getStatusCode());
        $this->assertSame('target', $final->getHeaderLine('x-from'));
        $this->assertSame("status $status", (string) $final->getBody());
    }

    public function testTargetRedirectIsReturnedNotFollowed(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $this->targetClient = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response(301, ['Location' => 'https://target.example/moved'], '')
        );
        $this->handler = $this->createHandler($this->targetClient);

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/old'),
            new KeyConfigCollection([$pair->keyConfig()])
        );
        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));
        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());

        $this->assertSame(301, $final->getStatusCode());
        $this->assertSame('https://target.example/moved', $final->getHeaderLine('location'));
        // Exactly one target request: no automatic follow.
        $this->assertCount(1, $this->targetClient->requests);
    }

    public function testPolicyViolationProducesEncapsulated403(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();

        // Host is not on the allowlist.
        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://internal.example/secret'),
            new KeyConfigCollection([$pair->keyConfig()])
        );
        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));

        // The relay sees a normal 200 encapsulated response.
        $this->assertSame(200, $gatewayResponse->getStatusCode());
        $this->assertSame('message/ohttp-res', $gatewayResponse->getHeaderLine('Content-Type'));

        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());
        $this->assertSame(403, $final->getStatusCode());
        $this->assertSame('application/problem+json', $final->getHeaderLine('Content-Type'));
        // The target was never contacted.
        $this->assertCount(0, $this->targetClient->requests);
    }

    public function testRejectsNonPostMethod(): void
    {
        $response = $this->handler->handle(new ServerRequest('GET', 'https://gateway.example/oblivious/request'));

        $this->assertSame(405, $response->getStatusCode());
        $this->assertSame('POST', $response->getHeaderLine('Allow'));
    }

    public function testRejectsWrongContentType(): void
    {
        $request = new ServerRequest('POST', 'https://gateway.example/oblivious/request');
        $request = $request->withHeader('Content-Type', 'application/json');

        $response = $this->handler->handle($request);

        $this->assertSame(415, $response->getStatusCode());
    }

    public function testRejectsEmptyBody(): void
    {
        $response = $this->handler->handle($this->wrapEncapsulatedRequest(''));

        $this->assertSame(400, $response->getStatusCode());
    }

    public function testRejectsOversizedBodyBeforeCryptographicProcessing(): void
    {
        $handler = new OhttpGatewayHandler(
            $this->keyStore,
            new AllowlistTargetPolicy(['target.example'], ['https'], null, false, new StubDnsResolver([])),
            $this->targetClient,
            $this->factory,
            $this->factory,
            $this->factory,
            $this->factory,
            64,
            1048576,
            $this->logger,
        );

        $response = $handler->handle($this->wrapEncapsulatedRequest(str_repeat('a', 65)));

        $this->assertSame(413, $response->getStatusCode());
        $this->assertCount(0, $this->targetClient->requests);
    }

    public function testRejectsUnknownKeyIdentifierUniformly(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/'),
            new KeyConfigCollection([$pair->keyConfig()])
        );

        // Tamper the key identifier byte (header position 0).
        $tampered = $encapsulation->encapsulatedRequest;
        $tampered[0] = "\x7f";

        $response = $this->handler->handle($this->wrapEncapsulatedRequest($tampered));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
    }

    public function testRejectsUnsupportedSuiteUniformly(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/'),
            new KeyConfigCollection([$pair->keyConfig()])
        );

        // Tamper the KDF identifier (header bytes 3-4) to an unknown value.
        $tampered = $encapsulation->encapsulatedRequest;
        $tampered[3] = "\x00";
        $tampered[4] = "\xff";

        $response = $this->handler->handle($this->wrapEncapsulatedRequest($tampered));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame(
            'The encapsulated request could not be processed.',
            $this->problemDetail($response)
        );
    }

    public function testRejectsTruncatedEncapsulatedRequest(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/'),
            new KeyConfigCollection([$pair->keyConfig()])
        );

        $truncated = substr($encapsulation->encapsulatedRequest, 0, 10);

        $this->assertSame(400, $this->handler->handle($this->wrapEncapsulatedRequest($truncated))->getStatusCode());
    }

    public function testRejectsCorruptedCiphertextWithUniformError(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/'),
            new KeyConfigCollection([$pair->keyConfig()])
        );

        $corrupted = $encapsulation->encapsulatedRequest;
        $last = strlen($corrupted) - 1;
        $corrupted[$last] = $corrupted[$last] ^ "\xff";

        $response = $this->handler->handle($this->wrapEncapsulatedRequest($corrupted));

        // Uniform 400: indistinguishable from other decapsulation failures.
        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame(
            'The encapsulated request could not be processed.',
            $this->problemDetail($response)
        );
    }

    public function testTargetNetworkFailureProducesEncapsulated502(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $this->handler = $this->createHandler(CallbackHttpClient::failingNetwork());

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/'),
            new KeyConfigCollection([$pair->keyConfig()])
        );
        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));
        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());

        $this->assertSame(502, $final->getStatusCode());
    }

    public function testTargetTimeoutProducesEncapsulated504(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $this->handler = $this->createHandler(CallbackHttpClient::failingTimeout());

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/'),
            new KeyConfigCollection([$pair->keyConfig()])
        );
        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));
        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());

        $this->assertSame(504, $final->getStatusCode());
    }

    public function testOversizedTargetResponseProducesEncapsulated502(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $this->targetClient = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response(200, [], str_repeat('x', 1024))
        );
        $this->handler = $this->createHandler($this->targetClient, 256);

        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/big'),
            new KeyConfigCollection([$pair->keyConfig()])
        );
        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));
        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());

        $this->assertSame(502, $final->getStatusCode());
    }

    public function testHopByHopHeadersAreStrippedFromForwardedRequest(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();

        $encapsulation = $client->encapsulate(
            (new Request(
                'GET',
                'https://target.example/forwarded',
                [
                    'Connection' => ['x-secret'],
                    'X-Secret' => ['nominated-by-connection'],
                    'Proxy-Authorization' => ['Basic Zm9vOmJhcg=='],
                    'X-Keep' => ['yes'],
                ]
            )),
            new KeyConfigCollection([$pair->keyConfig()])
        );

        $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));

        $forwarded = $this->targetClient->requests[0];
        $this->assertFalse($forwarded->hasHeader('connection'));
        $this->assertFalse($forwarded->hasHeader('x-secret'));
        $this->assertFalse($forwarded->hasHeader('proxy-authorization'));
        // The Host header is re-derived by the HTTP client from the URI.
        $this->assertFalse($forwarded->hasHeader('host'));
        $this->assertTrue($forwarded->hasHeader('x-keep'));
    }

    public function testRetiredKeysStillDecryptButNewKeysAreUsedForNewRequests(): void
    {
        $old = $this->addKey(keyId: 1);
        $new = $this->addKey(keyId: 2);
        $this->keyStore->retire(1);
        $client = $this->createClient();

        // A client that still holds the old configuration succeeds.
        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/compat'),
            new KeyConfigCollection([$old->keyConfig()])
        );
        $gatewayResponse = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));
        $final = $client->decapsulateResponse($encapsulation->context, (string) $gatewayResponse->getBody());
        $this->assertSame(200, $final->getStatusCode());

        // And a client with the new configuration succeeds too.
        $encapsulation2 = $client->encapsulate(
            new Request('GET', 'https://target.example/current'),
            new KeyConfigCollection([$new->keyConfig()])
        );
        $gatewayResponse2 = $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation2->encapsulatedRequest));
        $final2 = $client->decapsulateResponse($encapsulation2->context, (string) $gatewayResponse2->getBody());
        $this->assertSame(200, $final2->getStatusCode());
    }

    public function testNoSecretMaterialInErrorsOrLogs(): void
    {
        $pair = $this->addKey();
        $client = $this->createClient();
        $secretHex = bin2hex($pair->secretKey->bytes);
        $secretB64 = base64_encode($pair->secretKey->bytes);

        // Trigger several error paths.
        $this->handler->handle(new ServerRequest('GET', 'https://gateway.example/x'));
        $this->handler->handle((new ServerRequest('POST', 'https://gateway.example/x'))->withHeader('Content-Type', 'text/plain'));
        $this->handler->handle($this->wrapEncapsulatedRequest(''));
        $this->handler->handle($this->wrapEncapsulatedRequest(str_repeat('a', 100)));
        $encapsulation = $client->encapsulate(
            new Request('GET', 'https://target.example/'),
            new KeyConfigCollection([$pair->keyConfig()])
        );
        $this->handler->handle($this->wrapEncapsulatedRequest($encapsulation->encapsulatedRequest));

        $collected = '';
        foreach ($this->logger->records as $record) {
            $collected .= $record['message'] . json_encode($record['context']);
        }
        foreach ($this->targetClient->requests as $forwarded) {
            $collected .= (string) $forwarded->getBody();
        }

        $this->assertStringNotContainsString($secretHex, $collected);
        $this->assertStringNotContainsString($secretB64, $collected);
    }

    private function problemDetail(ResponseInterface $response): string
    {
        $decoded = json_decode((string) $response->getBody(), true);
        $this->assertIsArray($decoded);
        $detail = $decoded['detail'] ?? '';
        $this->assertIsString($detail);

        return $detail;
    }
}
