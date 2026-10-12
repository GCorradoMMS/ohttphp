<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\Relay;

use Gcorradomms\Ohttphp\Relay\OhttpRelayHandler;
use Gcorradomms\Ohttphp\Tests\CallbackHttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

use function array_keys;
use function array_map;
use function sort;
use function strlen;

final class OhttpRelayHandlerTest extends TestCase
{
    private const GATEWAY_URI = 'https://gateway.internal/oblivious/request';
    private const ENCAPSULATED = "\x01\x00\x20\x00\x01\x00\x01" . 'enc-32-bytes-xxxxxxxxxxxxxxxx' . 'ciphertext';

    private Psr17Factory $factory;

    private CallbackHttpClient $downstream;

    private OhttpRelayHandler $handler;

    protected function setUp(): void
    {
        $this->factory = new Psr17Factory();
        $this->downstream = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response(200, ['Content-Type' => 'message/ohttp-res'], "\x00binary-response")
        );
        $this->handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            $this->downstream,
            $this->factory,
            $this->factory,
            $this->factory
        );
    }

    /**
     * @param array<string, string> $headers
     */
    private function relayRequest(string $body, array $headers = []): ServerRequest
    {
        $request = new ServerRequest('POST', 'https://relay.example.org/relay');
        $request = $request->withHeader('Content-Type', 'message/ohttp-req');
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $request->withBody($this->factory->createStream($body));
    }

    public function testForwardsEncapsulatedBodyUnchangedToFixedGateway(): void
    {
        $response = $this->handler->handle($this->relayRequest(self::ENCAPSULATED, [
            'User-Agent' => 'secret-client/1.0',
            'X-Forwarded-For' => '198.51.100.7',
        ]));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertCount(1, $this->downstream->requests);

        $forwarded = $this->downstream->requests[0];
        $this->assertSame('POST', $forwarded->getMethod());
        $this->assertSame(self::GATEWAY_URI, (string) $forwarded->getUri());
        $this->assertSame('message/ohttp-req', $forwarded->getHeaderLine('Content-Type'));
        $this->assertSame(self::ENCAPSULATED, (string) $forwarded->getBody());
    }

    public function testClientIdentifyingHeadersAreNotForwarded(): void
    {
        $this->handler->handle($this->relayRequest(self::ENCAPSULATED, [
            'Forwarded' => 'for=192.0.2.60;proto=http;by=203.0.113.43',
            'X-Forwarded-For' => '192.0.2.43',
            'X-Real-IP' => '192.0.2.99',
            'User-Agent' => 'Mozilla/5.0 identifying',
            'Cookie' => 'session=tracker',
            'Authorization' => 'Bearer leaked',
            'Accept-Language' => 'en-US',
        ]));

        $forwarded = $this->downstream->requests[0];
        $names = array_map('strtolower', array_keys($forwarded->getHeaders()));
        sort($names);
        $this->assertSame(['content-type', 'host'], $names);
    }

    public function testGatewayUriCannotBeOverridden(): void
    {
        // Attempt overrides via query string and headers; both ignored.
        $request = new ServerRequest('POST', 'https://relay.example.org/relay?gateway=http://evil.example/');
        $request = $request->withHeader('Content-Type', 'message/ohttp-req');
        $request = $request->withHeader('X-Gateway-Uri', 'http://evil.example/');
        $request = $request->withBody($this->factory->createStream(self::ENCAPSULATED));

        $this->handler->handle($request);

        $this->assertSame(self::GATEWAY_URI, (string) $this->downstream->requests[0]->getUri());
    }

    public function testStaticUpstreamHeadersAreAdded(): void
    {
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            $this->downstream,
            $this->factory,
            $this->factory,
            $this->factory,
            OhttpRelayHandler::DEFAULT_MAX_REQUEST_SIZE,
            ['X-Internal-Auth' => 'op-secret']
        );

        $handler->handle($this->relayRequest(self::ENCAPSULATED));

        $this->assertSame('op-secret', $this->downstream->requests[0]->getHeaderLine('X-Internal-Auth'));
    }

    public function testRejectsNonPostMethods(): void
    {
        foreach (['GET', 'PUT', 'DELETE'] as $method) {
            $response = $this->handler->handle(new ServerRequest($method, 'https://relay.example.org/relay'));
            $this->assertSame(405, $response->getStatusCode(), $method);
            $this->assertSame('POST', $response->getHeaderLine('Allow'));
        }
    }

    public function testRejectsWrongContentType(): void
    {
        $request = new ServerRequest('POST', 'https://relay.example.org/relay');
        $request = $request->withHeader('Content-Type', 'application/json');

        $this->assertSame(415, $this->handler->handle($request)->getStatusCode());
    }

    public function testRejectsEmptyBody(): void
    {
        $this->assertSame(400, $this->handler->handle($this->relayRequest(''))->getStatusCode());
    }

    public function testRejectsOversizedBody(): void
    {
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            $this->downstream,
            $this->factory,
            $this->factory,
            $this->factory,
            32
        );

        $response = $handler->handle($this->relayRequest(str_repeat('a', 33)));

        $this->assertSame(413, $response->getStatusCode());
        $this->assertCount(0, $this->downstream->requests);
    }

    public function testForwardsGatewayResponseUnchanged(): void
    {
        $binary = "\x00\x01\x02binary-encrypted-payload\x00";
        $this->downstream = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response(200, ['Content-Type' => 'message/ohttp-res'], $binary)
        );
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            $this->downstream,
            $this->factory,
            $this->factory,
            $this->factory
        );

        $response = $handler->handle($this->relayRequest(self::ENCAPSULATED));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($binary, (string) $response->getBody());
        $this->assertSame('message/ohttp-res', $response->getHeaderLine('Content-Type'));
    }

    public function testForwardsGatewayErrorStatuses(): void
    {
        $this->downstream = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response(400, ['Content-Type' => 'application/problem+json'], '{"title":"Invalid request"}')
        );
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            $this->downstream,
            $this->factory,
            $this->factory,
            $this->factory
        );

        $response = $handler->handle($this->relayRequest(self::ENCAPSULATED));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('{"title":"Invalid request"}', (string) $response->getBody());
    }

    public function testStripsUpstreamMetadataFromGatewayResponse(): void
    {
        $this->downstream = new CallbackHttpClient(
            static fn (): ResponseInterface => new Response(
                200,
                [
                    'Content-Type' => 'message/ohttp-res',
                    'Server' => 'internal-gateway/1.2.3',
                    'X-Internal-Trace' => 'secret-trace-id',
                    'Transfer-Encoding' => 'chunked',
                ],
                'payload'
            )
        );
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            $this->downstream,
            $this->factory,
            $this->factory,
            $this->factory
        );

        $response = $handler->handle($this->relayRequest(self::ENCAPSULATED));

        $this->assertFalse($response->hasHeader('Server'));
        $this->assertFalse($response->hasHeader('X-Internal-Trace'));
        $this->assertFalse($response->hasHeader('Transfer-Encoding'));
        $this->assertSame('payload', (string) $response->getBody());
    }

    public function testMapsNetworkFailuresTo502(): void
    {
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            CallbackHttpClient::failingNetwork(),
            $this->factory,
            $this->factory,
            $this->factory
        );

        $response = $handler->handle($this->relayRequest(self::ENCAPSULATED));

        $this->assertSame(502, $response->getStatusCode());
        $this->assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        // The failure detail must not leak upstream internals.
        $this->assertStringNotContainsString('connection refused', (string) $response->getBody());
    }

    public function testMapsGenericClientFailuresTo504(): void
    {
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            CallbackHttpClient::failingTimeout(),
            $this->factory,
            $this->factory,
            $this->factory
        );

        $response = $handler->handle($this->relayRequest(self::ENCAPSULATED));

        $this->assertSame(504, $response->getStatusCode());
    }

    public function testLogsContainNoBodies(): void
    {
        $logger = new \Gcorradomms\Ohttphp\Tests\InMemoryLogger();
        $handler = new OhttpRelayHandler(
            self::GATEWAY_URI,
            $this->downstream,
            $this->factory,
            $this->factory,
            $this->factory,
            OhttpRelayHandler::DEFAULT_MAX_REQUEST_SIZE,
            [],
            $logger
        );

        $handler->handle($this->relayRequest(self::ENCAPSULATED, ['User-Agent' => 'leaky-client']));

        foreach ($logger->records as $record) {
            $this->assertStringNotContainsString('enc-32-bytes', $record['message']);
            $this->assertStringNotContainsString('leaky-client', $record['message']);
        }
    }
}
