<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Relay;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;

use function json_encode;
use function strlen;
use function strpos;
use function strtolower;
use function substr;
use function trim;

/**
 * PSR-15 handler implementing the Oblivious Relay Resource role
 * (RFC 9458, Section 6.2): it forwards opaque encapsulated requests to a
 * fixed, operator-configured gateway URI and returns the gateway's
 * response without decrypting or inspecting the protected payload.
 *
 * Privacy properties:
 * - The gateway URI is configured by the operator and can never be
 *   influenced by an incoming request.
 * - No client-supplied header is forwarded to the gateway: nothing that
 *   could identify the client (Forwarded, X-Forwarded-For, User-Agent,
 *   cookies, ...) crosses this boundary. Only the protocol-required
 *   Content-Type header plus explicitly configured static upstream
 *   headers are sent.
 * - Encapsulated payloads are forwarded byte for byte; responses from
 *   the gateway are forwarded without modification of the body.
 * - Application logs (optional PSR-3 logger) contain status codes only:
 *   never bodies, gateway-side details, or client identifying data.
 */
final class OhttpRelayHandler implements RequestHandlerInterface
{
    public const REQUEST_CONTENT_TYPE = 'message/ohttp-req';
    public const RESPONSE_CONTENT_TYPE = 'message/ohttp-res';

    public const DEFAULT_MAX_REQUEST_SIZE = 65536;

    /**
     * @param string $gatewayUri The fixed Oblivious Gateway Resource URI
     * @param int $maxEncapsulatedRequestSize Upper bound for the
     *     encapsulated request body in bytes
     * @param array<string, string> $staticUpstreamHeaders Operator-configured
     *     static headers to add to gateway requests (for example an
     *     internal authentication header). Never populated from client input.
     * @param LoggerInterface|null $logger Optional PSR-3 logger receiving
     *     strictly redacted diagnostics
     */
    public function __construct(
        private readonly string $gatewayUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly int $maxEncapsulatedRequestSize = self::DEFAULT_MAX_REQUEST_SIZE,
        private readonly array $staticUpstreamHeaders = [],
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            return $this->problem(405, 'Method not allowed', 'POST with an encapsulated request is required.')
                ->withHeader('Allow', 'POST');
        }
        if (!self::isMediaType($request->getHeaderLine('Content-Type'), self::REQUEST_CONTENT_TYPE)) {
            $this->log('warning', 'Rejected request with unexpected content type');
            return $this->problem(415, 'Unsupported media type', 'Content-Type must be ' . self::REQUEST_CONTENT_TYPE . '.');
        }

        try {
            $body = $this->readBody($request);
        } catch (RuntimeException $e) {
            return $this->problem(400, 'Invalid request', 'The request body could not be read.');
        }
        if ($body === '') {
            return $this->problem(400, 'Invalid request', 'The request body is empty.');
        }
        if (strlen($body) > $this->maxEncapsulatedRequestSize) {
            $this->log('warning', 'Rejected oversized encapsulated request');
            return $this->problem(413, 'Payload too large', 'The encapsulated request exceeds the size limit.');
        }

        // Forward the payload unchanged to the fixed gateway. Deliberately
        // no client header is copied: the relay must not leak identifying
        // metadata across the privacy boundary.
        $upstream = $this->requestFactory
            ->createRequest('POST', $this->gatewayUri)
            ->withHeader('Content-Type', self::REQUEST_CONTENT_TYPE)
            ->withBody($this->streamFactory->createStream($body));
        foreach ($this->staticUpstreamHeaders as $name => $value) {
            $upstream = $upstream->withHeader($name, $value);
        }

        try {
            $gatewayResponse = $this->httpClient->sendRequest($upstream);
        } catch (NetworkExceptionInterface $e) {
            $this->log('warning', 'Gateway transport failure');
            return $this->problem(502, 'Bad gateway', 'The request could not be forwarded.');
        } catch (ClientExceptionInterface $e) {
            $this->log('warning', 'Gateway request failure');
            return $this->problem(504, 'Gateway timeout', 'The gateway did not respond in time.');
        }

        // Forward the gateway response: status and body verbatim, with only
        // the content type carried over. Every other gateway header is
        // upstream metadata the relay does not pass on.
        $status = $gatewayResponse->getStatusCode();
        $response = $this->responseFactory->createResponse($status);
        $contentType = $gatewayResponse->getHeaderLine('Content-Type');
        if ($contentType !== '') {
            $response = $response->withHeader('Content-Type', $contentType);
        }

        try {
            $responseBody = $this->readResponseBody($gatewayResponse);
        } catch (RuntimeException $e) {
            $this->log('warning', 'Gateway response body could not be read');
            return $this->problem(502, 'Bad gateway', 'The gateway response could not be read.');
        }
        $this->log('info', 'Forwarded encapsulated exchange', ['status' => $status]);

        return $response->withBody($this->streamFactory->createStream($responseBody));
    }

    private function readResponseBody(ResponseInterface $response): string
    {
        $body = $response->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $body->getContents();
    }

    private function readBody(ServerRequestInterface $request): string
    {
        $body = $request->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $body->getContents();
    }

    private function problem(int $status, string $title, string $detail): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse($status)
            ->withHeader('Content-Type', 'application/problem+json')
            ->withBody($this->streamFactory->createStream(
                json_encode(
                    ['title' => $title, 'detail' => $detail, 'status' => $status],
                    JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
                )
            ));
    }

    private static function isMediaType(string $headerValue, string $mediaType): bool
    {
        $position = strpos($headerValue, ';');
        $type = $position === false ? $headerValue : substr($headerValue, 0, $position);

        return strtolower(trim($type)) === $mediaType;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function log(string $level, string $message, array $context = []): void
    {
        $this->logger?->log($level, $message, $context);
    }
}
