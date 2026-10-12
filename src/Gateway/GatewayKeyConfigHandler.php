<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway;

use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigDecoder;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function array_map;
use function count;
use function json_encode;

/**
 * PSR-15 handler that publishes the gateway's active public key
 * configurations in the exact "application/ohttp-keys" binary format of
 * RFC 9458, Section 3.
 *
 * The response contains public key material only. Retired keys are
 * excluded. The endpoint path is a deployment choice; RFC 9458 does not
 * standardize one. In production, configurations must be distributed over
 * an authenticated, integrity-protected channel (normally HTTPS).
 */
final class GatewayKeyConfigHandler implements RequestHandlerInterface
{
    public const CONTENT_TYPE = 'application/ohttp-keys';

    private readonly KeyConfigDecoder $decoder;

    public function __construct(
        private readonly GatewayKeyStoreInterface $keyStore,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {
        $this->decoder = new KeyConfigDecoder();
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'GET') {
            return $this->problemResponse(
                405,
                'Method not allowed',
                'Use GET to retrieve the key configuration.'
            )->withHeader('Allow', 'GET');
        }

        $active = $this->keyStore->active();
        if (count($active) === 0) {
            return $this->problemResponse(503, 'No keys available', 'The gateway has no active keys.');
        }

        $collection = new KeyConfigCollection(
            array_map(static fn (GatewayKeyPair $pair): \Gcorradomms\Ohttphp\KeyConfig\KeyConfig => $pair->keyConfig(), $active)
        );
        $encoded = $this->decoder->encodeCollection($collection);

        return $this->responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', self::CONTENT_TYPE)
            ->withHeader('Cache-Control', 'no-store')
            ->withBody($this->streamFactory->createStream($encoded));
    }

    private function problemResponse(int $status, string $title, string $detail): ResponseInterface
    {
        $body = json_encode(
            ['title' => $title, 'detail' => $detail, 'status' => $status],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );

        return $this->responseFactory
            ->createResponse($status)
            ->withHeader('Content-Type', 'application/problem+json')
            ->withBody($this->streamFactory->createStream($body));
    }
}
