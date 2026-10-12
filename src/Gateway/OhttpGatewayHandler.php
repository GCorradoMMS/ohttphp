<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway;

use Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpDecoder;
use Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpEncoder;
use Gcorradomms\Ohttphp\Exception\KeyStoreException;
use Gcorradomms\Ohttphp\Exception\RequestDecapsulationException;
use Gcorradomms\Ohttphp\Gateway\Target\TargetPolicyInterface;
use Gcorradomms\Ohttphp\Gateway\Target\TargetPolicyViolationException;
use Gcorradomms\Ohttphp\Http\HopByHopHeaders;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Gcorradomms\Ohttphp\Ohttp\OhttpReceiverContext;
use ParagonIE\HPKE\HPKE;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;

use function array_map;
use function is_int;
use function json_encode;
use function pack;
use function strlen;
use function strpos;
use function strtolower;
use function substr;
use function trim;
use function unpack;

/**
 * PSR-15 handler implementing the Oblivious Gateway Resource role
 * (RFC 9458): it decapsulates incoming "message/ohttp-req" requests,
 * forwards the decoded binary HTTP request to the target resource under
 * the configured target access policy, and returns the response in an
 * Encapsulated Response ("message/ohttp-res").
 *
 * Error model:
 * - Failures before decapsulation (bad method, wrong content type,
 *   oversized or malformed payloads, unknown keys, unsupported
 *   algorithms, decryption failures) produce uniform plaintext HTTP 4xx
 *   problem responses. Decryption failures are deliberately
 *   indistinguishable from other processing failures.
 * - Failures after decapsulation (target policy violations, invalid
 *   binary HTTP, target transport errors, oversized target responses)
 *   are returned as Encapsulated Responses so the relay cannot observe
 *   them; the client receives a synthetic problem response.
 *
 * Diagnostics logged through the optional logger contain status codes,
 * key identifiers, and error class names only: never request bodies,
 * target URLs, key material, or cryptographic exception details.
 */
final class OhttpGatewayHandler implements RequestHandlerInterface
{
    public const REQUEST_CONTENT_TYPE = 'message/ohttp-req';
    public const RESPONSE_CONTENT_TYPE = 'message/ohttp-res';

    public const DEFAULT_MAX_ENCAPSULATED_REQUEST_SIZE = 65536;
    public const DEFAULT_MAX_TARGET_RESPONSE_SIZE = 1048576;

    private const READ_CHUNK_SIZE = 65536;

    private readonly BinaryHttpDecoder $decoder;
    private readonly BinaryHttpEncoder $encoder;

    public function __construct(
        private readonly GatewayKeyStoreInterface $keyStore,
        private readonly TargetPolicyInterface $targetPolicy,
        private readonly ClientInterface $targetClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly UriFactoryInterface $uriFactory,
        private readonly int $maxEncapsulatedRequestSize = self::DEFAULT_MAX_ENCAPSULATED_REQUEST_SIZE,
        private readonly int $maxTargetResponseSize = self::DEFAULT_MAX_TARGET_RESPONSE_SIZE,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->decoder = new BinaryHttpDecoder($responseFactory, $streamFactory, $requestFactory, $uriFactory);
        $this->encoder = new BinaryHttpEncoder();
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $method = $request->getMethod();
        if ($method !== 'POST') {
            return $this->plaintextProblem(405, 'Method not allowed', 'POST with an encapsulated request is required.')
                ->withHeader('Allow', 'POST');
        }
        if (!self::isMediaType($request->getHeaderLine('Content-Type'), self::REQUEST_CONTENT_TYPE)) {
            $this->log('warning', 'Rejected request with unexpected content type');
            return $this->plaintextProblem(415, 'Unsupported media type', 'Content-Type must be ' . self::REQUEST_CONTENT_TYPE . '.');
        }

        try {
            $encapsulatedRequest = $this->readBody($request);
        } catch (RuntimeException $e) {
            return $this->plaintextProblem(400, 'Invalid request', 'The request body could not be read.');
        }
        if ($encapsulatedRequest === '') {
            return $this->plaintextProblem(400, 'Invalid request', 'The request body is empty.');
        }
        if (strlen($encapsulatedRequest) > $this->maxEncapsulatedRequestSize) {
            $this->log('warning', 'Rejected oversized encapsulated request');
            return $this->plaintextProblem(413, 'Payload too large', 'The encapsulated request exceeds the size limit.');
        }

        return $this->processEncapsulatedRequest($encapsulatedRequest);
    }

    private function processEncapsulatedRequest(string $encapsulatedRequest): ResponseInterface
    {
        // Parse the 7-byte header: key_id (1), kem_id (2), kdf_id (2), aead_id (2).
        if (strlen($encapsulatedRequest) < OhttpReceiverContext::HEADER_LENGTH) {
            return $this->uniformRejection();
        }
        $header = substr($encapsulatedRequest, 0, OhttpReceiverContext::HEADER_LENGTH);

        $keyId = unpack('C', $header[0]);
        $kemRaw = unpack('n', substr($header, 1, 2));
        $kdfRaw = unpack('n', substr($header, 3, 2));
        $aeadRaw = unpack('n', substr($header, 5, 2));
        if ($keyId === false || $kemRaw === false || $kdfRaw === false || $aeadRaw === false
            || !is_int($keyId[1] ?? null) || !is_int($kemRaw[1] ?? null)
            || !is_int($kdfRaw[1] ?? null) || !is_int($aeadRaw[1] ?? null)) {
            return $this->uniformRejection();
        }

        $kemId = KemId::tryFrom($kemRaw[1]);
        if ($kemId === null) {
            $this->log('warning', 'Encapsulated request used an unknown KEM identifier');
            return $this->uniformRejection();
        }

        // Resolve the key and verify it matches the advertised KEM.
        $keyPair = $this->keyStore->get($keyId[1]);
        if ($keyPair === null || $keyPair->kemId !== $kemId) {
            $this->log('warning', 'Encapsulated request used an unknown key identifier', ['keyId' => $keyId[1]]);
            return $this->uniformRejection();
        }

        // Verify the symmetric suite is advertised by the key and supported.
        $suite = new SymmetricSuite($kdfRaw[1], $aeadRaw[1]);
        if (!$keyPair->keyConfig()->advertises($suite)
            || $suite->supportedKdf() === null
            || $suite->supportedAead() === null) {
            $this->log('warning', 'Encapsulated request used an unsupported algorithm combination', ['keyId' => $keyId[1]]);
            return $this->uniformRejection();
        }

        // Split the encapsulated KEM key and protected payload with strict bounds.
        $encLength = $kemId->publicKeyLength();
        $rest = substr($encapsulatedRequest, OhttpReceiverContext::HEADER_LENGTH);
        if (strlen($rest) < $encLength + $suite->supportedAead()->tagLength()) {
            return $this->uniformRejection();
        }
        $enc = substr($rest, 0, $encLength);
        $ciphertext = substr($rest, $encLength);

        $hpke = new HPKE(
            $kemId->toHpkeKem(),
            $suite->requireKdf()->toHpkeKdf(),
            $suite->requireAead()->toHpkeAead(),
        );

        try {
            [$context, $bhttpRequest] = OhttpReceiverContext::openEncapsulatedRequest(
                $keyPair->secretKey,
                $header,
                $enc,
                $ciphertext,
                $hpke,
            );
        } catch (RequestDecapsulationException $e) {
            $this->log('warning', 'Failed to decapsulate the request', [
                'keyId' => $keyId[1],
                'reason' => $e::class,
            ]);
            return $this->uniformRejection();
        }

        try {
            $targetRequest = $this->decoder->decodeRequest($bhttpRequest);
        } catch (\Gcorradomms\Ohttphp\Exception\BinaryDecodingException $e) {
            $this->log('warning', 'Decapsulated request contained an invalid binary HTTP message');
            return $this->encapsulatedProblem($context, 400, 'Invalid request', 'The request could not be decoded.');
        }

        // Unsupported target forms are rejected explicitly.
        if ($targetRequest->getMethod() === 'CONNECT' || $targetRequest->getRequestTarget() === '*') {
            return $this->encapsulatedProblem($context, 400, 'Unsupported request', 'This request form is not supported.');
        }

        try {
            $this->targetPolicy->enforce($targetRequest->getUri());
        } catch (TargetPolicyViolationException $e) {
            $this->log('warning', 'Target rejected by policy', ['reason' => $e->getMessage()]);
            return $this->encapsulatedProblem($context, 403, 'Forbidden', 'The target resource is not allowed.');
        }

        // Forward to the target: strip hop-by-hop headers (and Host, which
        // is re-derived from the validated URI by the HTTP client).
        $forwardRequest = HopByHopHeaders::strip($targetRequest, true);
        try {
            $targetResponse = $this->targetClient->sendRequest($forwardRequest);
        } catch (NetworkExceptionInterface $e) {
            $this->log('warning', 'Target transport failed', ['reason' => $e::class]);
            return $this->encapsulatedProblem($context, 502, 'Bad gateway', 'The target could not be reached.');
        } catch (ClientExceptionInterface $e) {
            $this->log('warning', 'Target transport error', ['reason' => $e::class]);
            return $this->encapsulatedProblem($context, 504, 'Gateway timeout', 'The target did not respond in time.');
        }

        try {
            $body = $this->readBodyWithLimit($targetResponse, $this->maxTargetResponseSize);
        } catch (BodyTooLargeException) {
            $this->log('warning', 'Target response exceeded the size limit');
            return $this->encapsulatedProblem($context, 502, 'Bad gateway', 'The target response exceeded the size limit.');
        } catch (RuntimeException $e) {
            $this->log('warning', 'Target response could not be read');
            return $this->encapsulatedProblem($context, 502, 'Bad gateway', 'The target response could not be read.');
        }
        $forwardResponse = HopByHopHeaders::strip(
            $targetResponse->withBody($this->streamFactory->createStream($body))
        );

        try {
            $bhttpResponse = $this->encoder->encodeResponse($forwardResponse);
        } catch (\Gcorradomms\Ohttphp\Exception\BinaryEncodingException $e) {
            $this->log('warning', 'Target response could not be encoded');
            return $this->encapsulatedProblem($context, 502, 'Bad gateway', 'The target response could not be encoded.');
        }

        try {
            $encapsulatedResponse = $context->encapsulateResponse($bhttpResponse);
        } catch (\Gcorradomms\Ohttphp\Exception\ResponseEncapsulationException $e) {
            $this->log('error', 'Unable to encapsulate the response');
            return $this->plaintextProblem(500, 'Internal error', 'The exchange could not be completed.');
        }

        $this->log('info', 'Completed oblivious exchange', ['status' => $targetResponse->getStatusCode()]);

        return $this->responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', self::RESPONSE_CONTENT_TYPE)
            ->withBody($this->streamFactory->createStream($encapsulatedResponse));
    }

    /**
     * Uniform rejection for everything that fails before or during
     * decapsulation: clients and relays must not learn why.
     */
    private function uniformRejection(): ResponseInterface
    {
        return $this->plaintextProblem(400, 'Invalid request', 'The encapsulated request could not be processed.');
    }

    private function plaintextProblem(int $status, string $title, string $detail): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse($status)
            ->withHeader('Content-Type', 'application/problem+json')
            ->withBody($this->streamFactory->createStream($this->problemJson($status, $title, $detail)));
    }

    /**
     * A synthetic problem response, encrypted for the client so the relay
     * cannot observe post-decapsulation failures.
     */
    private function encapsulatedProblem(OhttpReceiverContext $context, int $status, string $title, string $detail): ResponseInterface
    {
        $problem = $this->responseFactory
            ->createResponse($status)
            ->withHeader('Content-Type', 'application/problem+json')
            ->withBody($this->streamFactory->createStream($this->problemJson($status, $title, $detail)));
        $bhttpResponse = $this->encoder->encodeResponse($problem);

        try {
            $encapsulated = $context->encapsulateResponse($bhttpResponse);
        } catch (\Gcorradomms\Ohttphp\Exception\ResponseEncapsulationException $e) {
            $this->log('error', 'Unable to encapsulate an error response');
            return $this->plaintextProblem(500, 'Internal error', 'The exchange could not be completed.');
        }

        return $this->responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', self::RESPONSE_CONTENT_TYPE)
            ->withBody($this->streamFactory->createStream($encapsulated));
    }

    private function problemJson(int $status, string $title, string $detail): string
    {
        return json_encode(
            ['title' => $title, 'detail' => $detail, 'status' => $status],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
    }

    private function readBody(ServerRequestInterface $request): string
    {
        $body = $request->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $body->getContents();
    }

    /**
     * @throws BodyTooLargeException When the body exceeds the limit
     * @throws RuntimeException When the response body cannot be read
     */
    private function readBodyWithLimit(ResponseInterface $response, int $limit): string
    {
        $stream = $response->getBody();
        $declared = $stream->getSize();
        if ($declared !== null && $declared > $limit) {
            throw new BodyTooLargeException();
        }

        $buffer = '';
        while (!$stream->eof()) {
            $buffer .= $this->readChunk($stream);
            if (strlen($buffer) > $limit) {
                throw new BodyTooLargeException();
            }
        }

        return $buffer;
    }

    /**
     * @throws RuntimeException When the stream cannot be read
     */
    private function readChunk(\Psr\Http\Message\StreamInterface $stream): string
    {
        if ($stream->eof()) {
            return '';
        }

        return $stream->read(self::READ_CHUNK_SIZE);
    }

    /**
     * Compare a Content-Type header value against a media type, ignoring
     * parameters.
     */
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
