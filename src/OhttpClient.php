<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp;

use Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpDecoder;
use Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpEncoder;
use Gcorradomms\Ohttphp\Exception\RelayException;
use Gcorradomms\Ohttphp\Exception\UnsupportedAlgorithmException;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfig;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Gcorradomms\Ohttphp\Ohttp\Encapsulation;
use Gcorradomms\Ohttphp\Ohttp\OhttpContext;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
use RuntimeException;

use function is_string;

/**
 * Oblivious HTTP client (RFC 9458).
 *
 * Sends an HTTP request to a target through an Oblivious Relay Resource so
 * that the relay learns neither the request contents nor the target
 * identity, and the Oblivious Gateway Resource learns only the relay, not
 * the client.
 *
 * The client accepts any PSR-18 HTTP client for talking to the relay, and
 * PSR-17 factories for constructing messages. Cryptographic operations are
 * delegated to paragonie/hpke (RFC 9180).
 *
 * Supported HPKE suites (all combinations of):
 * - KEM: DHKEM(X25519, HKDF-SHA256), DHKEM(P-256, HKDF-SHA256),
 *   DHKEM(P-384, HKDF-SHA256), DHKEM(P-521, HKDF-SHA512)
 * - KDF: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512
 * - AEAD: AES-128-GCM, AES-256-GCM, ChaCha20Poly1305
 */
final class OhttpClient
{
    private const RELAY_CONTENT_TYPE = 'message/ohttp-req';

    private readonly BinaryHttpEncoder $encoder;
    private readonly BinaryHttpDecoder $decoder;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly UriFactoryInterface $uriFactory,
    ) {
        $this->encoder = new BinaryHttpEncoder();
        $this->decoder = new BinaryHttpDecoder(
            $responseFactory,
            $streamFactory,
            $requestFactory,
            $uriFactory,
        );
    }

    /**
     * Perform a complete Oblivious HTTP exchange: encapsulate the target
     * request, send it to the Oblivious Relay Resource, and decrypt the
     * encapsulated response.
     *
     * @param RequestInterface $targetRequest The request for the target server
     * @param KeyConfigCollection $keyConfigs Key configurations of the
     *     Oblivious Gateway Resource; the first fully supported
     *     configuration and symmetric suite is selected
     * @param string|UriInterface $relayUri URI of the Oblivious Relay Resource
     * @param array<string, string|array<int, string>> $relayRequestHeaders
     *     Additional headers for the request to the relay. These MUST NOT
     *     depend on the encapsulated request (RFC 9458, Section 5).
     *
     * @throws UnsupportedAlgorithmException When no advertised suite is supported
     * @throws \Gcorradomms\Ohttphp\Exception\EncapsulationException When HPKE
     *     encapsulation fails
     * @throws RelayException When the relay exchange fails
     * @throws \Gcorradomms\Ohttphp\Exception\ResponseDecryptionException When
     *     the encapsulated response cannot be decrypted
     * @throws \Gcorradomms\Ohttphp\Exception\BinaryDecodingException When the
     *     decrypted response is not a valid binary HTTP message
     * @throws \Gcorradomms\Ohttphp\Exception\InvalidKeyConfigurationException
     *     When a key configuration is malformed
     */
    public function send(
        RequestInterface $targetRequest,
        KeyConfigCollection $keyConfigs,
        string|UriInterface $relayUri,
        array $relayRequestHeaders = [],
    ): ResponseInterface {
        $encapsulation = $this->encapsulate($targetRequest, $keyConfigs);
        $relayResponse = $this->sendToRelay(
            $encapsulation->encapsulatedRequest,
            is_string($relayUri) ? $relayUri : (string) $relayUri,
            $relayRequestHeaders
        );

        return $this->decapsulateResponse($encapsulation->context, $relayResponse);
    }

    /**
     * Encode the target request as binary HTTP and encapsulate it for the
     * gateway (RFC 9458, Section 4.3). The returned context is required to
     * decrypt the eventual encapsulated response; keep it until the
     * exchange completes.
     *
     * @throws UnsupportedAlgorithmException When no advertised suite is supported
     * @throws \Gcorradomms\Ohttphp\Exception\EncapsulationException When HPKE
     *     encapsulation fails
     * @throws \Gcorradomms\Ohttphp\Exception\BinaryEncodingException When the
     *     request cannot be encoded as binary HTTP
     * @throws \Gcorradomms\Ohttphp\Exception\InvalidKeyConfigurationException
     *     When a key configuration is malformed
     */
    public function encapsulate(RequestInterface $targetRequest, KeyConfigCollection $keyConfigs): Encapsulation
    {
        // RFC 9458, Section 6.5.1: clients SHOULD include a Date header
        // field in encapsulated requests to support gateway anti-replay.
        if (!$targetRequest->hasHeader('Date')) {
            $targetRequest = $targetRequest->withAddedHeader('Date', gmdate('D, d M Y H:i:s') . ' GMT');
        }

        $bhttpRequest = $this->encoder->encodeRequest($targetRequest);
        [$config, $suite] = $this->selectSupported($keyConfigs);
        [$context, $encapsulatedRequest] = OhttpContext::encapsulateRequest($config, $suite, $bhttpRequest);

        return new Encapsulation($context, $encapsulatedRequest);
    }

    /**
     * Decrypt an Encapsulated Response with the context from encapsulate()
     * and decode the binary HTTP response into a PSR-7 response
     * (RFC 9458, Section 4.4, client side).
     *
     * @throws \Gcorradomms\Ohttphp\Exception\ResponseDecryptionException When
     *     the encapsulated response cannot be decrypted
     * @throws \Gcorradomms\Ohttphp\Exception\BinaryDecodingException When the
     *     decrypted response is not a valid binary HTTP message
     */
    public function decapsulateResponse(OhttpContext $context, string $encapsulatedResponse): ResponseInterface
    {
        $bhttpResponse = $context->decapsulateResponse($encapsulatedResponse);

        return $this->decoder->decodeResponse($bhttpResponse);
    }

    /**
     * Send an Encapsulated Request to the Oblivious Relay Resource and
     * return the raw body of the relay's response.
     *
     * @param string $encapsulatedRequest
     * @param string $relayUri
     * @param array<string, string|array<int, string>> $relayRequestHeaders
     * @return string The encapsulated response bytes
     * @throws RelayException
     */
    private function sendToRelay(string $encapsulatedRequest, string $relayUri, array $relayRequestHeaders): string
    {
        $relayRequest = $this->requestFactory
            ->createRequest('POST', $relayUri)
            ->withHeader('Content-Type', self::RELAY_CONTENT_TYPE)
            ->withBody($this->streamFactory->createStream($encapsulatedRequest));
        foreach ($relayRequestHeaders as $name => $value) {
            $relayRequest = $relayRequest->withHeader($name, $value);
        }

        try {
            $relayResponse = $this->httpClient->sendRequest($relayRequest);
            $status = $relayResponse->getStatusCode();
            if ($status !== 200) {
                throw new RelayException('Oblivious Relay Resource returned status code ' . $status);
            }

            return $this->readBody($relayResponse);
        } catch (ClientExceptionInterface | RuntimeException $e) {
            if ($e instanceof RelayException) {
                throw $e;
            }
            throw new RelayException('Failed to exchange with the Oblivious Relay Resource: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @param ResponseInterface $response
     */
    private function readBody(ResponseInterface $response): string
    {
        $body = $response->getBody();
        try {
            if ($body->isSeekable()) {
                $body->rewind();
            }

            return $body->getContents();
        } catch (RuntimeException $e) {
            throw new RelayException('Failed to read the relay response body: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Select the first key configuration and symmetric suite that this
     * library fully supports, preserving the order in which the gateway
     * advertised them (RFC 9458, Section 3).
     *
     * @return array{0: KeyConfig, 1: SymmetricSuite}
     * @throws UnsupportedAlgorithmException
     */
    private function selectSupported(KeyConfigCollection $keyConfigs): array
    {
        foreach ($keyConfigs as $config) {
            foreach ($config->symmetricSuites as $suite) {
                if ($suite->supportedKdf() !== null && $suite->supportedAead() !== null) {
                    return [$config, $suite];
                }
            }
        }

        throw new UnsupportedAlgorithmException('No key configuration advertises a supported HPKE suite');
    }
}
