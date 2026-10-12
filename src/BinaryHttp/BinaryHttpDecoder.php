<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\BinaryHttp;

use Gcorradomms\Ohttphp\Exception\BinaryDecodingException;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;

use function ord;
use function preg_match;
use function strlen;
use function strtolower;
use function str_contains;
use function str_repeat;
use function str_starts_with;
use function strpos;
use function substr;
use function is_numeric;

/**
 * Strict decoder for the known-length message formats of RFC 9292 (Binary
 * HTTP), producing PSR-7 messages.
 *
 * Behavior notes:
 * - Informational (1xx) responses are rejected; PSR-7 responses represent a
 *   single final response. This is a documented limitation.
 * - Trailer sections are decoded and validated, but dropped: PSR-7 has no
 *   representation for trailers.
 * - Truncation of empty trailing sections is accepted as equivalent to
 *   zero-length sections (RFC 9292 Section 3.8).
 * - Trailing padding must consist solely of zero-valued bytes; anything
 *   else invalidates the message.
 */
final class BinaryHttpDecoder
{
    private const FRAMING_REQUEST = 0;
    private const FRAMING_RESPONSE = 1;

    private const FORBIDDEN_FIELD_NAMES = [
        ':method' => true,
        ':scheme' => true,
        ':authority' => true,
        ':path' => true,
        ':status' => true,
    ];

    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly UriFactoryInterface $uriFactory,
    ) {
    }

    /**
     * Decode a known-length Binary HTTP response into a PSR-7 response.
     *
     * @throws BinaryDecodingException When the message is invalid
     */
    public function decodeResponse(string $bytes): ResponseInterface
    {
        $framing = $this->readFraming($bytes, self::FRAMING_RESPONSE);
        $status = VarInt::decode($bytes, $framing);
        if ($status['value'] < 200 || $status['value'] > 599) {
            throw new BinaryDecodingException('Invalid or informational response status code: ' . $status['value']);
        }

        $response = $this->responseFactory->createResponse($status['value']);

        $headers = $this->sectionLength($bytes, $status['nextOffset']);
        $headersEnd = $headers['nextOffset'] + $headers['length'];
        if ($headersEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Field section extends beyond end of message');
        }
        $response = $this->applyFieldLines($response, $bytes, $headers['nextOffset'], $headersEnd);

        $content = $this->sectionLength($bytes, $headersEnd);
        $contentEnd = $content['nextOffset'] + $content['length'];
        if ($contentEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Content extends beyond end of message');
        }
        $response = $response->withBody(
            $this->streamFactory->createStream(substr($bytes, $content['nextOffset'], $content['length']))
        );

        $trailers = $this->sectionLength($bytes, $contentEnd);
        $trailersEnd = $trailers['nextOffset'] + $trailers['length'];
        if ($trailersEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Field section extends beyond end of message');
        }
        // Trailers are validated but dropped; PSR-7 has no trailer concept.
        $this->readFieldLines($bytes, $trailers['nextOffset'], $trailersEnd);
        $this->assertOnlyZeroPadding($bytes, $trailersEnd);

        return $response;
    }

    /**
     * Decode a known-length Binary HTTP request into a PSR-7 request.
     *
     * @throws BinaryDecodingException When the message is invalid
     */
    public function decodeRequest(string $bytes): RequestInterface
    {
        $framing = $this->readFraming($bytes, self::FRAMING_REQUEST);

        $method = VarInt::decode($bytes, $framing);
        $methodEnd = $method['nextOffset'] + $method['value'];
        if ($methodEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Invalid request method');
        }
        $methodString = substr($bytes, $method['nextOffset'], $method['value']);
        if ($methodString === '') {
            throw new BinaryDecodingException('Empty request method');
        }

        $scheme = VarInt::decode($bytes, $methodEnd);
        $schemeEnd = $scheme['nextOffset'] + $scheme['value'];
        if ($schemeEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Invalid request scheme');
        }
        $schemeString = substr($bytes, $scheme['nextOffset'], $scheme['value']);

        $authority = VarInt::decode($bytes, $schemeEnd);
        $authorityEnd = $authority['nextOffset'] + $authority['value'];
        if ($authorityEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Invalid request authority');
        }
        $authorityString = substr($bytes, $authority['nextOffset'], $authority['value']);

        $path = VarInt::decode($bytes, $authorityEnd);
        $pathEnd = $path['nextOffset'] + $path['value'];
        if ($pathEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Invalid request path');
        }
        $pathString = substr($bytes, $path['nextOffset'], $path['value']);

        $request = $this->requestFactory->createRequest(
            $methodString,
            $this->buildUri($schemeString, $authorityString, $pathString)
        );

        $headers = $this->sectionLength($bytes, $pathEnd);
        $headersEnd = $headers['nextOffset'] + $headers['length'];
        if ($headersEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Field section extends beyond end of message');
        }
        $request = $this->applyFieldLines($request, $bytes, $headers['nextOffset'], $headersEnd);

        $content = $this->sectionLength($bytes, $headersEnd);
        $contentEnd = $content['nextOffset'] + $content['length'];
        if ($contentEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Content extends beyond end of message');
        }
        $request = $request->withBody(
            $this->streamFactory->createStream(substr($bytes, $content['nextOffset'], $content['length']))
        );

        $trailers = $this->sectionLength($bytes, $contentEnd);
        $trailersEnd = $trailers['nextOffset'] + $trailers['length'];
        if ($trailersEnd > strlen($bytes)) {
            throw new BinaryDecodingException('Field section extends beyond end of message');
        }
        $this->readFieldLines($bytes, $trailers['nextOffset'], $trailersEnd);
        $this->assertOnlyZeroPadding($bytes, $trailersEnd);

        return $request;
    }

    /**
     * Read and validate the framing indicator.
     *
     * @return int Offset after the framing indicator
     * @throws BinaryDecodingException
     */
    private function readFraming(string $bytes, int $expected): int
    {
        if (strlen($bytes) === 0 || ord($bytes[0]) !== $expected) {
            throw new BinaryDecodingException('Unexpected framing indicator');
        }

        return 1;
    }

    /**
     * Read the length prefix of a section. Per RFC 9292 Section 3.8, a
     * message may be truncated before any length prefix; a missing prefix
     * is treated as a zero-length section.
     *
     * @return array{length: int, nextOffset: int}
     * @throws BinaryDecodingException
     */
    private function sectionLength(string $bytes, int $offset): array
    {
        if ($offset >= strlen($bytes)) {
            return ['length' => 0, 'nextOffset' => $offset];
        }

        $decoded = VarInt::decode($bytes, $offset);

        return ['length' => $decoded['value'], 'nextOffset' => $decoded['nextOffset']];
    }

    /**
     * Build a PSR-7 URI from binary HTTP request control data. The
     * authority may be empty (RFC 9292 Section 3.4) and may carry an
     * explicit port, with host names or IP-literal ([IPv6]) notation.
     *
     * @throws BinaryDecodingException When the authority is malformed
     */
    private function buildUri(string $scheme, string $authority, string $path): UriInterface
    {
        $uri = $this->uriFactory->createUri();
        if ($scheme !== '') {
            $uri = $uri->withScheme($scheme);
        }
        if ($authority !== '') {
            $host = $authority;
            $port = null;
            if (str_starts_with($authority, '[')) {
                $closing = strpos($authority, ']');
                if ($closing === false) {
                    throw new BinaryDecodingException('Malformed IP-literal authority');
                }
                $host = substr($authority, 0, $closing + 1);
                $rest = substr($authority, $closing + 1);
                if ($rest !== '') {
                    if (!str_starts_with($rest, ':') || !is_numeric(substr($rest, 1))) {
                        throw new BinaryDecodingException('Malformed authority port');
                    }
                    $port = (int) substr($rest, 1);
                }
            } elseif (preg_match('/:[0-9]+$/', $authority) === 1) {
                $separator = (int) strrpos($authority, ':');
                $host = substr($authority, 0, $separator);
                $port = (int) substr($authority, $separator + 1);
            }
            $uri = $uri->withHost(strtolower($host));
            if ($port !== null) {
                $uri = $uri->withPort($port);
            }
        }

        // The request path field carries the path and query together,
        // following the HTTP/2 ":path" pseudo-header semantics.
        $query = '';
        $pathOnly = $path;
        $queryStart = strpos($path, '?');
        if ($queryStart !== false) {
            $pathOnly = substr($path, 0, $queryStart);
            $query = substr($path, $queryStart + 1);
        }

        return $uri->withPath($pathOnly === '' ? '/' : $pathOnly)->withQuery($query);
    }

    /**
     * Decode field lines in the range [$offset, $end) and apply them to the
     * message. Duplicate names produce repeated header lines.
     *
     * @template T of MessageInterface
     * @param T $message
     * @return T
     * @throws BinaryDecodingException
     */
    private function applyFieldLines(MessageInterface $message, string $bytes, int $offset, int $end): MessageInterface
    {
        foreach ($this->readFieldLines($bytes, $offset, $end) as $line) {
            $message = $message->withAddedHeader($line['name'], $line['value']);
        }

        return $message;
    }

    /**
     * Decode field lines in the range [$offset, $end).
     *
     * @return list<array{name: string, value: string}>
     * @throws BinaryDecodingException
     */
    private function readFieldLines(string $bytes, int $offset, int $end): array
    {
        $lines = [];
        while ($offset < $end) {
            $name = VarInt::decode($bytes, $offset);
            $nameEnd = $name['nextOffset'] + $name['value'];
            if ($nameEnd > $end || $name['value'] === 0) {
                throw new BinaryDecodingException('Invalid field line name');
            }
            $nameString = strtolower(substr($bytes, $name['nextOffset'], $name['value']));
            $this->assertValidFieldName($nameString);

            $value = VarInt::decode($bytes, $nameEnd);
            $valueEnd = $value['nextOffset'] + $value['value'];
            if ($valueEnd > $end) {
                throw new BinaryDecodingException('Invalid field line value');
            }
            $valueString = substr($bytes, $value['nextOffset'], $value['value']);

            $lines[] = ['name' => $nameString, 'value' => $valueString];
            $offset = $valueEnd;
        }

        return $lines;
    }

    /**
     * After the final section, only zero-valued padding may remain.
     *
     * @throws BinaryDecodingException
     */
    private function assertOnlyZeroPadding(string $bytes, int $offset): void
    {
        $remaining = substr($bytes, $offset);
        if ($remaining !== '' && $remaining !== str_repeat("\x00", strlen($remaining))) {
            throw new BinaryDecodingException('Non-zero padding at end of message');
        }
    }

    /**
     * Field names must be valid HTTP field names (RFC 9110 tokens) and must
     * not be pseudo-header names reserved by RFC 9292 Section 3.6.
     *
     * @throws BinaryDecodingException When the name is invalid
     */
    private function assertValidFieldName(string $name): void
    {
        if (isset(self::FORBIDDEN_FIELD_NAMES[$name])) {
            throw new BinaryDecodingException('Forbidden pseudo-field name: ' . $name);
        }
        if (preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $name) !== 1) {
            throw new BinaryDecodingException('Invalid field name');
        }
    }
}
