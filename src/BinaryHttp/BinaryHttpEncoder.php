<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\BinaryHttp;

use Gcorradomms\Ohttphp\Exception\BinaryEncodingException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function pack;
use function preg_match;
use function strlen;
use function strtolower;
use function str_contains;

/**
 * Encoder for the known-length message formats of RFC 9292 (Binary HTTP).
 *
 * Requests are encoded with framing indicator 0; responses with framing
 * indicator 1. Empty trailing sections (headers, content, trailers) are
 * omitted ("truncated") as permitted by Section 3.8 of RFC 9292.
 *
 * Not supported:
 * - CONNECT requests (their authority-form request target has no
 *   representation in the request control data of RFC 9292).
 * - Responses with informational (1xx) status codes; PSR-7 responses
 *   represent a single final response.
 */
final class BinaryHttpEncoder
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

    /**
     * Encode a PSR-7 request as a known-length Binary HTTP message.
     *
     * @throws BinaryEncodingException When the request cannot be represented
     */
    public function encodeRequest(RequestInterface $request): string
    {
        if ($request->getMethod() === 'CONNECT') {
            throw new BinaryEncodingException('CONNECT requests are not supported by this encoder');
        }

        $uri = $request->getUri();
        $scheme = $uri->getScheme();
        if ($scheme === '') {
            throw new BinaryEncodingException('Request URI has no scheme');
        }

        $target = $request->getRequestTarget();
        $path = $target === '*'
            ? '*'
            : $uri->getPath() . ($uri->getQuery() !== '' ? '?' . $uri->getQuery() : '');

        $out = pack('C', self::FRAMING_REQUEST);
        $out .= VarInt::encode(strlen($request->getMethod())) . $request->getMethod();
        $out .= VarInt::encode(strlen($scheme)) . $scheme;
        $authority = $uri->getAuthority();
        $out .= VarInt::encode(strlen($authority)) . $authority;
        $out .= VarInt::encode(strlen($path)) . $path;

        return $out . $this->encodeTrailingSections(
            $this->encodeFieldLines($request->getHeaders()),
            (string) $request->getBody()
        );
    }

    /**
     * Encode a PSR-7 response as a known-length Binary HTTP message.
     *
     * @throws BinaryEncodingException When the response cannot be represented
     */
    public function encodeResponse(ResponseInterface $response): string
    {
        $status = $response->getStatusCode();
        if ($status < 200 || $status > 599) {
            throw new BinaryEncodingException(
                'Only final response status codes (200-599) can be encoded; got ' . $status
            );
        }

        $out = pack('C', self::FRAMING_RESPONSE) . VarInt::encode($status);

        return $out . $this->encodeTrailingSections(
            $this->encodeFieldLines($response->getHeaders()),
            (string) $response->getBody()
        );
    }

    /**
     * Encode the header section and content, omitting trailing empty parts
     * per RFC 9292 Section 3.8. The trailer section is always empty for
     * PSR-7 messages, so its length prefix is always omitted.
     */
    private function encodeTrailingSections(string $headers, string $content): string
    {
        if ($headers === '' && $content === '') {
            return '';
        }
        $out = VarInt::encode(strlen($headers)) . $headers;
        if ($content !== '') {
            $out .= VarInt::encode(strlen($content)) . $content;
        }

        return $out;
    }

    /**
     * Encode field lines as length-prefixed name/value pairs. Field names
     * are lowercased per HTTP/2 field name rules.
     *
     * @param array<array-key, array<array-key, string>> $headers
     * @throws BinaryEncodingException When a field line is invalid
     */
    private function encodeFieldLines(array $headers): string
    {
        $out = '';
        foreach ($headers as $name => $values) {
            if (!is_string($name)) {
                throw new BinaryEncodingException('Field names must be strings');
            }
            $lowerName = strtolower($name);
            $this->assertValidFieldName($lowerName);
            foreach ($values as $value) {
                if (str_contains($value, "\r") || str_contains($value, "\n") || str_contains($value, "\0")) {
                    throw new BinaryEncodingException('Invalid characters in field value for ' . $lowerName);
                }
                $out .= VarInt::encode(strlen($lowerName)) . $lowerName;
                $out .= VarInt::encode(strlen($value)) . $value;
            }
        }

        return $out;
    }

    /**
     * Field names must be valid HTTP field names (RFC 9110 tokens) and must
     * not be pseudo-header names reserved by RFC 9292 Section 3.6.
     *
     * @throws BinaryEncodingException When the name is invalid
     */
    private function assertValidFieldName(string $name): void
    {
        if ($name === '' || isset(self::FORBIDDEN_FIELD_NAMES[$name])) {
            throw new BinaryEncodingException('Invalid or forbidden field name: ' . $name);
        }
        if (preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $name) !== 1) {
            throw new BinaryEncodingException('Invalid field name: ' . $name);
        }
    }
}
