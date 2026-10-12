<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\BinaryHttp;

use Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpDecoder;
use Gcorradomms\Ohttphp\Exception\BinaryDecodingException;
use Gcorradomms\Ohttphp\Tests\Rfc9458Vectors;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

use function bin2hex;

final class BinaryHttpDecoderTest extends TestCase
{
    private BinaryHttpDecoder $decoder;

    protected function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->decoder = new BinaryHttpDecoder($factory, $factory, $factory, $factory);
    }

    /**
     * RFC 9292 Figure 13: known-length encoding of a response with content
     * and a trailer section.
     */
    public function testDecodesRfc9292Figure13Response(): void
    {
        $response = $this->decoder->decodeResponse(
            Rfc9458Vectors::hex(
                '0140c8001d5468697320636f6e74656e7420636f6e7461696e732043524c462e0d0a0d07747261696c65720474657874'
            )
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('This content contains CRLF.' . "\r\n", (string) $response->getBody());
        $this->assertFalse($response->hasHeader('trailer'));
    }

    /**
     * RFC 9458 Appendix A response: `0140c8`, truncated empty sections.
     */
    public function testDecodesTruncatedMinimalResponse(): void
    {
        $response = $this->decoder->decodeResponse(Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_RESPONSE));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', (string) $response->getBody());
    }

    public function testDecodesResponseWithDuplicateHeaderLines(): void
    {
        $encoded = Rfc9458Vectors::hex(
            '0140c8' // framing + 200
            . '1f' // header section, 31 bytes
            . '04' . bin2hex('link') . '19' . bin2hex('</style.css>; rel=preload')
            . '00' // empty content
        );

        $response = $this->decoder->decodeResponse($encoded);

        $this->assertSame(['</style.css>; rel=preload'], $response->getHeader('link'));
    }

    public function testAcceptsZeroPadding(): void
    {
        $encoded = Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_RESPONSE) . "\x00\x00\x00";

        $response = $this->decoder->decodeResponse($encoded);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testRejectsNonZeroPadding(): void
    {
        $encoded = Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_RESPONSE) . "\x00\x01";

        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse($encoded);
    }

    public function testRejectsUnknownFramingIndicator(): void
    {
        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse(Rfc9458Vectors::hex('02'));
    }

    public function testRejectsEmptyMessage(): void
    {
        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse('');
    }

    public function testRejectsRequestFramingAsResponse(): void
    {
        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse(Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST));
    }

    public function testRejectsInformationalStatus(): void
    {
        // framing 1, status 100 (varint 0x4064), nothing else
        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse(Rfc9458Vectors::hex('014064'));
    }

    public function testRejectsTruncatedContent(): void
    {
        // framing 1, status 200, empty headers, content length 10, only 3 bytes
        $encoded = Rfc9458Vectors::hex('0140c800' . '0a' . bin2hex('abc'));

        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse($encoded);
    }

    public function testRejectsForbiddenPseudoHeader(): void
    {
        // framing 1, status 200, header section (12 bytes) with ":status"
        $encoded = Rfc9458Vectors::hex(
            '0140c8'
            . '0c' . '07' . bin2hex(':status') . '03' . bin2hex('200')
        );

        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse($encoded);
    }

    public function testRejectsInvalidFieldName(): void
    {
        // framing 1, status 200, header section (6 bytes) with a space in the name
        $encoded = Rfc9458Vectors::hex(
            '0140c8'
            . '06' . '02' . bin2hex('a b') . '01' . bin2hex('x')
        );

        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse($encoded);
    }

    public function testRejectsFieldSectionOverrun(): void
    {
        // Header section claims 10 bytes but only 2 follow.
        $encoded = Rfc9458Vectors::hex(
            '0140c8'
            . '0a' . '01' . bin2hex('x')
        );

        $this->expectException(BinaryDecodingException::class);
        $this->decoder->decodeResponse($encoded);
    }

    public function testRoundTripsThroughEncoder(): void
    {
        $factory = new Psr17Factory();
        $original = $factory->createResponse(200, 'OK')
            ->withHeader('Content-Type', 'text/plain')
            ->withAddedHeader('Set-Cookie', 'a=1')
            ->withAddedHeader('Set-Cookie', 'b=2');
        $original = $original->withBody($factory->createStream('payload'));

        $encoded = (new \Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpEncoder())->encodeResponse($original);
        $decoded = $this->decoder->decodeResponse($encoded);

        $this->assertSame(200, $decoded->getStatusCode());
        $this->assertSame('text/plain', $decoded->getHeaderLine('content-type'));
        $this->assertSame(['a=1', 'b=2'], $decoded->getHeader('set-cookie'));
        $this->assertSame('payload', (string) $decoded->getBody());
    }

    public function testDecodesRequestRoundTrip(): void
    {
        $original = Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST);
        $request = $this->decoder->decodeRequest($original);

        $this->assertSame('GET', $request->getMethod());
        $this->assertSame('example.com', $request->getUri()->getAuthority());
        $this->assertSame('/', $request->getRequestTarget());

        $reencoded = (new \Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpEncoder())
            ->encodeRequest($request->withoutHeader('Host'));
        $this->assertSame($original, $reencoded);
    }
}
