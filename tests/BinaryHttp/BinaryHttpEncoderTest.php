<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\BinaryHttp;

use Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpEncoder;
use Gcorradomms\Ohttphp\Exception\BinaryEncodingException;
use Gcorradomms\Ohttphp\Tests\Rfc9458Vectors;
use Gcorradomms\Ohttphp\Tests\UnvalidatedRequest;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;

use function bin2hex;

final class BinaryHttpEncoderTest extends TestCase
{
    private BinaryHttpEncoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new BinaryHttpEncoder();
    }

    /**
     * The RFC 9458 Appendix A binary HTTP request, which truncates the
     * empty header, content, and trailer sections.
     */
    public function testEncodesRfc9458ExampleRequest(): void
    {
        $request = new Request('GET', 'https://example.com/');
        $request = $request->withoutHeader('Host');

        $encoded = $this->encoder->encodeRequest($request);

        $this->assertSame(Rfc9458Vectors::BHTTP_REQUEST, bin2hex($encoded));
    }

    /**
     * RFC 9292 Figure 8: known-length encoding of a GET request with
     * headers, empty authority, and explicit empty content and trailer
     * sections. Truncation is permitted but not required, so the decoder
     * (not the encoder) is authoritative for this vector.
     */
    public function testDecodesRfc9292Figure8Request(): void
    {
        $encoded = Rfc9458Vectors::hex(
            '0003474554056874747073000a2f68656c6c6f2e747874406c0a757365722d6167656e74'
            . '346375726c2f372e31362e33206c69626375726c2f372e31362e3320'
            . '4f70656e53534c2f302e392e376c207a6c69622f312e322e3304686f'
            . '73740f7777772e6578616d706c652e636f6d0f6163636570742d6c61'
            . '6e677561676506656e2c206d690000'
        );

        $decoder = new \Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpDecoder(
            new \Nyholm\Psr7\Factory\Psr17Factory(),
            new \Nyholm\Psr7\Factory\Psr17Factory(),
            new \Nyholm\Psr7\Factory\Psr17Factory(),
            new \Nyholm\Psr7\Factory\Psr17Factory(),
        );
        $request = $decoder->decodeRequest($encoded);

        $this->assertSame('GET', $request->getMethod());
        $this->assertSame('https', $request->getUri()->getScheme());
        $this->assertSame('', $request->getUri()->getAuthority());
        $this->assertSame('/hello.txt', $request->getRequestTarget());
        $this->assertSame('curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3', $request->getHeaderLine('User-Agent'));
        $this->assertSame('www.example.com', $request->getHeaderLine('Host'));
        $this->assertSame('en, mi', $request->getHeaderLine('Accept-Language'));
        $this->assertSame('', (string) $request->getBody());
    }

    public function testEncodesRequestWithHeadersAndContent(): void
    {
        $request = new Request(
            'POST',
            'https://example.com/api?x=1',
            ['Content-Type' => ['text/plain'], 'X-Test' => ['a', 'b']],
            'hello'
        );
        $request = $request->withoutHeader('Host');

        $encoded = $this->encoder->encodeRequest($request);

        $fieldLines = "\x0c" . 'content-type' . "\x0a" . 'text/plain'
            . "\x06" . 'x-test' . "\x01" . 'a'
            . "\x06" . 'x-test' . "\x01" . 'b';
        $expected = "\x00"
            . "\x04" . 'POST'
            . "\x05" . 'https'
            . "\x0b" . 'example.com'
            . "\x08" . '/api?x=1'
            . "\x2a" . $fieldLines
            . "\x05" . 'hello';

        $this->assertSame($expected, $encoded);
    }

    public function testEncodesResponseWithRfc9292Figure13Semantics(): void
    {
        $response = new Response(200, [], 'This content contains CRLF.' . "\r\n");

        $encoded = $this->encoder->encodeResponse($response);

        // Figure 13 emits explicit zero-length headers and a trailer section;
        // this encoder truncates the empty trailer. Semantics are identical.
        $expected = "\x01"
            . "\x40\xc8" // status 200
            . "\x00" // empty headers
            . "\x1d" . 'This content contains CRLF.' . "\r\n";

        $this->assertSame(bin2hex($expected), bin2hex($encoded));
    }

    public function testLowercasesAndPreservesDuplicateHeaderLines(): void
    {
        $request = new Request('GET', 'https://example.com/', ['X-THINGS' => ['one', 'two']]);
        $request = $request->withoutHeader('Host');

        $encoded = $this->encoder->encodeRequest($request);

        $this->assertStringContainsString('x-things', $encoded);
        $this->assertSame(2, substr_count($encoded, 'x-things'));
    }

    public function testRejectsConnectRequests(): void
    {
        $request = new Request('CONNECT', 'example.com:443');

        $this->expectException(BinaryEncodingException::class);
        $this->encoder->encodeRequest($request);
    }

    public function testRejectsForbiddenPseudoHeaderNames(): void
    {
        $request = (new UnvalidatedRequest())->withAddedHeader(':method', ['GET']);

        $this->expectException(BinaryEncodingException::class);
        $this->encoder->encodeRequest($request);
    }

    public function testRejectsInvalidFieldNameCharacters(): void
    {
        $request = (new UnvalidatedRequest())->withAddedHeader('Bad Header', ['x']);

        $this->expectException(BinaryEncodingException::class);
        $this->encoder->encodeRequest($request);
    }

    public function testRejectsHeaderValueWithLineBreaks(): void
    {
        $request = (new UnvalidatedRequest())->withAddedHeader('X-Evil', ["a\r\nb"]);

        $this->expectException(BinaryEncodingException::class);
        $this->encoder->encodeRequest($request);
    }

    public function testRejectsSchemeLessRequest(): void
    {
        $request = new Request('GET', '/relative');

        $this->expectException(BinaryEncodingException::class);
        $this->encoder->encodeRequest($request);
    }

    public function testRejectsInformationalResponseStatus(): void
    {
        $this->expectException(BinaryEncodingException::class);
        $this->encoder->encodeResponse(new Response(103));
    }

    public function testEncodesAsteriskFormOptionsRequest(): void
    {
        $request = new Request('OPTIONS', 'https://example.com');
        $request = $request->withRequestTarget('*')->withoutHeader('Host');

        $encoded = $this->encoder->encodeRequest($request);

        $expected = "\x00\x07OPTIONS\x05https\x0bexample.com\x01*";
        $this->assertSame(bin2hex($expected), bin2hex($encoded));
    }
}
