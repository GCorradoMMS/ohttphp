<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\Ohttp;

use Gcorradomms\Ohttphp\Exception\RequestDecapsulationException;
use Gcorradomms\Ohttphp\Ohttp\OhttpContext;
use Gcorradomms\Ohttphp\Ohttp\OhttpReceiverContext;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigDecoder;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Gcorradomms\Ohttphp\Tests\Rfc9458Vectors;
use ParagonIE\HPKE\AEAD\AES128GCM;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PHPUnit\Framework\TestCase;

use function bin2hex;
use function str_repeat;
use function strlen;
use function substr;

/**
 * Gateway-side (receiver) interoperability against RFC 9458, Appendix A.
 */
final class OhttpReceiverContextTest extends TestCase
{
    private DecapsKey $gatewaySecretKey;

    private HPKE $suite;

    protected function setUp(): void
    {
        $this->gatewaySecretKey = new DecapsKey(
            Curve::X25519,
            Rfc9458Vectors::hex(Rfc9458Vectors::GATEWAY_SECRET_KEY)
        );
        $this->suite = new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );
    }

    /**
     * @return array{0: string, 1: string, 2: string} header, enc, ciphertext
     */
    private function splitVectorRequest(): array
    {
        $encapsulated = Rfc9458Vectors::hex(Rfc9458Vectors::ENCAPSULATED_REQUEST);

        return [
            substr($encapsulated, 0, 7),
            substr($encapsulated, 7, 32),
            substr($encapsulated, 39),
        ];
    }

    public function testOpensRfc9458VectorRequest(): void
    {
        [$header, $enc, $ciphertext] = $this->splitVectorRequest();

        [$context, $bhttpRequest] = OhttpReceiverContext::openEncapsulatedRequest(
            $this->gatewaySecretKey,
            $header,
            $enc,
            $ciphertext,
            $this->suite,
        );

        $this->assertSame(Rfc9458Vectors::BHTTP_REQUEST, bin2hex($bhttpRequest));
        $this->assertSame(substr(Rfc9458Vectors::ENCAPSULATED_REQUEST, 0, 14), bin2hex($context->header()));
        $this->assertSame(
            Rfc9458Vectors::EPHEMERAL_PUBLIC_KEY,
            bin2hex($context->encapsulationKey())
        );
    }

    /**
     * With the RFC's deterministic response nonce, the gateway must produce
     * the exact Encapsulated Response from the RFC, and the client side of
     * the library must decrypt it.
     */
    public function testEncapsulatesRfc9458VectorResponse(): void
    {
        [$header, $enc, $ciphertext] = $this->splitVectorRequest();

        [$context] = OhttpReceiverContext::openEncapsulatedRequest(
            $this->gatewaySecretKey,
            $header,
            $enc,
            $ciphertext,
            $this->suite,
        );

        $encapsulatedResponse = $context->encapsulateResponse(
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_RESPONSE),
            fn (int $length): string => Rfc9458Vectors::hex(Rfc9458Vectors::RESPONSE_NONCE)
        );

        $this->assertSame(Rfc9458Vectors::ENCAPSULATED_RESPONSE, bin2hex($encapsulatedResponse));

        // The existing client API must accept and decrypt it.
        $config = (new KeyConfigDecoder())->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );
        $deterministicClient = new HPKE(
            new \Gcorradomms\Ohttphp\Tests\DeterministicKem(
                Curve::X25519,
                new HKDF(Hash::Sha256),
                Rfc9458Vectors::hex(Rfc9458Vectors::EPHEMERAL_SECRET_KEY)
            ),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );
        [$clientContext] = OhttpContext::encapsulateRequest(
            $config,
            SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm),
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST),
            $deterministicClient,
        );

        $this->assertSame(
            Rfc9458Vectors::BHTTP_RESPONSE,
            bin2hex($clientContext->decapsulateResponse($encapsulatedResponse))
        );
    }

    /**
     * Full exchange with fresh random keys in both roles: the client
     * context from a random encapsulation decrypts the response produced
     * by the receiver context that opened the same encapsulation.
     */
    public function testRoundTripWithRandomKeys(): void
    {
        $config = (new KeyConfigDecoder())->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );

        // Client side with a random ephemeral.
        [$clientContext, $encapsulatedRequest] = OhttpContext::encapsulateRequest(
            $config,
            SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm),
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST),
        );

        $header = substr($encapsulatedRequest, 0, 7);
        $enc = substr($encapsulatedRequest, 7, 32);
        $ciphertext = substr($encapsulatedRequest, 39);

        // Gateway side: open the same encapsulated request.
        [$receiverContext, $opened] = OhttpReceiverContext::openEncapsulatedRequest(
            $this->gatewaySecretKey,
            $header,
            $enc,
            $ciphertext,
            $this->suite,
        );
        $this->assertSame(Rfc9458Vectors::BHTTP_REQUEST, bin2hex($opened));

        $encapsulatedResponse = $receiverContext->encapsulateResponse(
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_RESPONSE)
        );

        $this->assertSame(16 + 3 + 16, strlen($encapsulatedResponse));
        $this->assertSame(
            Rfc9458Vectors::BHTTP_RESPONSE,
            bin2hex($clientContext->decapsulateResponse($encapsulatedResponse))
        );
    }

    public function testRejectsCorruptedCiphertextUniformly(): void
    {
        [$header, $enc, $ciphertext] = $this->splitVectorRequest();
        $corrupted = $ciphertext;
        $corrupted[0] = $corrupted[0] ^ "\x01";

        $this->expectException(RequestDecapsulationException::class);
        $this->expectExceptionMessage('Unable to process the encapsulated request');
        OhttpReceiverContext::openEncapsulatedRequest(
            $this->gatewaySecretKey,
            $header,
            $enc,
            $corrupted,
            $this->suite,
        );
    }

    public function testRejectsWrongKey(): void
    {
        [$header, $enc, $ciphertext] = $this->splitVectorRequest();
        $wrongKey = new DecapsKey(Curve::X25519, str_repeat("\x07", 32));

        $this->expectException(RequestDecapsulationException::class);
        OhttpReceiverContext::openEncapsulatedRequest(
            $wrongKey,
            $header,
            $enc,
            $ciphertext,
            $this->suite,
        );
    }

    public function testRejectsShortEncapsulationKey(): void
    {
        [$header, , $ciphertext] = $this->splitVectorRequest();

        $this->expectException(RequestDecapsulationException::class);
        OhttpReceiverContext::openEncapsulatedRequest(
            $this->gatewaySecretKey,
            $header,
            str_repeat("\x00", 31),
            $ciphertext,
            $this->suite,
        );
    }

    public function testRejectsMalformedHeader(): void
    {
        [, $enc, $ciphertext] = $this->splitVectorRequest();

        $this->expectException(RequestDecapsulationException::class);
        OhttpReceiverContext::openEncapsulatedRequest(
            $this->gatewaySecretKey,
            'short',
            $enc,
            $ciphertext,
            $this->suite,
        );
    }

    public function testRejectsSecondResponseEncapsulation(): void
    {
        [$header, $enc, $ciphertext] = $this->splitVectorRequest();
        [$context] = OhttpReceiverContext::openEncapsulatedRequest(
            $this->gatewaySecretKey,
            $header,
            $enc,
            $ciphertext,
            $this->suite,
        );
        $context->encapsulateResponse(Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_RESPONSE));

        $this->expectException(\Gcorradomms\Ohttphp\Exception\ResponseEncapsulationException::class);
        $context->encapsulateResponse(Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_RESPONSE));
    }
}
