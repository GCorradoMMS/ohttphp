<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\Ohttp;

use Gcorradomms\Ohttphp\Exception\ResponseDecryptionException;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigDecoder;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Gcorradomms\Ohttphp\Ohttp\OhttpContext;
use Gcorradomms\Ohttphp\Tests\DeterministicKem;
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
use function substr;

/**
 * Interoperability test against RFC 9458, Appendix A (Complete Example of
 * a Request and Response), suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * AES-128-GCM.
 */
final class Rfc9458AppendixATest extends TestCase
{
    private KeyConfigDecoder $decoder;

    protected function setUp(): void
    {
        $this->decoder = new KeyConfigDecoder();
    }

    /**
     * Encapsulate the RFC 9458 example request with the RFC's ephemeral
     * client key and compare every intermediate value and the final
     * Encapsulated Request byte for byte.
     */
    public function testEncapsulationMatchesRfc9458Vector(): void
    {
        $config = $this->decoder->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );
        $suite = SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm);

        $deterministicHpke = new HPKE(
            new DeterministicKem(Curve::X25519, new HKDF(Hash::Sha256), Rfc9458Vectors::hex(Rfc9458Vectors::EPHEMERAL_SECRET_KEY)),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );

        [$context, $encapsulatedRequest] = OhttpContext::encapsulateRequest(
            $config,
            $suite,
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST),
            $deterministicHpke,
        );

        // The Encapsulated Request must match the RFC byte for byte.
        $this->assertSame(
            Rfc9458Vectors::ENCAPSULATED_REQUEST,
            bin2hex($encapsulatedRequest)
        );

        // Header and encapsulation key components.
        $this->assertSame('01002000010001', bin2hex($context->header()));
        $this->assertSame(
            Rfc9458Vectors::EPHEMERAL_PUBLIC_KEY,
            bin2hex($context->encapsulationKey())
        );
    }

    /**
     * Derive the response keys from the exporter secret of the deterministic
     * context and verify them against every intermediate value in the RFC.
     */
    public function testResponseDerivationMatchesRfc9458Vector(): void
    {
        $config = $this->decoder->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );
        $suite = SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm);

        $deterministicHpke = new HPKE(
            new DeterministicKem(Curve::X25519, new HKDF(Hash::Sha256), Rfc9458Vectors::hex(Rfc9458Vectors::EPHEMERAL_SECRET_KEY)),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );

        [$context] = OhttpContext::encapsulateRequest(
            $config,
            $suite,
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST),
            $deterministicHpke,
        );

        // Decrypt the RFC's Encapsulated Response: this transitively proves
        // the exporter secret, salt, PRK, AEAD key, and AEAD nonce all match.
        $bhttpResponse = $context->decapsulateResponse(
            Rfc9458Vectors::hex(Rfc9458Vectors::ENCAPSULATED_RESPONSE)
        );

        $this->assertSame(Rfc9458Vectors::BHTTP_RESPONSE, bin2hex($bhttpResponse));
    }

    /**
     * Independently reproduce the exporter secret from the RFC's gateway
     * secret key using the receiver role, proving cross-role agreement.
     */
    public function testExporterSecretMatchesReceiverSide(): void
    {
        $gatewaySecret = new DecapsKey(Curve::X25519, Rfc9458Vectors::hex(Rfc9458Vectors::GATEWAY_SECRET_KEY));
        $hpke = new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );

        $encapsulatedRequest = Rfc9458Vectors::hex(Rfc9458Vectors::ENCAPSULATED_REQUEST);
        $enc = substr($encapsulatedRequest, 7, 32);
        $ciphertext = substr($encapsulatedRequest, 39);

        $receiver = $hpke->setupBaseReceiver(
            $gatewaySecret,
            $enc,
            Rfc9458Vectors::hex(Rfc9458Vectors::HPKE_INFO)
        );

        // Receiver opens the request ciphertext to the exact binary HTTP bytes.
        $this->assertSame(
            Rfc9458Vectors::BHTTP_REQUEST,
            bin2hex($receiver->open($ciphertext, ''))
        );

        // The receiver-side exporter secret matches the RFC value.
        $this->assertSame(
            Rfc9458Vectors::EXPORTED_SECRET,
            bin2hex($receiver->export('message/bhttp response', 16))
        );

        // And the raw KDF chain matches every RFC intermediate value.
        $kdf = new HKDF(Hash::Sha256);
        $prk = $kdf->extract(
            Rfc9458Vectors::hex(Rfc9458Vectors::EXPORTED_SECRET),
            Rfc9458Vectors::hex(Rfc9458Vectors::RESPONSE_SALT)
        );
        $this->assertSame(Rfc9458Vectors::RESPONSE_PRK, bin2hex($prk));
        $this->assertSame(
            Rfc9458Vectors::RESPONSE_AEAD_KEY,
            bin2hex($kdf->expand($prk, 'key', 16))
        );
        $this->assertSame(
            Rfc9458Vectors::RESPONSE_AEAD_NONCE,
            bin2hex($kdf->expand($prk, 'nonce', 12))
        );
    }

    /**
     * With a fresh random ephemeral key, the gateway's secret key must still
     * decrypt the encapsulated request to the exact original message.
     */
    public function testEncapsulationIsInteroperableWithRandomEphemeralKey(): void
    {
        $config = $this->decoder->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );
        $suite = SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm);

        [$context, $encapsulatedRequest] = OhttpContext::encapsulateRequest(
            $config,
            $suite,
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST),
        );

        $gatewaySecret = new DecapsKey(Curve::X25519, Rfc9458Vectors::hex(Rfc9458Vectors::GATEWAY_SECRET_KEY));
        $hpke = new HPKE(
            new DiffieHellmanKEM(Curve::X25519, new HKDF(Hash::Sha256)),
            new HKDF(Hash::Sha256),
            new AES128GCM(),
        );

        $enc = substr($encapsulatedRequest, 7, 32);
        $ciphertext = substr($encapsulatedRequest, 39);

        $receiver = $hpke->setupBaseReceiver(
            $gatewaySecret,
            $enc,
            Rfc9458Vectors::hex(Rfc9458Vectors::HPKE_INFO)
        );

        $this->assertSame(
            Rfc9458Vectors::BHTTP_REQUEST,
            bin2hex($receiver->open($ciphertext, ''))
        );

        // The context cannot decrypt two responses.
        $this->expectException(ResponseDecryptionException::class);
        $context->decapsulateResponse(str_repeat('a', 32));
    }

    public function testRejectsShortEncapsulatedResponse(): void
    {
        $config = $this->decoder->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );
        $suite = SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm);

        [$context] = OhttpContext::encapsulateRequest(
            $config,
            $suite,
            Rfc9458Vectors::hex(Rfc9458Vectors::BHTTP_REQUEST),
        );

        $this->expectException(ResponseDecryptionException::class);
        $context->decapsulateResponse('short');
    }
}
