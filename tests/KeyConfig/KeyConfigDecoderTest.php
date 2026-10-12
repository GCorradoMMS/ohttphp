<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\KeyConfig;

use Gcorradomms\Ohttphp\Exception\InvalidKeyConfigurationException;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfig;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigDecoder;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigCollection;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Gcorradomms\Ohttphp\Tests\Rfc9458Vectors;
use PHPUnit\Framework\TestCase;

use function bin2hex;
use function count;
use function hex2bin;
use function pack;
use function strlen;
use function substr;

final class KeyConfigDecoderTest extends TestCase
{
    private KeyConfigDecoder $decoder;

    protected function setUp(): void
    {
        $this->decoder = new KeyConfigDecoder();
    }

    public function testDecodesRfc9458AppendixAConfiguration(): void
    {
        $config = $this->decoder->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );

        $this->assertSame(1, $config->keyId);
        $this->assertSame(KemId::DhkemX25519HkdfSha256, $config->kemId);
        $this->assertSame(
            '31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155',
            bin2hex($config->publicKey)
        );
        $this->assertCount(2, $config->symmetricSuites);
        $this->assertTrue($config->symmetricSuites[0]->equals(SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm)));
        $this->assertTrue($config->symmetricSuites[1]->equals(SymmetricSuite::from(KdfId::HkdfSha256, AeadId::ChaCha20Poly1305)));
    }

    public function testDecodesCollection(): void
    {
        $single = Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG);
        $collectionBytes = pack('n', strlen($single)) . $single
            . pack('n', strlen($single)) . $single;

        $collection = $this->decoder->decodeCollection($collectionBytes);

        $this->assertCount(2, $collection);
        $this->assertSame(1, $collection->toArray()[0]->keyId);
    }

    public function testRoundTripsThroughEncoder(): void
    {
        $original = Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG);
        $config = $this->decoder->decodeConfiguration($original);

        $this->assertSame($original, $config->bytes());

        $collection = new KeyConfigCollection([$config]);
        $encoded = $this->decoder->encodeCollection($collection);
        $reparsed = KeyConfigCollection::fromEncoded($encoded);

        $this->assertCount(1, $reparsed);
        $this->assertSame($original, $reparsed->toArray()[0]->bytes());
    }

    public function testRejectsEmptyCollection(): void
    {
        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeCollection('');
    }

    public function testRejectsTruncatedLengthPrefix(): void
    {
        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeCollection("\x00");
    }

    public function testRejectsTruncatedConfiguration(): void
    {
        $single = substr(Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG), 0, -4);

        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeCollection(pack('n', strlen($single)) . $single);
    }

    public function testRejectsLengthLongerThanData(): void
    {
        $single = Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG);

        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeCollection(pack('n', strlen($single) + 1) . $single);
    }

    public function testRejectsTrailingBytesInSingleConfiguration(): void
    {
        $single = Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG);

        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeConfiguration($single . "\x00");
    }

    public function testRejectsUnknownKemIdentifier(): void
    {
        // Same as Appendix A config but kem_id = 0x0030 (unknown).
        $bytes = Rfc9458Vectors::hex('01003031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003');

        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeConfiguration($bytes);
    }

    public function testRejectsZeroSymmetricAlgorithmLength(): void
    {
        // key_id=01, kem=0020, 32-byte key, suites length 0000.
        $bytes = Rfc9458Vectors::hex('01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e7981550000');

        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeConfiguration($bytes);
    }

    public function testRejectsSymmetricAlgorithmLengthNotMultipleOfFour(): void
    {
        $bytes = Rfc9458Vectors::hex('01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500020001');

        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeConfiguration($bytes);
    }

    public function testRejectsPublicKeyLengthMismatch(): void
    {
        // Public key is two bytes short for X25519; the suites that follow
        // remain self-consistent, so only the key length check catches this.
        $bytes = Rfc9458Vectors::hex(
            '01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79'
            . '00080001000100010003'
        );

        $this->expectException(InvalidKeyConfigurationException::class);
        $this->decoder->decodeConfiguration($bytes);
    }

    public function testAcceptsUnknownKdfAeadIdentifiersButNeverSelectsThem(): void
    {
        // Suites: (0x0001, 0x0002) supported; (0x00FF, 0x0003) unknown KDF;
        // (0x0001, 0xFFFF) unknown AEAD.
        $bytes = Rfc9458Vectors::hex(
            '01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155'
            . '000c0001000200ff00030001ffff'
        );

        $config = $this->decoder->decodeConfiguration($bytes);

        $this->assertCount(3, $config->symmetricSuites);
        $this->assertNull($config->symmetricSuites[1]->supportedKdf());
        $this->assertNull($config->symmetricSuites[2]->supportedAead());
        $this->assertNotNull($config->symmetricSuites[0]->supportedKdf());
    }

    public function testKeyConfigConstructorRejectsEmptySuites(): void
    {
        $this->expectException(InvalidKeyConfigurationException::class);
        new KeyConfig(1, KemId::DhkemX25519HkdfSha256, str_repeat("\x00", 32), []);
    }

    public function testKeyConfigConstructorRejectsWrongPublicKeyLength(): void
    {
        $this->expectException(InvalidKeyConfigurationException::class);
        new KeyConfig(
            1,
            KemId::DhkemX25519HkdfSha256,
            str_repeat("\x00", 31),
            [SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm)]
        );
    }

    public function testKeyConfigConstructorRejectsKeyIdentifierOutOfRange(): void
    {
        $this->expectException(InvalidKeyConfigurationException::class);
        new KeyConfig(
            256,
            KemId::DhkemX25519HkdfSha256,
            str_repeat("\x00", 32),
            [SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm)]
        );
    }

    public function testToHpkeSuiteRejectsUnadvertisedSuite(): void
    {
        $config = $this->decoder->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );

        $this->expectException(InvalidKeyConfigurationException::class);
        $config->toHpkeSuite(SymmetricSuite::from(KdfId::HkdfSha384, AeadId::Aes256Gcm));
    }

    public function testRequestHeaderMatchesRfc9458VectorPrefix(): void
    {
        $config = $this->decoder->decodeConfiguration(
            Rfc9458Vectors::hex(Rfc9458Vectors::KEY_CONFIG)
        );

        $header = $config->requestHeader(SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm));

        // From the Encapsulated Request: 01 0020 0001 0001.
        $this->assertSame('01002000010001', bin2hex($header));
        $this->assertSame(7, strlen($header));
    }

    public function testCollectionRequiresNonEmptyList(): void
    {
        $this->expectException(InvalidKeyConfigurationException::class);
        new KeyConfigCollection([]);
    }
}
