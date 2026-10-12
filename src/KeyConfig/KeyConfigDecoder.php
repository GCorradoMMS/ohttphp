<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\KeyConfig;

use Gcorradomms\Ohttphp\Exception\InvalidKeyConfigurationException;

use function count;
use function ord;
use function pack;
use function strlen;
use function substr;
use function unpack;

/**
 * Parser and validator for OHTTP key configuration encodings (RFC 9458,
 * Sections 3.1 and 3.2).
 *
 * Parsing is deliberately strict. RFC 9458 Section 3.2 requires clients to
 * discard incorrectly encoded key configuration collections in their
 * entirety, because partial recovery differences can be exploited to
 * segregate clients. Any structural error therefore results in an
 * InvalidKeyConfigurationException for the whole collection.
 *
 * Unknown KDF/AEAD identifiers are accepted (they are well-formed), stored
 * as raw values, and never selected. Unknown KEM identifiers are an error:
 * without a known KEM the length of the public key cannot be determined,
 * making the remainder of the encoding unparseable.
 */
final class KeyConfigDecoder
{
    /**
     * Parse an "application/ohttp-keys" collection: one or more key
     * configurations, each prefixed with a 2-byte network-order length.
     *
     * @throws InvalidKeyConfigurationException When the collection is invalid
     */
    public function decodeCollection(string $bytes): KeyConfigCollection
    {
        $configs = [];
        $offset = 0;
        $length = strlen($bytes);
        while ($offset < $length) {
            if ($length - $offset < 2) {
                throw new InvalidKeyConfigurationException('Truncated key configuration length prefix');
            }
            $prefix = unpack('n', substr($bytes, $offset, 2));
            if ($prefix === false || !is_int($prefix[1] ?? null)) {
                throw new InvalidKeyConfigurationException('Malformed key configuration length prefix');
            }
            $configLength = $prefix[1];
            $offset += 2;
            if ($configLength === 0) {
                throw new InvalidKeyConfigurationException('Empty key configuration');
            }
            if ($length - $offset < $configLength) {
                throw new InvalidKeyConfigurationException('Truncated key configuration');
            }
            $configs[] = $this->decodeConfiguration(
                substr($bytes, $offset, $configLength)
            );
            $offset += $configLength;
        }
        if (count($configs) === 0) {
            throw new InvalidKeyConfigurationException('Empty key configuration collection');
        }

        return new KeyConfigCollection($configs);
    }

    /**
     * Parse exactly one key configuration; trailing bytes are an error.
     *
     * @throws InvalidKeyConfigurationException When the configuration is invalid
     */
    public function decodeConfiguration(string $bytes): KeyConfig
    {
        $length = strlen($bytes);
        if ($length < 3) {
            throw new InvalidKeyConfigurationException('Key configuration too short');
        }

        $keyId = ord($bytes[0]);
        $kemRaw = unpack('n', substr($bytes, 1, 2));
        if ($kemRaw === false || !is_int($kemRaw[1] ?? null)) {
            throw new InvalidKeyConfigurationException('Malformed KEM identifier');
        }
        $kemId = KemId::tryFrom($kemRaw[1]);
        if ($kemId === null) {
            throw new InvalidKeyConfigurationException('Unknown HPKE KEM identifier: ' . $kemRaw[1]);
        }

        $publicKeyLength = $kemId->publicKeyLength();
        $publicKeyOffset = 3;
        $suitesOffset = $publicKeyOffset + $publicKeyLength;
        if ($length < $suitesOffset + 2) {
            throw new InvalidKeyConfigurationException('Truncated key configuration');
        }
        $publicKey = substr($bytes, $publicKeyOffset, $publicKeyLength);

        $suitesRaw = unpack('n', substr($bytes, $suitesOffset, 2));
        if ($suitesRaw === false || !is_int($suitesRaw[1] ?? null)) {
            throw new InvalidKeyConfigurationException('Malformed symmetric algorithms length');
        }
        $suitesLength = $suitesRaw[1];
        if ($suitesLength < 4 || $suitesLength % 4 !== 0) {
            throw new InvalidKeyConfigurationException('Invalid symmetric algorithms length');
        }
        if ($length !== $suitesOffset + 2 + $suitesLength) {
            throw new InvalidKeyConfigurationException('Key configuration length mismatch');
        }

        $suites = [];
        for ($offset = $suitesOffset + 2; $offset < $length; $offset += 4) {
            $suiteRaw = unpack('nkdf/naead', substr($bytes, $offset, 4));
            if ($suiteRaw === false || !is_int($suiteRaw['kdf'] ?? null) || !is_int($suiteRaw['aead'] ?? null)) {
                throw new InvalidKeyConfigurationException('Malformed symmetric algorithm entry');
            }
            $suites[] = new SymmetricSuite($suiteRaw['kdf'], $suiteRaw['aead']);
        }

        return new KeyConfig($keyId, $kemId, $publicKey, $suites);
    }

    /**
     * Serialize a collection in the "application/ohttp-keys" format.
     *
     * @param KeyConfigCollection $collection
     */
    public function encodeCollection(KeyConfigCollection $collection): string
    {
        $out = '';
        foreach ($collection as $config) {
            $encoded = $config->bytes();
            $out .= pack('n', strlen($encoded)) . $encoded;
        }

        return $out;
    }
}
