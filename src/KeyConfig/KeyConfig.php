<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\KeyConfig;

use Gcorradomms\Ohttphp\Exception\InvalidKeyConfigurationException;
use ParagonIE\HPKE\HPKE;

use function count;
use function pack;
use function strlen;

/**
 * A validated OHTTP key configuration for one key of the Oblivious Gateway
 * Resource (RFC 9458, Section 3.1): a key identifier, a KEM, the gateway
 * public key, and the advertised KDF/AEAD combinations.
 */
final class KeyConfig
{
    /**
     * @param int $keyId 8-bit key identifier
     * @param KemId $kemId The KEM of the public key
     * @param string $publicKey Gateway encapsulation key (Npk bytes)
     * @param list<SymmetricSuite> $symmetricSuites One or more KDF/AEAD pairs
     *
     * @throws InvalidKeyConfigurationException When the configuration is inconsistent
     */
    public function __construct(
        public readonly int $keyId,
        public readonly KemId $kemId,
        public readonly string $publicKey,
        public readonly array $symmetricSuites,
    ) {
        if ($keyId < 0 || $keyId > 0xFF) {
            throw new InvalidKeyConfigurationException('Key identifier must be an 8-bit value');
        }
        if (strlen($publicKey) !== $kemId->publicKeyLength()) {
            throw new InvalidKeyConfigurationException(
                'Public key length does not match the KEM: expected '
                . $kemId->publicKeyLength() . ' bytes, got ' . strlen($publicKey)
            );
        }
        if (count($symmetricSuites) === 0) {
            throw new InvalidKeyConfigurationException('At least one symmetric algorithm is required');
        }
    }

    /**
     * Construct the HPKE suite for a symmetric suite advertised by this
     * configuration.
     *
     * @throws InvalidKeyConfigurationException When the suite is not advertised
     * @throws \Gcorradomms\Ohttphp\Exception\UnsupportedAlgorithmException When the suite is not implemented
     */
    public function toHpkeSuite(SymmetricSuite $suite): HPKE
    {
        $advertised = false;
        foreach ($this->symmetricSuites as $candidate) {
            if ($candidate->equals($suite)) {
                $advertised = true;
                break;
            }
        }
        if (!$advertised) {
            throw new InvalidKeyConfigurationException('Symmetric suite is not advertised by this key configuration');
        }

        return new HPKE(
            $this->kemId->toHpkeKem(),
            $suite->requireKdf()->toHpkeKdf(),
            $suite->requireAead()->toHpkeAead(),
        );
    }

    /**
     * The 7-byte request header for this configuration and suite:
     * key_id (1), kem_id (2), kdf_id (2), aead_id (2), network byte order.
     *
     * @throws InvalidKeyConfigurationException When the suite is not advertised
     * @throws \Gcorradomms\Ohttphp\Exception\UnsupportedAlgorithmException When the suite is not implemented
     */
    public function requestHeader(SymmetricSuite $suite): string
    {
        if (!$this->advertises($suite)) {
            throw new InvalidKeyConfigurationException('Symmetric suite is not advertised by this key configuration');
        }

        return pack(
            'Cnnn',
            $this->keyId,
            $this->kemId->value,
            $suite->requireKdf()->value,
            $suite->requireAead()->value,
        );
    }

    public function advertises(SymmetricSuite $suite): bool
    {
        foreach ($this->symmetricSuites as $candidate) {
            if ($candidate->equals($suite)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Serialize this configuration in the RFC 9458 Section 3.1 format
     * (without the collection length prefix).
     */
    public function bytes(): string
    {
        $suites = '';
        foreach ($this->symmetricSuites as $suite) {
            $suites .= pack('nn', $suite->kdfId, $suite->aeadId);
        }

        return pack('Cn', $this->keyId, $this->kemId->value)
            . $this->publicKey
            . pack('n', strlen($suites))
            . $suites;
    }
}
