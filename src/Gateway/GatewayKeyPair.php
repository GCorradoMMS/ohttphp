<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway;

use Gcorradomms\Ohttphp\Exception\KeyStoreException;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfig;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;

use function count;
use function hash_equals;
use function strlen;

/**
 * A gateway key pair: a key identifier, a KEM, the HPKE private key, the
 * supported KDF/AEAD suites, and lifecycle metadata for rotation.
 *
 * The public key is always derived from the private key, so the pair can
 * never diverge. Key configurations published through keyConfig() contain
 * public material only.
 */
final class GatewayKeyPair
{
    public const STATE_ACTIVE = 'active';
    public const STATE_RETIRED = 'retired';

    private ?KeyConfig $keyConfig = null;

    /**
     * @param int $keyId 8-bit key identifier
     * @param list<SymmetricSuite> $symmetricSuites One or more KDF/AEAD pairs
     * @param string $state active or retired
     *
     * @throws KeyStoreException When the parameters are inconsistent
     */
    public function __construct(
        public readonly int $keyId,
        public readonly KemId $kemId,
        public readonly DecapsKey $secretKey,
        public readonly array $symmetricSuites,
        public readonly \DateTimeImmutable $createdAt,
        public readonly string $state = self::STATE_ACTIVE,
        public readonly ?\DateTimeImmutable $retiredAt = null,
    ) {
        if ($keyId < 0 || $keyId > 0xFF) {
            throw new KeyStoreException('Key identifier must be an 8-bit value');
        }
        if (count($symmetricSuites) === 0) {
            throw new KeyStoreException('At least one symmetric algorithm is required');
        }
        if ($state !== self::STATE_ACTIVE && $state !== self::STATE_RETIRED) {
            throw new KeyStoreException('Invalid key state');
        }
        if ($state === self::STATE_RETIRED && $retiredAt === null) {
            throw new KeyStoreException('A retired key requires a retirement timestamp');
        }
        if (strlen($secretKey->bytes) !== $kemId->toHpkeCurve()->decapsKeyLength()) {
            throw new KeyStoreException('Secret key length does not match the KEM');
        }
        if ($secretKey->curve !== $kemId->toHpkeCurve()) {
            throw new KeyStoreException('Secret key curve does not match the KEM');
        }
    }

    /**
     * Generate a new key pair for the given KEM using paragonie/hpke.
     *
     * @param list<SymmetricSuite> $symmetricSuites
     *
     * @throws KeyStoreException When key generation fails
     */
    public static function generate(
        int $keyId,
        KemId $kemId,
        array $symmetricSuites,
        ?\DateTimeImmutable $createdAt = null,
    ): self {
        try {
            $keys = $kemId->toHpkeKem()->generateKeys();
        } catch (\Throwable $e) {
            throw new KeyStoreException('Unable to generate a gateway key pair', 0, $e);
        }
        if (!$keys[0] instanceof DecapsKey || !$keys[1] instanceof EncapsKey) {
            throw new KeyStoreException('Key generation produced unexpected key types');
        }

        // Verify the generated public/private key relationship.
        try {
            $derivedPublic = $keys[0]->getEncapsKey()->bytes;
        } catch (\Throwable $e) {
            throw new KeyStoreException('Generated key pair failed validation', 0, $e);
        }
        if (!hash_equals($derivedPublic, $keys[1]->bytes)) {
            throw new KeyStoreException('Generated key pair is inconsistent');
        }

        return new self(
            $keyId,
            $kemId,
            $keys[0],
            $symmetricSuites,
            $createdAt ?? new \DateTimeImmutable(),
        );
    }

    /**
     * The public key configuration advertised to clients. Contains public
     * material only and is derived from the private key on first use.
     */
    public function keyConfig(): KeyConfig
    {
        if ($this->keyConfig === null) {
            $this->keyConfig = new KeyConfig(
                $this->keyId,
                $this->kemId,
                $this->publicKey(),
                $this->symmetricSuites,
            );
        }

        return $this->keyConfig;
    }

    /**
     * The encapsulation (public) key bytes, derived from the private key.
     */
    public function publicKey(): string
    {
        try {
            return $this->secretKey->getEncapsKey()->bytes;
        } catch (\Throwable $e) {
            throw new KeyStoreException('Unable to derive the public key', 0, $e);
        }
    }

    public function isActive(): bool
    {
        return $this->state === self::STATE_ACTIVE;
    }

    public function isRetired(): bool
    {
        return $this->state === self::STATE_RETIRED;
    }

    /**
     * A copy of this key pair in the retired state, still usable for
     * decryption but no longer advertised to clients.
     */
    public function retired(): self
    {
        if ($this->isRetired()) {
            return $this;
        }

        return new self(
            $this->keyId,
            $this->kemId,
            $this->secretKey,
            $this->symmetricSuites,
            $this->createdAt,
            self::STATE_RETIRED,
            new \DateTimeImmutable(),
        );
    }
}
