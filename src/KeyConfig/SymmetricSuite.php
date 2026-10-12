<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\KeyConfig;

use Gcorradomms\Ohttphp\Exception\UnsupportedAlgorithmException;

/**
 * One HPKE symmetric algorithm combination (KDF + AEAD) advertised in an
 * OHTTP key configuration (RFC 9458, Section 3.1).
 *
 * Identifiers are stored as raw 16-bit values: key configurations may
 * advertise algorithms this library does not implement, and those entries
 * are simply never selected.
 */
final class SymmetricSuite
{
    /**
     * @param int $kdfId 16-bit HPKE KDF identifier
     * @param int $aeadId 16-bit HPKE AEAD identifier
     */
    public function __construct(
        public readonly int $kdfId,
        public readonly int $aeadId,
    ) {
        if ($kdfId < 0 || $kdfId > 0xFFFF) {
            throw new \OutOfRangeException('KDF identifier out of range');
        }
        if ($aeadId < 0 || $aeadId > 0xFFFF) {
            throw new \OutOfRangeException('AEAD identifier out of range');
        }
    }

    public static function from(KdfId $kdfId, AeadId $aeadId): self
    {
        return new self($kdfId->value, $aeadId->value);
    }

    /**
     * The KDF for this suite, or null when this library does not implement it.
     */
    public function supportedKdf(): ?KdfId
    {
        return KdfId::tryFrom($this->kdfId);
    }

    /**
     * The AEAD for this suite, or null when this library does not implement it.
     */
    public function supportedAead(): ?AeadId
    {
        return AeadId::tryFrom($this->aeadId);
    }

    /**
     * @throws UnsupportedAlgorithmException When the suite is not implemented
     */
    public function requireKdf(): KdfId
    {
        return $this->supportedKdf()
            ?? throw new UnsupportedAlgorithmException('Unsupported HPKE KDF identifier: ' . $this->kdfId);
    }

    /**
     * @throws UnsupportedAlgorithmException When the suite is not implemented
     */
    public function requireAead(): AeadId
    {
        return $this->supportedAead()
            ?? throw new UnsupportedAlgorithmException('Unsupported HPKE AEAD identifier: ' . $this->aeadId);
    }

    public function equals(SymmetricSuite $other): bool
    {
        return $this->kdfId === $other->kdfId && $this->aeadId === $other->aeadId;
    }
}
