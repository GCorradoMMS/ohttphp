<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\KeyConfig;

use Gcorradomms\Ohttphp\Exception\UnsupportedAlgorithmException;
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;

/**
 * HPKE KEM identifiers from the IANA "HPKE KEM Identifiers" registry, as
 * used in OHTTP key configurations (RFC 9458, Section 3.1).
 *
 * Only the four KEMs defined for OHTTP in RFC 9458 are supported. The
 * inner KDF of each DHKEM is fixed by its identifier per RFC 9180,
 * Section 7.1.
 */
enum KemId: int
{
    case DhkemP256HkdfSha256 = 0x0010;
    case DhkemP384HkdfSha256 = 0x0011;
    case DhkemP521HkdfSha512 = 0x0012;
    case DhkemX25519HkdfSha256 = 0x0020;

    /**
     * Length in bytes of encapsulation (public) keys for this KEM (Npk).
     */
    public function publicKeyLength(): int
    {
        return $this->toHpkeCurve()->encapsKeyLength();
    }

    /**
     * Construct the DHKEM identified by this enum value.
     *
     * @throws UnsupportedAlgorithmException
     */
    public function toHpkeKem(): DiffieHellmanKEM
    {
        return new DiffieHellmanKEM($this->toHpkeCurve(), $this->innerKdf());
    }

    public function toHpkeCurve(): Curve
    {
        return match ($this) {
            KemId::DhkemX25519HkdfSha256 => Curve::X25519,
            KemId::DhkemP256HkdfSha256 => Curve::NistP256,
            KemId::DhkemP384HkdfSha256 => Curve::NistP384,
            KemId::DhkemP521HkdfSha512 => Curve::NistP521,
        };
    }

    private function innerKdf(): HKDF
    {
        return new HKDF(match ($this) {
            KemId::DhkemX25519HkdfSha256,
            KemId::DhkemP256HkdfSha256,
            KemId::DhkemP384HkdfSha256 => Hash::Sha256,
            KemId::DhkemP521HkdfSha512 => Hash::Sha512,
        });
    }
}
