<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\KeyConfig;

use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\KDF\HKDF;

/**
 * HPKE KDF identifiers from the IANA "HPKE KDF Identifiers" registry, as
 * used in OHTTP key configurations (RFC 9458, Section 3.1).
 */
enum KdfId: int
{
    case HkdfSha256 = 0x0001;
    case HkdfSha384 = 0x0002;
    case HkdfSha512 = 0x0003;

    public function toHpkeKdf(): HKDF
    {
        return new HKDF(match ($this) {
            KdfId::HkdfSha256 => Hash::Sha256,
            KdfId::HkdfSha384 => Hash::Sha384,
            KdfId::HkdfSha512 => Hash::Sha512,
        });
    }
}
