<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\KeyConfig;

use ParagonIE\HPKE\AEAD\AES128GCM;
use ParagonIE\HPKE\AEAD\AES256GCM;
use ParagonIE\HPKE\AEAD\ChaCha20Poly1305;
use ParagonIE\HPKE\Interfaces\AEADInterface;

/**
 * HPKE AEAD identifiers from the IANA "HPKE AEAD Identifiers" registry, as
 * used in OHTTP key configurations (RFC 9458, Section 3.1).
 *
 * The "Export-Only AEAD" (0xFFFF) is not supported: OHTTP requires a real
 * AEAD to protect responses.
 */
enum AeadId: int
{
    case Aes128Gcm = 0x0001;
    case Aes256Gcm = 0x0002;
    case ChaCha20Poly1305 = 0x0003;

    public function keyLength(): int
    {
        return match ($this) {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm, AeadId::ChaCha20Poly1305 => 32,
        };
    }

    public function nonceLength(): int
    {
        return 12;
    }

    public function tagLength(): int
    {
        return 16;
    }

    /**
     * Length of the response nonce field: max(Nn, Nk) per RFC 9458.
     *
     * @return int<1, max>
     */
    public function responseNonceLength(): int
    {
        return match ($this) {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm, AeadId::ChaCha20Poly1305 => 32,
        };
    }

    public function toHpkeAead(): AEADInterface
    {
        return match ($this) {
            AeadId::Aes128Gcm => new AES128GCM(),
            AeadId::Aes256Gcm => new AES256GCM(),
            AeadId::ChaCha20Poly1305 => new ChaCha20Poly1305(),
        };
    }
}
