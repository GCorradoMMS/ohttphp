<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests;

use ParagonIE\EasyECC\EasyECC;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use ParagonIE\HPKE\Interfaces\KDFInterface;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;

use function sodium_crypto_scalarmult;
use function str_repeat;

/**
 * DiffieHellmanKEM variant that always derives its ephemeral key pair from
 * a fixed secret, enabling byte-exact RFC 9458 test vector comparisons.
 *
 * The parent class documents generatePrivateKey() as a hook intended to be
 * overridden in unit tests.
 */
final class DeterministicKem extends DiffieHellmanKEM
{
    public function __construct(
        Curve $curve,
        KDFInterface $kdf,
        private readonly string $fixedSecret,
    ) {
        parent::__construct($curve, $kdf);
    }

    public function generatePrivateKey(EasyECC $ecc): string|PrivateKeyInterface
    {
        if ($ecc->getCurveName() === 'sodium') {
            // libsodium "keypair" format: secret (32 bytes) || public (32 bytes)
            return $this->fixedSecret . sodium_crypto_scalarmult($this->fixedSecret, "\x09" . str_repeat("\x00", 31));
        }

        return parent::generatePrivateKey($ecc);
    }
}
