<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Ohttp;

use Gcorradomms\Ohttphp\Exception\EncapsulationException;
use Gcorradomms\Ohttphp\Exception\ResponseDecryptionException;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfig;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use ParagonIE\HPKE\Context\Sender;
use ParagonIE\HPKE\SymmetricKey;
use SodiumException;

use function strlen;
use function substr;

/**
 * Client-side HPKE context for one Oblivious HTTP exchange (RFC 9458).
 *
 * encapsulateRequest() implements Section 4.3: it selects the key
 * configuration and symmetric suite, sets up a sending HPKE context with
 * info = "message/bhttp request" || 0x00 || hdr, seals the binary HTTP
 * request, and produces the Encapsulated Request.
 *
 * decapsulateResponse() implements the client side of Section 4.4: it
 * derives the response protection keys from the HPKE exporter secret and
 * decrypts the Encapsulated Response.
 *
 * A context protects exactly one request and decrypts exactly one
 * response; a second decryption attempt is rejected to prevent accidental
 * key and nonce reuse.
 */
final class OhttpContext
{
    private const REQUEST_INFO_LABEL = 'message/bhttp request';
    private const RESPONSE_EXPORTER_CONTEXT = 'message/bhttp response';

    private bool $responseProcessed = false;

    /**
     * @param string $header The 7-byte header (key_id, kem_id, kdf_id, aead_id)
     * @param string $enc The encapsulated KEM shared secret (Nenc bytes)
     */
    private function __construct(
        private readonly string $header,
        private readonly string $enc,
        private readonly Sender $sender,
        private readonly KdfId $kdfId,
        private readonly AeadId $aeadId,
    ) {
    }

    /**
     * Encapsulate a binary HTTP request using values from a key
     * configuration (RFC 9458, Section 4.3).
     *
     * @param KeyConfig $config Validated key configuration of the gateway
     * @param SymmetricSuite $suite A KDF/AEAD combination advertised by the configuration
     * @param string $bhttpRequest The binary HTTP request to protect
     * @param HPKE|null $hpkeOverride Pre-built HPKE suite, for testing with
     *     deterministic ephemeral keys
     * @return array{0: OhttpContext, 1: string} The context and the
     *     Encapsulated Request bytes
     *
     * @throws EncapsulationException When HPKE setup or sealing fails
     * @throws \Gcorradomms\Ohttphp\Exception\UnsupportedAlgorithmException
     * @throws \Gcorradomms\Ohttphp\Exception\InvalidKeyConfigurationException
     */
    public static function encapsulateRequest(
        KeyConfig $config,
        SymmetricSuite $suite,
        string $bhttpRequest,
        ?HPKE $hpkeOverride = null,
    ): array {
        $hpke = $hpkeOverride ?? $config->toHpkeSuite($suite);
        $header = $config->requestHeader($suite);
        $info = self::REQUEST_INFO_LABEL . "\x00" . $header;

        try {
            $publicKey = new EncapsKey($config->kemId->toHpkeCurve(), $config->publicKey);
            /** @var array{0: string, 1: Sender} $setup */
            $setup = $hpke->setupBaseSender($publicKey, $info);
            [$enc, $sender] = $setup;
            $ciphertext = $sender->seal($bhttpRequest, '');
        } catch (HPKEException | SodiumException $e) {
            throw new EncapsulationException('Failed to encapsulate the request: ' . $e->getMessage(), 0, $e);
        }

        $context = new self($header, $enc, $sender, $suite->requireKdf(), $suite->requireAead());

        return [$context, $header . $enc . $ciphertext];
    }

    /**
     * The 7-byte header of the encapsulated request.
     */
    public function header(): string
    {
        return $this->header;
    }

    /**
     * The encapsulated KEM shared secret (enc) generated for this exchange.
     */
    public function encapsulationKey(): string
    {
        return $this->enc;
    }

    /**
     * Decrypt an Encapsulated Response and return the binary HTTP response
     * message (RFC 9458, Section 4.4, client side).
     *
     * @throws ResponseDecryptionException When the response cannot be decrypted
     */
    public function decapsulateResponse(string $encapsulatedResponse): string
    {
        if ($this->responseProcessed) {
            throw new ResponseDecryptionException('This context has already processed a response');
        }

        $nonceLength = $this->aeadId->responseNonceLength();
        $tagLength = $this->aeadId->tagLength();
        if (strlen($encapsulatedResponse) < $nonceLength + $tagLength) {
            throw new ResponseDecryptionException('Encapsulated response is too short');
        }

        $responseNonce = substr($encapsulatedResponse, 0, $nonceLength);
        $protected = substr($encapsulatedResponse, $nonceLength);
        $ciphertext = substr($protected, 0, -$tagLength);
        $tag = substr($protected, -$tagLength);

        $kdf = $this->kdfId->toHpkeKdf();

        // secret = context.Export("message/bhttp response", max(Nn, Nk))
        $secret = $this->sender->export(self::RESPONSE_EXPORTER_CONTEXT, $nonceLength);

        // prk = Extract(salt = enc || response_nonce, ikm = secret)
        $prk = $kdf->extract($secret, $this->enc . $responseNonce);

        // aead_key = Expand(prk, "key", Nk); aead_nonce = Expand(prk, "nonce", Nn)
        $aeadKey = new SymmetricKey($kdf->expand($prk, 'key', $this->aeadId->keyLength()));
        $aeadNonce = $kdf->expand($prk, 'nonce', $this->aeadId->nonceLength());

        try {
            $plaintext = $this->aeadId->toHpkeAead()->decrypt($aeadKey, $ciphertext, $tag, $aeadNonce, '');
        } catch (HPKEException | SodiumException $e) {
            throw new ResponseDecryptionException('Failed to decrypt the encapsulated response', 0, $e);
        }

        $this->responseProcessed = true;

        return $plaintext;
    }
}
