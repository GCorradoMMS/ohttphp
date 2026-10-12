<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Ohttp;

use Gcorradomms\Ohttphp\Exception\RequestDecapsulationException;
use Gcorradomms\Ohttphp\Exception\ResponseEncapsulationException;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use ParagonIE\HPKE\Context\Receiver;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;
use ParagonIE\HPKE\SymmetricKey;

use function is_string;
use function random_bytes;
use function strlen;
use function substr;

/**
 * Gateway-side HPKE context for one Oblivious HTTP exchange (RFC 9458).
 *
 * openEncapsulatedRequest() implements the gateway side of Section 4.3:
 * it sets up a receiving HPKE context with info =
 * "message/bhttp request" || 0x00 || hdr and opens the protected request.
 *
 * encapsulateResponse() implements Section 4.4: it derives the response
 * protection key material from the HPKE exporter secret and returns the
 * Encapsulated Response (nonce || ciphertext || tag).
 *
 * A context opens exactly one request and encapsulates exactly one
 * response; reuse is rejected to prevent accidental key and nonce reuse.
 *
 * All failures are reported with uniform messages: callers must not emit
 * exception details to clients, to avoid decryption oracles.
 */
final class OhttpReceiverContext
{
    private const REQUEST_INFO_LABEL = 'message/bhttp request';
    private const RESPONSE_EXPORTER_CONTEXT = 'message/bhttp response';

    public const HEADER_LENGTH = 7;

    private bool $responseEncapsulated = false;

    /**
     * @param string $header The 7-byte header (key_id, kem_id, kdf_id, aead_id)
     * @param string $enc The encapsulated KEM key (Nenc bytes)
     */
    private function __construct(
        private readonly string $header,
        private readonly string $enc,
        private readonly Receiver $receiver,
        private readonly KdfId $kdfId,
        private readonly AeadId $aeadId,
    ) {
    }

    /**
     * Open an encapsulated request and retain the context for the
     * encapsulated response (RFC 9458, Section 4.3, gateway side).
     *
     * @param DecapsKey $secretKey The gateway private key for the key
     *     identifier in the header
     * @param string $header The 7-byte request header
     * @param string $enc The encapsulated KEM key
     * @param string $ciphertext The HPKE-protected request payload
     * @param HPKE $hpke The HPKE suite selected from the header identifiers;
     *     its KEM must match the secret key's curve
     * @return array{0: OhttpReceiverContext, 1: string} The context and the
     *     binary HTTP request
     *
     * @throws RequestDecapsulationException When the request cannot be opened
     */
    public static function openEncapsulatedRequest(
        DecapsKey $secretKey,
        string $header,
        string $enc,
        string $ciphertext,
        HPKE $hpke,
    ): array {
        if (strlen($header) !== self::HEADER_LENGTH) {
            throw new RequestDecapsulationException('Invalid encapsulated request header length');
        }
        if (strlen($enc) !== $hpke->kem->getHeaderLength()) {
            throw new RequestDecapsulationException('Invalid encapsulated request length');
        }
        if (strlen($ciphertext) < $hpke->aead->tagLength()) {
            throw new RequestDecapsulationException('Invalid encapsulated request length');
        }

        $info = self::REQUEST_INFO_LABEL . "\x00" . $header;

        try {
            $receiver = $hpke->setupBaseReceiver($secretKey, $enc, $info);
            $bhttpRequest = $receiver->open($ciphertext, '');
        } catch (\Throwable $e) {
            // Uniform failure: the underlying cause (wrong key, corrupted
            // ciphertext, malformed encapsulation key, ...) is attached as
            // the previous exception for redacted internal logging only.
            throw new RequestDecapsulationException('Unable to process the encapsulated request', 0, $e);
        }

        $context = new self($header, $enc, $receiver, self::resolveKdf($hpke), self::resolveAead($hpke));

        return [$context, $bhttpRequest];
    }

    /**
     * The 7-byte header of the encapsulated request.
     */
    public function header(): string
    {
        return $this->header;
    }

    /**
     * The encapsulated KEM key (enc) from the request.
     */
    public function encapsulationKey(): string
    {
        return $this->enc;
    }

    /**
     * Encapsulate a binary HTTP response for the client (RFC 9458,
     * Section 4.4, gateway side).
     *
     * @param string $bhttpResponse The binary HTTP response to protect
     * @param callable|null $nonceGenerator Optional source of cryptographically
     *     secure random bytes with signature (int $length): string, for
     *     deterministic testing. Production callers must leave this null.
     * @return string The Encapsulated Response: nonce || ciphertext || tag
     *
     * @throws ResponseEncapsulationException When the response cannot be
     *     encapsulated
     */
    public function encapsulateResponse(string $bhttpResponse, ?callable $nonceGenerator = null): string
    {
        if ($this->responseEncapsulated) {
            throw new ResponseEncapsulationException('This context has already encapsulated a response');
        }

        $nonceLength = $this->aeadId->responseNonceLength();
        $responseNonce = $nonceGenerator !== null
            ? $nonceGenerator($nonceLength)
            : random_bytes($nonceLength);
        if (!is_string($responseNonce) || strlen($responseNonce) !== $nonceLength) {
            throw new ResponseEncapsulationException('Response nonce generation failed');
        }

        $kdf = $this->kdfId->toHpkeKdf();

        // secret = context.Export("message/bhttp response", max(Nn, Nk))
        $secret = $this->receiver->export(self::RESPONSE_EXPORTER_CONTEXT, $nonceLength);

        // prk = Extract(salt = enc || response_nonce, ikm = secret)
        $prk = $kdf->extract($secret, $this->enc . $responseNonce);

        // aead_key = Expand(prk, "key", Nk); aead_nonce = Expand(prk, "nonce", Nn)
        $aeadKey = new SymmetricKey($kdf->expand($prk, 'key', $this->aeadId->keyLength()));
        $aeadNonce = $kdf->expand($prk, 'nonce', $this->aeadId->nonceLength());

        try {
            [$ciphertext, $tag] = $this->aeadId->toHpkeAead()->encrypt($aeadKey, $bhttpResponse, $aeadNonce, '');
        } catch (\RuntimeException $e) {
            throw new ResponseEncapsulationException('Unable to protect the response', 0, $e);
        }
        if (!is_string($ciphertext) || !is_string($tag)) {
            throw new ResponseEncapsulationException('Unable to protect the response');
        }

        $this->responseEncapsulated = true;

        return $responseNonce . $ciphertext . $tag;
    }

    /**
     * Resolve the KDF identifier from the suite used to open the request.
     */
    private static function resolveKdf(HPKE $hpke): KdfId
    {
        $kdf = KdfId::tryFrom(self::unpackId($hpke->kdf->getKdfId()));
        if ($kdf === null) {
            throw new ResponseEncapsulationException('Unsupported KDF identifier');
        }

        return $kdf;
    }

    /**
     * Resolve the AEAD identifier from the suite used to open the request.
     */
    private static function resolveAead(HPKE $hpke): AeadId
    {
        $aead = AeadId::tryFrom(self::unpackId($hpke->aead->getAeadId()));
        if ($aead === null) {
            throw new ResponseEncapsulationException('Unsupported AEAD identifier');
        }

        return $aead;
    }

    /**
     * @return int The 16-bit algorithm identifier
     */
    private static function unpackId(string $idBytes): int
    {
        $unpacked = unpack('n', $idBytes);
        if ($unpacked === false || !is_int($unpacked[1] ?? null)) {
            throw new ResponseEncapsulationException('Malformed algorithm identifier');
        }

        return $unpacked[1];
    }
}
