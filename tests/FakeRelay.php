<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests;

use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfig;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use ParagonIE\HPKE\AEAD\AES128GCM;
use ParagonIE\HPKE\Context\Receiver;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KDF\Hash;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use ParagonIE\HPKE\SymmetricKey;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

use function bin2hex;
use function random_bytes;
use function strlen;
use function substr;

/**
 * In-process stand-in for the Oblivious Relay Resource and the Oblivious
 * Gateway Resource, implementing the gateway role of RFC 9458 (Sections
 * 4.3 and 4.4, receiver side) directly with paragonie/hpke. This provides
 * an independent cross-check of the client implementation.
 *
 * The gateway answers every target request with a 200 response whose body
 * records the method and request target it observed, proving that the
 * encapsulated request was correctly decrypted and decoded.
 */
final class FakeRelay implements ClientInterface
{
    public const RELAY_URI = 'https://relay.example.org/relay';

    private readonly HPKE $hpke;
    private readonly Psr17Factory $factory;
    private string $lastTargetSummary = '';

    public function __construct(
        private readonly KemId $kemId,
        private readonly KdfId $kdfId,
        private readonly AeadId $aeadId,
        private readonly DecapsKey $secretKey,
        private readonly KeyConfig $keyConfig,
    ) {
        $this->hpke = new HPKE(
            $kemId->toHpkeKem(),
            $kdfId->toHpkeKdf(),
            $aeadId->toHpkeAead(),
        );
        $this->factory = new Psr17Factory();
    }

    /**
     * Generate a new gateway key pair for the given KEM and build the
     * matching key configuration with a single symmetric suite.
     */
    public static function create(KemId $kemId = KemId::DhkemX25519HkdfSha256, KdfId $kdfId = KdfId::HkdfSha256, AeadId $aeadId = AeadId::Aes128Gcm): self
    {
        $kem = $kemId->toHpkeKem();
        $keys = $kem->generateKeys();
        if (!$keys[0] instanceof DecapsKey || !$keys[1] instanceof EncapsKey) {
            throw new RuntimeException('Unexpected key types generated');
        }
        $config = new KeyConfig(
            1,
            $kemId,
            $keys[1]->bytes,
            [SymmetricSuite::from($kdfId, $aeadId)]
        );

        return new self($kemId, $kdfId, $aeadId, $keys[0], $config);
    }

    public function keyConfig(): KeyConfig
    {
        return $this->keyConfig;
    }

    public function lastTargetSummary(): string
    {
        return $this->lastTargetSummary;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            throw new RuntimeException('Relay expects POST');
        }
        if ($request->getHeaderLine('Content-Type') !== 'message/ohttp-req') {
            throw new RuntimeException('Relay expects message/ohttp-req content type');
        }

        $encapsulatedRequest = (string) $request->getBody();
        $kem = $this->kemId->toHpkeKem();
        $headerLength = 7;
        $encLength = $kem->getHeaderLength();
        if (strlen($encapsulatedRequest) < $headerLength + $encLength) {
            throw new RuntimeException('Encapsulated request too short');
        }

        $header = substr($encapsulatedRequest, 0, $headerLength);
        $enc = substr($encapsulatedRequest, $headerLength, $encLength);
        $ciphertext = substr($encapsulatedRequest, $headerLength + $encLength);

        $info = 'message/bhttp request' . "\x00" . $header;
        $receiver = $this->hpke->setupBaseReceiver($this->secretKey, $enc, $info);
        $bhttpRequest = $receiver->open($ciphertext, '');

        // Decode the request to prove the client produced valid binary HTTP.
        $decoded = (new \Gcorradomms\Ohttphp\BinaryHttp\BinaryHttpDecoder(
            $this->factory,
            $this->factory,
            $this->factory,
            $this->factory,
        ))->decodeRequest($bhttpRequest);
        $this->lastTargetSummary = $decoded->getMethod() . ' ' . $decoded->getRequestTarget();

        $bhttpResponse = $this->encodeResponse('200 response for ' . $this->lastTargetSummary);
        $encapsulatedResponse = $this->encapsulateResponse($receiver, $enc, $bhttpResponse);

        return new Response(200, ['Content-Type' => 'message/ohttp-res'], $encapsulatedResponse);
    }

    /**
     * Gateway-side response encapsulation (RFC 9458, Section 4.4).
     */
    private function encapsulateResponse(Receiver $receiver, string $enc, string $bhttpResponse): string
    {
        $nonceLength = $this->aeadId->responseNonceLength();
        $secret = $receiver->export('message/bhttp response', $nonceLength);
        $responseNonce = random_bytes($nonceLength);

        $kdf = $this->kdfId->toHpkeKdf();
        $prk = $kdf->extract($secret, $enc . $responseNonce);
        $aeadKey = new SymmetricKey($kdf->expand($prk, 'key', $this->aeadId->keyLength()));
        $aeadNonce = $kdf->expand($prk, 'nonce', $this->aeadId->nonceLength());

        [$ciphertext, $tag] = $this->aeadId->toHpkeAead()->encrypt($aeadKey, $bhttpResponse, $aeadNonce, '');
        if (!is_string($ciphertext) || !is_string($tag)) {
            throw new RuntimeException('AEAD encryption produced unexpected output');
        }

        return $responseNonce . $ciphertext . $tag;
    }

    /**
     * Encode a known-length binary HTTP response with a body.
     */
    private function encodeResponse(string $body): string
    {
        return pack('C', 1) // known-length response framing
            . \Gcorradomms\Ohttphp\BinaryHttp\VarInt::encode(200)
            . pack('C', 0) // empty header section
            . \Gcorradomms\Ohttphp\BinaryHttp\VarInt::encode(strlen($body))
            . $body
            . pack('C', 0); // empty trailer section
    }

    /**
     * Expose the raw encapsulation key bytes of the gateway key (debug aid).
     */
    public function publicKeyHex(): string
    {
        return bin2hex($this->keyConfig->publicKey);
    }
}
