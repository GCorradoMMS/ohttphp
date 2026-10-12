<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway;

use Gcorradomms\Ohttphp\Exception\KeyStoreException;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;

use function array_keys;
use function array_map;
use function base64_decode;
use function base64_encode;
use function chmod;
use function count;
use function file_get_contents;
use function file_put_contents;
use function glob;
use function hash_equals;
use function is_array;
use function is_dir;
use function is_int;
use function json_decode;
use function json_encode;
use function max;
use function mkdir;
use function rename;
use function sprintf;
use function strlen;
use function tempnam;
use function unlink;

use const JSON_THROW_ON_ERROR;

/**
 * File-based key store. Each key pair is stored as a single JSON document
 * in an operator-provided directory (one file per key identifier).
 *
 * Security properties:
 * - The directory is created with mode 0700 and key files are written
 *   with mode 0600 where the platform supports it.
 * - Writes are atomic: content goes to a temporary file in the same
 *   directory that is rename()d over the target.
 * - On load, key material is validated: structure, KEM consistency, and
 *   public key derivation from the stored private key.
 * - No key material is ever included in exception messages.
 *
 * This store is a convenience for simple installations and the local
 * demo. It is NOT a substitute for a secrets manager or hardware-backed
 * key management; use GatewayKeyStoreInterface to integrate one.
 */
final class FileGatewayKeyStore implements GatewayKeyStoreInterface
{
    private const FILE_FORMAT_VERSION = 1;
    private const FILE_MODE = 0600;
    private const DIRECTORY_MODE = 0700;

    /** @var array<int, GatewayKeyPair> */
    private array $keys = [];

    /**
     * @throws KeyStoreException When the directory cannot be prepared or a
     *     stored key is invalid
     */
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory)) {
            if (!@mkdir($directory, self::DIRECTORY_MODE, true) && !is_dir($directory)) {
                throw new KeyStoreException('Unable to create the key store directory');
            }
            @chmod($directory, self::DIRECTORY_MODE);
        }
        $this->loadAll();
    }

    public function add(GatewayKeyPair $keyPair): void
    {
        if (isset($this->keys[$keyPair->keyId])) {
            throw new KeyStoreException('A key with this identifier already exists');
        }
        $this->persist($keyPair);
        $this->keys[$keyPair->keyId] = $keyPair;
    }

    public function get(int $keyId): ?GatewayKeyPair
    {
        return $this->keys[$keyId] ?? null;
    }

    public function active(): array
    {
        $active = [];
        foreach ($this->keys as $key) {
            if ($key->isActive()) {
                $active[] = $key;
            }
        }

        return $active;
    }

    public function retire(int $keyId): void
    {
        $key = $this->keys[$keyId] ?? null;
        if ($key === null) {
            throw new KeyStoreException('Unknown key identifier');
        }
        if ($key->isRetired()) {
            throw new KeyStoreException('Key is already retired');
        }
        $retired = $key->retired();
        $this->persist($retired);
        $this->keys[$keyId] = $retired;
    }

    /**
     * The key identifier that would be assigned to the next generated key
     * when no explicit identifier is chosen (highest identifier plus one).
     */
    public function nextKeyIdentifier(): int
    {
        if (count($this->keys) === 0) {
            return 1;
        }

        return max(array_keys($this->keys)) + 1;
    }

    private function persist(GatewayKeyPair $keyPair): void
    {
        $document = [
            'version' => self::FILE_FORMAT_VERSION,
            'keyId' => $keyPair->keyId,
            'kemId' => $keyPair->kemId->value,
            'symmetricSuites' => array_map(
                static fn (SymmetricSuite $suite): array => [$suite->kdfId, $suite->aeadId],
                $keyPair->symmetricSuites
            ),
            'secretKey' => base64_encode($keyPair->secretKey->bytes),
            'publicKey' => base64_encode($keyPair->publicKey()),
            'createdAt' => $keyPair->createdAt->format(DATE_ATOM),
            'state' => $keyPair->state,
            'retiredAt' => $keyPair->retiredAt?->format(DATE_ATOM),
        ];

        try {
            $json = json_encode($document, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new KeyStoreException('Unable to encode the key document', 0, $e);
        }

        $target = $this->pathFor($keyPair->keyId);
        $temporary = tempnam($this->directory, '.key-');
        if ($temporary === false) {
            throw new KeyStoreException('Unable to create a temporary key file');
        }
        if (@file_put_contents($temporary, $json) === false || !@chmod($temporary, self::FILE_MODE)) {
            @unlink($temporary);
            throw new KeyStoreException('Unable to write the key file');
        }
        if (!@rename($temporary, $target)) {
            @unlink($temporary);
            throw new KeyStoreException('Unable to store the key file');
        }
    }

    private function pathFor(int $keyId): string
    {
        return sprintf('%s/key-%03d.json', $this->directory, $keyId);
    }

    private function loadAll(): void
    {
        $pattern = sprintf('%s/key-*.json', $this->directory);
        foreach (glob($pattern) ?: [] as $file) {
            $key = $this->loadFile($file);
            if (isset($this->keys[$key->keyId])) {
                throw new KeyStoreException('Duplicate key identifier in the key store');
            }
            $this->keys[$key->keyId] = $key;
        }
    }

    private function loadFile(string $path): GatewayKeyPair
    {
        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new KeyStoreException('Unable to read a key file');
        }
        try {
            /** @var mixed $document */
            $document = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new KeyStoreException('Invalid key file encoding', 0, $e);
        }
        if (!is_array($document)) {
            throw new KeyStoreException('Invalid key file structure');
        }

        $version = $document['version'] ?? null;
        if ($version !== self::FILE_FORMAT_VERSION) {
            throw new KeyStoreException('Unsupported key file version');
        }
        $keyId = $document['keyId'] ?? null;
        $kemRaw = $document['kemId'] ?? null;
        $suitesRaw = $document['symmetricSuites'] ?? null;
        $secretRaw = $document['secretKey'] ?? null;
        $publicRaw = $document['publicKey'] ?? null;
        $state = $document['state'] ?? null;
        $createdAtRaw = $document['createdAt'] ?? null;
        $retiredAtRaw = $document['retiredAt'] ?? null;

        if (!is_int($keyId) || !is_int($kemRaw) || !is_string($secretRaw) || !is_string($publicRaw)
            || !is_string($state) || !is_string($createdAtRaw)
            || !is_array($suitesRaw) || count($suitesRaw) === 0) {
            throw new KeyStoreException('Invalid key file fields');
        }

        $kemId = KemId::tryFrom($kemRaw);
        if ($kemId === null) {
            throw new KeyStoreException('Unsupported KEM in key file');
        }

        $suites = [];
        foreach ($suitesRaw as $suite) {
            if (!is_array($suite) || !is_int($suite[0] ?? null) || !is_int($suite[1] ?? null)) {
                throw new KeyStoreException('Invalid symmetric algorithm entry in key file');
            }
            $suites[] = new SymmetricSuite($suite[0], $suite[1]);
        }

        $secretBytes = base64_decode($secretRaw, true);
        $publicBytes = base64_decode($publicRaw, true);
        if ($secretBytes === false || $publicBytes === false
            || strlen($secretBytes) !== $kemId->toHpkeCurve()->decapsKeyLength()
            || strlen($publicBytes) !== $kemId->toHpkeCurve()->encapsKeyLength()) {
            throw new KeyStoreException('Invalid key encoding in key file');
        }

        try {
            $secretKey = new DecapsKey($kemId->toHpkeCurve(), $secretBytes);
            $createdAt = new \DateTimeImmutable($createdAtRaw);
            $retiredAt = is_string($retiredAtRaw) ? new \DateTimeImmutable($retiredAtRaw) : null;
        } catch (\Throwable $e) {
            throw new KeyStoreException('Invalid key file contents', 0, $e);
        }

        if ($state !== GatewayKeyPair::STATE_ACTIVE && $state !== GatewayKeyPair::STATE_RETIRED) {
            throw new KeyStoreException('Invalid key state in key file');
        }
        if ($state === GatewayKeyPair::STATE_RETIRED && $retiredAt === null) {
            throw new KeyStoreException('Retired key without retirement timestamp in key file');
        }

        // Constructing the pair validates the key material and derives the
        // public key; the stored public key must match that derivation, so
        // any tampering with either field is detected.
        try {
            $pair = new GatewayKeyPair($keyId, $kemId, $secretKey, $suites, $createdAt, $state, $retiredAt);
        } catch (\Throwable $e) {
            throw new KeyStoreException('Key file failed validation', 0, $e);
        }
        if (!hash_equals($pair->publicKey(), $publicBytes)) {
            throw new KeyStoreException('Key file failed validation');
        }

        return $pair;
    }
}
