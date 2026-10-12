<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\Gateway;

use Gcorradomms\Ohttphp\Exception\KeyStoreException;
use Gcorradomms\Ohttphp\Gateway\FileGatewayKeyStore;
use Gcorradomms\Ohttphp\Gateway\GatewayKeyPair;
use Gcorradomms\Ohttphp\Gateway\InMemoryGatewayKeyStore;
use Gcorradomms\Ohttphp\KeyConfig\AeadId;
use Gcorradomms\Ohttphp\KeyConfig\KeyConfigDecoder;
use Gcorradomms\Ohttphp\KeyConfig\KemId;
use Gcorradomms\Ohttphp\KeyConfig\KdfId;
use Gcorradomms\Ohttphp\KeyConfig\SymmetricSuite;
use PHPUnit\Framework\TestCase;

use function count;
use function decoct;
use function fileperms;
use function file_get_contents;
use function glob;
use function is_dir;
use function json_decode;
use function mkdir;
use function str_contains;
use function sys_get_temp_dir;
use function uniqid;

final class GatewayKeyStoreTest extends TestCase
{
    /** @var list<string> */
    private array $tempDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            self::deleteDirectory($dir);
        }
    }

    private static function deleteDirectory(string $dir): void
    {
        foreach (glob($dir . '/*') ?: [] as $file) {
            if (is_dir($file)) {
                self::deleteDirectory($file);
            } else {
                @unlink($file);
            }
        }
        @rmdir($dir);
    }

    private function tempDir(): string
    {
        $dir = sys_get_temp_dir() . '/ohttphp-test-' . uniqid('', true);
        mkdir($dir, 0700, true);
        $this->tempDirs[] = $dir;

        return $dir;
    }

    /**
     * @return list<SymmetricSuite>
     */
    private function defaultSuites(): array
    {
        return [
            SymmetricSuite::from(KdfId::HkdfSha256, AeadId::Aes128Gcm),
            SymmetricSuite::from(KdfId::HkdfSha256, AeadId::ChaCha20Poly1305),
        ];
    }

    public function testGeneratedKeyPairIsConsistent(): void
    {
        $pair = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());

        $this->assertSame(1, $pair->keyId);
        $this->assertTrue($pair->isActive());
        $this->assertNull($pair->retiredAt);

        // Public configuration derives from the private key.
        $this->assertSame(
            bin2hex($pair->publicKey()),
            bin2hex($pair->keyConfig()->publicKey)
        );
        $this->assertSame(1, $pair->keyConfig()->keyId);
        $this->assertSame(KemId::DhkemX25519HkdfSha256, $pair->keyConfig()->kemId);
    }

    public function testKeyConfigRoundTripsThroughDecoder(): void
    {
        $pair = GatewayKeyPair::generate(7, KemId::DhkemP256HkdfSha256, $this->defaultSuites());

        $decoded = (new KeyConfigDecoder())->decodeConfiguration($pair->keyConfig()->bytes());

        $this->assertSame(7, $decoded->keyId);
        $this->assertSame(KemId::DhkemP256HkdfSha256, $decoded->kemId);
        $this->assertSame($pair->keyConfig()->publicKey, $decoded->publicKey);
    }

    public function testSerializedConfigurationContainsNoSecretMaterial(): void
    {
        $pair = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());

        $encoded = $pair->keyConfig()->bytes();

        $this->assertStringNotContainsString(bin2hex($pair->secretKey->bytes), bin2hex($encoded));
        $this->assertStringNotContainsString(base64_encode($pair->secretKey->bytes), $encoded);
    }

    public function testInMemoryStoreLifecycle(): void
    {
        $store = new InMemoryGatewayKeyStore();

        $pair1 = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());
        $pair2 = GatewayKeyPair::generate(2, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());
        $store->add($pair1);
        $store->add($pair2);

        $this->assertCount(2, $store->active());
        $this->assertSame($pair1, $store->get(1));
        $this->assertNull($store->get(3));

        // Duplicate identifiers are rejected.
        $duplicate = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());
        $this->expectException(KeyStoreException::class);
        $store->add($duplicate);
    }

    public function testInMemoryRetirement(): void
    {
        $store = new InMemoryGatewayKeyStore();
        $pair = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());
        $store->add($pair);

        $store->retire(1);

        $retired = $store->get(1);
        $this->assertNotNull($retired);
        $this->assertTrue($retired->isRetired());
        $this->assertCount(0, $store->active());

        $this->expectException(KeyStoreException::class);
        $store->retire(1);
    }

    public function testFileStoreRoundTripAndPermissions(): void
    {
        $dir = $this->tempDir();
        $pair = GatewayKeyPair::generate(5, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());

        $store = new FileGatewayKeyStore($dir);
        $store->add($pair);

        // Reload from disk in a fresh instance.
        $reloaded = new FileGatewayKeyStore($dir);
        $loaded = $reloaded->get(5);
        $this->assertNotNull($loaded);
        $this->assertSame(5, $loaded->keyId);
        $this->assertSame(
            bin2hex($pair->secretKey->bytes),
            bin2hex($loaded->secretKey->bytes)
        );
        $this->assertSame($pair->publicKey(), $loaded->publicKey());

        $directoryPerms = fileperms($dir) & 0777;
        $this->assertSame(decoct(0700), decoct($directoryPerms));
        $filePerms = fileperms($dir . '/key-005.json') & 0777;
        $this->assertSame(decoct(0600), decoct($filePerms));
    }

    public function testFileStoreRejectsCorruptedSecretKey(): void
    {
        $dir = $this->tempDir();
        $pair = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());
        (new FileGatewayKeyStore($dir))->add($pair);

        // Corrupt the stored secret key.
        $path = $dir . '/key-001.json';
        /** @var array<string, mixed> $document */
        $document = json_decode(file_get_contents($path) ?: '', true, 8);
        $document['secretKey'] = base64_encode(str_repeat('X', 32));
        file_put_contents($path, json_encode($document));

        $this->expectException(KeyStoreException::class);
        new FileGatewayKeyStore($dir);
    }

    public function testFileStoreRejectsMalformedJson(): void
    {
        $dir = $this->tempDir();
        file_put_contents($dir . '/key-001.json', '{not json');

        $this->expectException(KeyStoreException::class);
        new FileGatewayKeyStore($dir);
    }

    public function testFileStoreHandlesEmptyDirectory(): void
    {
        $store = new FileGatewayKeyStore($this->tempDir());

        $this->assertCount(0, $store->active());
        $this->assertSame(1, $store->nextKeyIdentifier());
    }

    public function testFileStoreRotationAndRetirement(): void
    {
        $dir = $this->tempDir();
        $store = new FileGatewayKeyStore($dir);

        $old = GatewayKeyPair::generate(1, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());
        $new = GatewayKeyPair::generate(2, KemId::DhkemX25519HkdfSha256, $this->defaultSuites());
        $store->add($old);
        $store->add($new);
        $store->retire(1);

        $reloaded = new FileGatewayKeyStore($dir);
        $this->assertCount(1, $reloaded->active());
        $this->assertSame(2, $reloaded->active()[0]->keyId);
        $retiredOld = $reloaded->get(1);
        $this->assertNotNull($retiredOld);
        $this->assertTrue($retiredOld->isRetired());
        $this->assertNotNull($retiredOld->retiredAt);
        // Retired keys remain decryptable.
        $reloadedOld = $reloaded->get(1);
        $this->assertNotNull($reloadedOld);
        $this->assertSame($old->secretKey->bytes, $reloadedOld->secretKey->bytes);
    }

    public function testNextKeyIdentifier(): void
    {
        $store = new FileGatewayKeyStore($this->tempDir());
        $this->assertSame(1, $store->nextKeyIdentifier());

        $store->add(GatewayKeyPair::generate(3, KemId::DhkemX25519HkdfSha256, $this->defaultSuites()));
        $this->assertSame(4, $store->nextKeyIdentifier());
    }
}
