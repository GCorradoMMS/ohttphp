<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway;

use Gcorradomms\Ohttphp\Exception\KeyStoreException;

use function array_values;
use function ksort;

/**
 * Key store that keeps key pairs in process memory. Suitable for tests
 * and ephemeral deployments; keys are lost when the process exits.
 */
final class InMemoryGatewayKeyStore implements GatewayKeyStoreInterface
{
    /** @var array<int, GatewayKeyPair> */
    private array $keys = [];

    public function add(GatewayKeyPair $keyPair): void
    {
        if (isset($this->keys[$keyPair->keyId])) {
            throw new KeyStoreException('A key with this identifier already exists');
        }
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
                $active[$key->keyId] = $key;
            }
        }
        ksort($active);

        /** @var list<GatewayKeyPair> */
        return array_values($active);
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
        $this->keys[$keyId] = $key->retired();
    }
}
