<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Gateway;

use Gcorradomms\Ohttphp\Exception\KeyStoreException;

/**
 * Storage for gateway key pairs.
 *
 * Implementations must enforce key identifier uniqueness among all keys
 * they accept, and must never expose secret key material outside of
 * GatewayKeyPair objects.
 */
interface GatewayKeyStoreInterface
{
    /**
     * Store a new key pair.
     *
     * @throws KeyStoreException When the key identifier is already in use
     *     or the key pair cannot be persisted
     */
    public function add(GatewayKeyPair $keyPair): void;

    /**
     * Fetch a key pair by key identifier, regardless of lifecycle state.
     */
    public function get(int $keyId): ?GatewayKeyPair;

    /**
     * All keys in the active state, in stable order. These are the keys
     * advertised to clients in the public key configuration.
     *
     * @return list<GatewayKeyPair>
     */
    public function active(): array;

    /**
     * Move a key to the retired state. Retired keys continue to decrypt
     * requests from clients that still hold the old configuration, but are
     * excluded from the published key configuration.
     *
     * @throws KeyStoreException When the key is unknown or already retired
     */
    public function retire(int $keyId): void;
}
