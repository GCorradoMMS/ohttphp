<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\KeyConfig;

use ArrayIterator;
use Countable;
use Gcorradomms\Ohttphp\Exception\InvalidKeyConfigurationException;
use IteratorAggregate;

use function count;

/**
 * An ordered collection of OHTTP key configurations, as distributed in the
 * "application/ohttp-keys" format (RFC 9458, Section 3.2).
 *
 * @implements IteratorAggregate<int, KeyConfig>
 */
final class KeyConfigCollection implements IteratorAggregate, Countable
{
    /** @var list<KeyConfig> */
    private readonly array $configs;

    /**
     * @param list<KeyConfig> $configs One or more configurations
     *
     * @throws InvalidKeyConfigurationException When the list is empty
     */
    public function __construct(array $configs)
    {
        if (count($configs) === 0) {
            throw new InvalidKeyConfigurationException('A key configuration collection must not be empty');
        }
        $this->configs = $configs;
    }

    /**
     * Parse an "application/ohttp-keys" encoded collection.
     *
     * @throws InvalidKeyConfigurationException When the collection is invalid
     */
    public static function fromEncoded(string $bytes): self
    {
        return (new KeyConfigDecoder())->decodeCollection($bytes);
    }

    /**
     * @return ArrayIterator<int, KeyConfig>
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->configs);
    }

    public function count(): int
    {
        return count($this->configs);
    }

    /**
     * @return list<KeyConfig>
     */
    public function toArray(): array
    {
        return $this->configs;
    }
}
