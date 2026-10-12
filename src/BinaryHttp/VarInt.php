<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\BinaryHttp;

use Gcorradomms\Ohttphp\Exception\BinaryDecodingException;

use function ord;
use function pack;
use function strlen;
use function substr;
use function unpack;

/**
 * Variable-length integer encoding defined in Section 16 of RFC 9000 (QUIC),
 * as referenced by RFC 9292 (Binary HTTP) for all length and numeric fields.
 *
 * Values are encoded in network byte order with a 2-bit length prefix:
 * the two most significant bits of the first byte indicate how many bytes
 * follow (1, 2, 4, or 8), allowing values up to 2^62 - 1.
 */
final class VarInt
{
    /**
     * Maximum representable value (2^62 - 1).
     */
    public const MAX_VALUE = (1 << 62) - 1;

    private const VALUE_MASK_1 = 0x3F;
    private const VALUE_MASK_2 = 0x3FFF;
    private const VALUE_MASK_4 = 0x3FFFFFFF;
    private const VALUE_MASK_8 = 0x3FFFFFFFFFFFFFFF;

    private function __construct()
    {
    }

    /**
     * Encode an integer using the minimum number of bytes necessary.
     * Values must lie between 0 and 2^62 - 1 (MAX_VALUE).
     *
     * @param int $value
     * @return string Binary representation
     * @throws \OutOfRangeException When the value is out of range
     */
    public static function encode(int $value): string
    {
        if ($value < 0 || $value > self::MAX_VALUE) {
            throw new \OutOfRangeException('Variable-length integer out of range: ' . $value);
        }
        if ($value <= self::VALUE_MASK_1) {
            return pack('C', $value);
        }
        if ($value <= self::VALUE_MASK_2) {
            return pack('n', $value | 0x4000);
        }
        if ($value <= self::VALUE_MASK_4) {
            return pack('N', $value | 0x80000000);
        }

        return pack('J', $value | (0xC0 << 56));
    }

    /**
     * Decode a variable-length integer starting at the given offset.
     *
     * @param string $bytes Buffer to decode from
     * @param int $offset Offset of the first byte of the integer
     * @return array{value: int, nextOffset: int} The decoded value and the
     *     offset immediately after the encoded integer
     * @throws BinaryDecodingException When the buffer ends mid-integer
     */
    public static function decode(string $bytes, int $offset = 0): array
    {
        $length = strlen($bytes);
        if ($offset < 0 || $offset >= $length) {
            throw new BinaryDecodingException('Truncated variable-length integer');
        }
        $prefix = ord($bytes[$offset]) >> 6;
        $size = 1 << $prefix;
        if ($offset + $size > $length) {
            throw new BinaryDecodingException('Truncated variable-length integer');
        }
        $encoded = substr($bytes, $offset, $size);
        /** @var array<int, int> $parts */
        $parts = unpack(
            match ($size) {
                1 => 'C',
                2 => 'n',
                4 => 'N',
                default => 'J',
            },
            $encoded
        );
        $raw = (int) ($parts[1] ?? throw new BinaryDecodingException('Invalid variable-length integer'));
        $value = $raw & match ($size) {
            1 => self::VALUE_MASK_1,
            2 => self::VALUE_MASK_2,
            4 => self::VALUE_MASK_4,
            default => self::VALUE_MASK_8,
        };

        return ['value' => $value, 'nextOffset' => $offset + $size];
    }
}
