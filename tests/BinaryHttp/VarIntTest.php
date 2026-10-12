<?php

declare(strict_types=1);

namespace Gcorradomms\Ohttphp\Tests\BinaryHttp;

use Gcorradomms\Ohttphp\BinaryHttp\VarInt;
use Gcorradomms\Ohttphp\Exception\BinaryDecodingException;
use Gcorradomms\Ohttphp\Tests\Rfc9458Vectors;
use OutOfRangeException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function bin2hex;
use function strlen;

final class VarIntTest extends TestCase
{
    /** @return array<string, array{0: int, 1: string}> */
    public static function provideMinimalEncodings(): array
    {
        return [
            'zero (1 byte)' => [0, '00'],
            'max 1-byte' => [63, '3f'],
            'min 2-byte' => [64, '4040'],
            'RFC 9000 example 15293' => [15293, '7bbd'],
            'max 2-byte' => [16383, '7fff'],
            'min 4-byte' => [16384, '80004000'],
            'max 4-byte' => [1073741823, 'bfffffff'],
            'min 8-byte' => [1073741824, 'c000000040000000'],
            'RFC 9000 example' => [494878333, '9d7f3e7d'],
            'max value' => [VarInt::MAX_VALUE, 'ffffffffffffffff'],
        ];
    }

    #[DataProvider('provideMinimalEncodings')]
    public function testEncode(int $value, string $expectedHex): void
    {
        $this->assertSame($expectedHex, bin2hex(VarInt::encode($value)));
    }

    #[DataProvider('provideMinimalEncodings')]
    public function testDecodeRoundTrip(int $value, string $encodedHex): void
    {
        $decoded = VarInt::decode(Rfc9458Vectors::hex($encodedHex));
        $this->assertSame($value, $decoded['value']);
        $this->assertSame((int) (strlen($encodedHex) / 2), $decoded['nextOffset']);
    }

    public function testDecodeAcceptsNonMinimalEncoding(): void
    {
        // 0 encoded in 8 bytes, as shown in RFC 9000 Section 16.
        $decoded = VarInt::decode(Rfc9458Vectors::hex('c000000000000000'));
        $this->assertSame(0, $decoded['value']);
        $this->assertSame(8, $decoded['nextOffset']);
    }

    public function testDecodeWithOffset(): void
    {
        $buffer = Rfc9458Vectors::hex('ff31ab4040');
        $decoded = VarInt::decode($buffer, 1);
        $this->assertSame(49, $decoded['value']);
        $this->assertSame(2, $decoded['nextOffset']);

        $decoded = VarInt::decode($buffer, 3);
        $this->assertSame(64, $decoded['value']);
    }

    public function testDecodeRejectsTruncatedInput(): void
    {
        $this->expectException(BinaryDecodingException::class);
        VarInt::decode(Rfc9458Vectors::hex('7b'));
    }

    public function testDecodeRejectsEmptyInput(): void
    {
        $this->expectException(BinaryDecodingException::class);
        VarInt::decode('');
    }

    public function testDecodeRejectsNegativeOffset(): void
    {
        $this->expectException(BinaryDecodingException::class);
        VarInt::decode(Rfc9458Vectors::hex('31'), -1);
    }

    public function testEncodeRejectsNegativeValues(): void
    {
        $this->expectException(OutOfRangeException::class);
        VarInt::encode(-1);
    }

    public function testEncodeRejectsOverflow(): void
    {
        $this->expectException(OutOfRangeException::class);
        VarInt::encode(VarInt::MAX_VALUE + 1);
    }
}
