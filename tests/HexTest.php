<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Utils\Hex;
use PHPUnit\Framework\TestCase;

class HexTest extends TestCase
{
    // ========================================================================
    // toBytes
    // ========================================================================

    public function testToBytesBasic(): void
    {
        $bytes = Hex::toBytes('0123456789abcdef');
        $this->assertEquals([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], $bytes);
    }

    public function testToBytesOddLength(): void
    {
        $bytes = Hex::toBytes('fff');
        $this->assertEquals([0x0f, 0xff], $bytes);
    }

    public function testToBytesWithWhitespace(): void
    {
        $bytes = Hex::toBytes('01 23 45');
        $this->assertEquals([0x01, 0x23, 0x45], $bytes);
    }

    public function testToBytesEmpty(): void
    {
        $bytes = Hex::toBytes('');
        $this->assertEquals([], $bytes);
    }

    public function testToBytesAllZeros(): void
    {
        $bytes = Hex::toBytes('0000');
        $this->assertEquals([0x00, 0x00], $bytes);
    }

    public function testToBytesAllOnes(): void
    {
        $bytes = Hex::toBytes('ffffff');
        $this->assertEquals([0xff, 0xff, 0xff], $bytes);
    }

    public function testToBytesSingleByte(): void
    {
        $bytes = Hex::toBytes('ab');
        $this->assertEquals([0xab], $bytes);
    }

    public function testToBytesStripsNonHex(): void
    {
        $bytes = Hex::toBytes('01-23:45');
        $this->assertEquals([0x01, 0x23, 0x45], $bytes);
    }

    // ========================================================================
    // toHex
    // ========================================================================

    public function testToHexBasic(): void
    {
        $hex = Hex::toHex([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        $this->assertEquals('0123456789abcdef', $hex);
    }

    public function testToHexEmpty(): void
    {
        $hex = Hex::toHex([]);
        $this->assertEquals('', $hex);
    }

    public function testToHexSingleByte(): void
    {
        $hex = Hex::toHex([0x00]);
        $this->assertEquals('00', $hex);
    }

    public function testToHexAllOnes(): void
    {
        $hex = Hex::toHex([0xff, 0xff]);
        $this->assertEquals('ffff', $hex);
    }

    public function testToHexIsLowerCase(): void
    {
        $hex = Hex::toHex([0xab, 0xcd]);
        $this->assertEquals('abcd', $hex);
    }

    // ========================================================================
    // toHexString
    // ========================================================================

    public function testToHexStringBasic(): void
    {
        $hex = Hex::toHexString('ABC');
        $this->assertEquals('414243', $hex);
    }

    public function testToHexStringEmpty(): void
    {
        $hex = Hex::toHexString('');
        $this->assertEquals('', $hex);
    }

    public function testToHexStringBinary(): void
    {
        $hex = Hex::toHexString(chr(0x00) . chr(0xff));
        $this->assertEquals('00ff', $hex);
    }

    public function testToHexStringChinese(): void
    {
        $hex = Hex::toHexString('你');
        $this->assertNotEmpty($hex);
        $this->assertTrue(ctype_xdigit($hex));
    }

    // ========================================================================
    // fromHex
    // ========================================================================

    public function testFromHexBasic(): void
    {
        $str = Hex::fromHex('414243');
        $this->assertEquals('ABC', $str);
    }

    public function testFromHexOddLength(): void
    {
        $str = Hex::fromHex('fff');
        $this->assertEquals(chr(0x0f) . chr(0xff), $str);
    }

    public function testFromHexEmpty(): void
    {
        $str = Hex::fromHex('');
        $this->assertEquals('', $str);
    }

    public function testFromHexWithWhitespace(): void
    {
        $str = Hex::fromHex('41 42');
        $this->assertEquals('AB', $str);
    }

    public function testFromHexAllZeros(): void
    {
        $str = Hex::fromHex('00000000');
        $this->assertEquals("\x00\x00\x00\x00", $str);
    }

    public function testFromHexAllOnes(): void
    {
        $str = Hex::fromHex('ffffffff');
        $this->assertEquals("\xff\xff\xff\xff", $str);
    }

    public function testFromHexStripsNonHex(): void
    {
        $str = Hex::fromHex('41-42');
        $this->assertEquals('AB', $str);
    }

    // ========================================================================
    // 往返一致性
    // ========================================================================

    public function testRoundTripToBytesToHex(): void
    {
        $original = 'deadbeef0102030405';
        $bytes = Hex::toBytes($original);
        $result = Hex::toHex($bytes);
        $this->assertEquals($original, $result);
    }

    public function testRoundTripToHexStringFromHex(): void
    {
        $original = 'Hello World';
        $hex = Hex::toHexString($original);
        $result = Hex::fromHex($hex);
        $this->assertEquals($original, $result);
    }

    public function testRoundTripFromHexToHexString(): void
    {
        $original = '48656c6c6f';
        $str = Hex::fromHex($original);
        $result = Hex::toHexString($str);
        $this->assertEquals($original, $result);
    }

    public function testRoundTripChineseText(): void
    {
        $original = '你好世界';
        $hex = Hex::toHexString($original);
        $result = Hex::fromHex($hex);
        $this->assertEquals($original, $result);
    }

    // ========================================================================
    // 边界情况
    // ========================================================================

    public function testToBytesUpperCase(): void
    {
        $bytes1 = Hex::toBytes('abcdef');
        $bytes2 = Hex::toBytes('ABCDEF');
        $this->assertEquals($bytes1, $bytes2);
    }

    public function testFromHexUpperCase(): void
    {
        $str1 = Hex::fromHex('abcdef');
        $str2 = Hex::fromHex('ABCDEF');
        $this->assertEquals($str1, $str2);
    }

    public function testToBytesLongInput(): void
    {
        $hex = str_repeat('ab', 1000);
        $bytes = Hex::toBytes($hex);
        $this->assertCount(1000, $bytes);
    }

    public function testFromHexLongInput(): void
    {
        $hex = str_repeat('cd', 1000);
        $str = Hex::fromHex($hex);
        $this->assertEquals(1000, strlen($str));
    }

    // ========================================================================
    // 纯非 hex 输入
    // ========================================================================

    public function testToBytesAllNonHex(): void
    {
        $bytes = Hex::toBytes('xyz!@#');
        $this->assertEquals([], $bytes);
    }

    public function testFromHexAllNonHex(): void
    {
        $str = Hex::fromHex('xyz!@#');
        $this->assertEquals('', $str);
    }

    // ========================================================================
    // toBytes / fromHex 零边界
    // ========================================================================

    public function testToBytesSingleHexChar(): void
    {
        // 'f' → '0f' → [0x0f]
        $bytes = Hex::toBytes('f');
        $this->assertEquals([0x0f], $bytes);
    }

    public function testFromHexSingleHexChar(): void
    {
        $str = Hex::fromHex('f');
        $this->assertEquals(chr(0x0f), $str);
    }

    // ========================================================================
    // toHex 边界
    // ========================================================================

    public function testToHexMaxByte(): void
    {
        $hex = Hex::toHex([0xff]);
        $this->assertEquals('ff', $hex);
    }

    public function testToHexZeroByte(): void
    {
        $hex = Hex::toHex([0x00]);
        $this->assertEquals('00', $hex);
    }

    // ========================================================================
    // toHexString 特殊字符
    // ========================================================================

    public function testToHexStringNullByte(): void
    {
        $hex = Hex::toHexString(chr(0));
        $this->assertEquals('00', $hex);
    }

    // ========================================================================
    // 往返一致性 - toBytes ↔ toHex (含边界值)
    // ========================================================================

    public function testRoundTripWithZeroBytes(): void
    {
        $hex = '0000000000000000';
        $bytes = Hex::toBytes($hex);
        $result = Hex::toHex($bytes);
        $this->assertEquals($hex, $result);
    }

    public function testRoundTripWithMaxBytes(): void
    {
        $hex = 'ffffffffffffffff';
        $bytes = Hex::toBytes($hex);
        $result = Hex::toHex($bytes);
        $this->assertEquals($hex, $result);
    }
}
