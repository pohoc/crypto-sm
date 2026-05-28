<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Exception\CryptoException;
use PHPUnit\Framework\TestCase;

class Asn1Test extends TestCase
{
    // ========================================================================
    // encodeInteger / decodeInteger 往返测试
    // ========================================================================

    public function testEncodeDecodeInteger(): void
    {
        $hex = '01';
        $encoded = Asn1::encodeInteger($hex);
        $this->assertStringStartsWith(chr(0x02), $encoded);

        $offset = 0;
        $decoded = Asn1::decodeInteger($encoded, $offset);
        $this->assertEquals('1', $decoded);
    }

    public function testEncodeIntegerLeadingZeroByte(): void
    {
        $hex = 'ff';
        $encoded = Asn1::encodeInteger($hex);
        $this->assertStringContainsString("\x00\xff", $encoded);
    }

    public function testEncodeIntegerStripsLeadingZeros(): void
    {
        $hex = '0001';
        $encoded = Asn1::encodeInteger($hex);
        $this->assertFalse(strpos($encoded, "\x00\x01") === 0);
    }

    public function testEncodeDecodeSequence(): void
    {
        $content = "\x02\x01\x01\x02\x01\x02";
        $encoded = Asn1::encodeSequence($content);
        $this->assertEquals(chr(0x30), $encoded[0]);
    }

    public function testEncodeDecodeDerSignature(): void
    {
        $rHex = str_pad('1', 64, '0', STR_PAD_LEFT);
        $sHex = str_pad('2', 64, '0', STR_PAD_LEFT);

        $der = Asn1::encodeDerSignature($rHex, $sHex);
        $this->assertNotEmpty($der);
        $this->assertTrue(ctype_xdigit($der));

        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }

    public function testEncodeDecodeDerSignatureFull(): void
    {
        $rHex = str_repeat('a', 64);
        $sHex = str_repeat('b', 64);

        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }

    public function testDecodeDerSignatureInvalidHex(): void
    {
        $this->expectException(CryptoException::class);
        Asn1::decodeDerSignature('not-valid-hex!');
    }

    public function testEncodeIntegerInvalidHex(): void
    {
        $this->expectException(CryptoException::class);
        Asn1::encodeInteger('zz');
    }

    public function testEncodeDecodeDerSignaturePadding(): void
    {
        $rHex = str_pad('ff', 64, '0', STR_PAD_LEFT);
        $sHex = str_pad('abcd', 64, '0', STR_PAD_LEFT);

        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }

    // ========================================================================
    // DER 长度编码边界测试 (encodeLength via encodeInteger/encodeSequence)
    // ========================================================================

    public function testEncodeIntegerShortLength(): void
    {
        // 1 字节值: 长度 < 128, DER 编码长度为单字节
        $hex = '7f'; // 1 字节, < 0x80, 无需前导零
        $encoded = Asn1::encodeInteger($hex);
        // 0x02 0x01 0x7f
        $this->assertEquals("\x02\x01\x7f", $encoded);
    }

    public function testEncodeIntegerMediumLength(): void
    {
        // 128 字节 hex = 128 bytes, 首字节 0xAB > 0x7F → 添加前导零 → 129 bytes
        // 长度 129 = 0x81, 需要多字节长度编码: 0x81 0x81
        $hex = str_repeat('ab', 128);
        $encoded = Asn1::encodeInteger($hex);
        $this->assertEquals(chr(0x02), $encoded[0]);
        $this->assertEquals(chr(0x81), $encoded[1]); // 长度用1字节表示
        $this->assertEquals(chr(0x81), $encoded[2]); // 长度值 129
    }

    public function testEncodeIntegerLongLength(): void
    {
        // 256 字节 hex = 256 bytes, 首字节 0xCD > 0x7F → 添加前导零 → 257 bytes
        // 长度 257 = 0x0101, 需要多字节长度编码: 0x82 0x01 0x01
        $hex = str_repeat('cd', 256);
        $encoded = Asn1::encodeInteger($hex);
        $this->assertEquals(chr(0x02), $encoded[0]);
        $this->assertEquals(chr(0x82), $encoded[1]); // 长度用2字节表示
        $this->assertEquals(chr(0x01), $encoded[2]); // 高位
        $this->assertEquals(chr(0x01), $encoded[3]); // 低位 → 257
    }

    public function testEncodeSequenceShortLength(): void
    {
        $content = str_repeat('A', 10);
        $encoded = Asn1::encodeSequence($content);
        // 0x30 0x0A ...
        $this->assertEquals(chr(0x30), $encoded[0]);
        $this->assertEquals(chr(10), $encoded[1]);
    }

    public function testEncodeSequenceMediumLength(): void
    {
        $content = str_repeat('A', 200);
        $encoded = Asn1::encodeSequence($content);
        // 0x30 0x81 0xC8 ...
        $this->assertEquals(chr(0x30), $encoded[0]);
        $this->assertEquals(chr(0x81), $encoded[1]);
        $this->assertEquals(chr(200), $encoded[2]);
    }

    // ========================================================================
    // decodeInteger / decodeSequence 异常测试
    // ========================================================================

    public function testDecodeIntegerInvalidTag(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid INTEGER tag');
        $data = "\x30\x01\x01"; // SEQUENCE tag instead of INTEGER
        $offset = 0;
        Asn1::decodeInteger($data, $offset);
    }

    public function testDecodeSequenceInvalidTag(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid SEQUENCE tag');
        $data = "\x02\x01\x01"; // INTEGER tag instead of SEQUENCE
        $offset = 0;
        Asn1::decodeSequence($data, $offset);
    }

    public function testDecodeIntegerMultiByteLength(): void
    {
        // 构造带多字节长度的 DER INTEGER
        // 0x02 0x81 0x80 [128 positive bytes]
        $der = chr(0x02) . chr(0x81) . chr(0x80) . str_repeat(chr(0x2B), 128);
        $offset = 0;
        $result = Asn1::decodeInteger($der, $offset);
        $this->assertNotEmpty($result);
        $this->assertEquals(strlen($der), $offset);
    }

    public function testDecodeSequenceMultiByteLength(): void
    {
        // 0x30 0x81 0x80 [128 bytes of content]
        $content = str_repeat("\x00", 128);
        $der = chr(0x30) . chr(0x81) . chr(0x80) . $content;
        $offset = 0;
        $seqLen = Asn1::decodeSequence($der, $offset);
        $this->assertEquals(strlen($content), $seqLen);
    }

    // ========================================================================
    // encodeInteger 边界值测试
    // ========================================================================

    public function testEncodeIntegerZero(): void
    {
        $hex = '00';
        $encoded = Asn1::encodeInteger($hex);
        $offset = 0;
        $decoded = Asn1::decodeInteger($encoded, $offset);
        $this->assertEquals('0', $decoded);
    }

    public function testEncodeIntegerOne(): void
    {
        $hex = '01';
        $encoded = Asn1::encodeInteger($hex);
        $offset = 0;
        $decoded = Asn1::decodeInteger($encoded, $offset);
        $this->assertEquals('1', $decoded);
    }

    public function testEncodeIntegerMaxByte(): void
    {
        $hex = 'ff';
        $encoded = Asn1::encodeInteger($hex);
        // ff > 0x7f → 应添加前导零
        $offset = 0;
        $decoded = Asn1::decodeInteger($encoded, $offset);
        $this->assertEquals('255', $decoded);
    }

    public function testEncodeIntegerEmptyHexRejected(): void
    {
        $this->expectException(CryptoException::class);
        Asn1::encodeInteger('');
    }

    // ========================================================================
    // decodeDerSignature 错误输入测试
    // ========================================================================

    public function testDecodeDerSignatureEmptyString(): void
    {
        $this->expectException(CryptoException::class);
        Asn1::decodeDerSignature('');
    }

    public function testDecodeDerSignatureMalformedSequence(): void
    {
        // 0x01 不是有效的 SEQUENCE 标签 → 应抛出 CryptoException
        $this->expectException(CryptoException::class);
        Asn1::decodeDerSignature('0101020101');
    }

    public function testDecodeDerSignatureRejectsTrailingBytes(): void
    {
        $der = '3006020101020101ff';
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid DER signature structure');
        Asn1::decodeDerSignature($der);
    }

    public function testDecodeIntegerUnexpectedEndOfData(): void
    {
        $offset = 0;
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Unexpected end of ASN.1 data');
        Asn1::decodeInteger('', $offset);
    }

    public function testDecodeSequenceUnexpectedEndOfData(): void
    {
        $offset = 0;
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Unexpected end of ASN.1 data');
        Asn1::decodeSequence('', $offset);
    }

    // ========================================================================
    // 常量验证
    // ========================================================================

    public function testAsn1Constants(): void
    {
        $this->assertEquals(0x30, Asn1::TAG_SEQUENCE);
        $this->assertEquals(0x02, Asn1::TAG_INTEGER);
        $this->assertEquals(0x04, Asn1::TAG_OCTET_STRING);
    }

    // ========================================================================
    // DER 往返一致性 (随机签名值)
    // ========================================================================

    public function testDerSignatureRoundTripWithHighValues(): void
    {
        // r 和 s 值的高位字节 > 0x7f, 需要前导零
        $rHex = str_repeat('f', 64);
        $sHex = str_repeat('e', 64);

        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }

    public function testDerSignatureRoundTripWithMixedValues(): void
    {
        // r 的第一个字节 < 0x80, s 的第一个字节 > 0x80
        $rHex = str_pad('1', 64, '0', STR_PAD_LEFT);
        $sHex = str_repeat('ff', 32);

        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }

    // ========================================================================
    // encodeSequence 长长度测试
    // ========================================================================

    public function testEncodeSequenceLongLength(): void
    {
        // 300 字节内容 → 长度需要 0x82 前缀
        $content = str_repeat('A', 300);
        $encoded = Asn1::encodeSequence($content);
        $this->assertEquals(chr(0x30), $encoded[0]);
        $this->assertEquals(chr(0x82), $encoded[1]); // 2 字节长度
        $this->assertEquals(chr(1), $encoded[2]);     // 高位
        $this->assertEquals(chr(44), $encoded[3]);    // 低位 → 300
    }

    // ========================================================================
    // decodeInteger 2 字节多字节长度
    // ========================================================================

    public function testDecodeIntegerTwoByteLength(): void
    {
        // 构造 0x02 0x82 0x01 0x00 [256 bytes of 0x41]
        $der = chr(0x02) . chr(0x82) . chr(0x01) . chr(0x00) . str_repeat(chr(0x41), 256);
        $offset = 0;
        $result = Asn1::decodeInteger($der, $offset);
        $this->assertNotEmpty($result);
        $this->assertEquals(strlen($der), $offset);
    }

    public function testDecodeSequenceTwoByteLength(): void
    {
        // 0x30 0x82 0x01 0x00 [256 bytes of content]
        $content = str_repeat("\x00", 256);
        $der = chr(0x30) . chr(0x82) . chr(0x01) . chr(0x00) . $content;
        $offset = 0;
        $seqLen = Asn1::decodeSequence($der, $offset);
        $this->assertEquals(256, $seqLen);
    }

    // ========================================================================
    // encodeLength len=128 边界
    // ========================================================================

    public function testEncodeIntegerExact128ByteContent(): void
    {
        // 128 字节 hex, 首字节 < 0x80 → 无前导零 → 正好 128 bytes
        // 长度 128 = 0x80 → 多字节编码: 0x81 0x80
        $hex = str_repeat('7f', 128);
        $encoded = Asn1::encodeInteger($hex);
        $this->assertEquals(chr(0x02), $encoded[0]);
        $this->assertEquals(chr(0x81), $encoded[1]); // 长度用1字节表示
        $this->assertEquals(chr(0x80), $encoded[2]); // 长度值 128
    }

    // ========================================================================
    // 往返验证更多值
    // ========================================================================

    public function testDerSignatureRoundTripWithSmallValues(): void
    {
        // r 和 s 都很小
        $rHex = str_pad('ff', 64, '0', STR_PAD_LEFT);
        $sHex = str_pad('1', 64, '0', STR_PAD_LEFT);
        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }

    public function testEncodeIntegerLargeValueRoundTrip(): void
    {
        // 大数值：64 字节
        $hex = str_repeat('ab', 32);
        $encoded = Asn1::encodeInteger($hex);
        $offset = 0;
        $decoded = Asn1::decodeInteger($encoded, $offset);
        $this->assertEquals(gmp_strval(gmp_init($hex, 16), 10), $decoded);
    }

    public function testEncodeDecodeDerSignatureWithZeroPrefixR(): void
    {
        // r 以 0x00..开头 (被 strip 后为小值)
        $rHex = str_pad('1', 64, '0', STR_PAD_LEFT);
        $sHex = str_pad('2', 64, '0', STR_PAD_LEFT);
        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }
}
