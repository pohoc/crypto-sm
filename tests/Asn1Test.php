<?php

namespace CryptoSm\Tests;

use PHPUnit\Framework\TestCase;
use CryptoSm\Crypto\Asn1;
use CryptoSm\Exception\CryptoException;

class Asn1Test extends TestCase
{
    public function testEncodeDecodeInteger()
    {
        $hex = '01';
        $encoded = Asn1::encodeInteger($hex);
        $this->assertStringStartsWith(chr(0x02), $encoded); // INTEGER tag

        // Decode it back
        $offset = 0;
        $decoded = Asn1::decodeInteger($encoded, $offset);
        $this->assertEquals('1', $decoded);
    }

    public function testEncodeIntegerLeadingZeroByte()
    {
        // Value > 0x7f should get a leading 0x00 byte
        $hex = 'ff';
        $encoded = Asn1::encodeInteger($hex);
        $this->assertStringContainsString("\x00\xff", $encoded);
    }

    public function testEncodeIntegerStripsLeadingZeros()
    {
        $hex = '0001';
        $encoded = Asn1::encodeInteger($hex);
        // Should strip the leading 00
        $this->assertFalse(strpos($encoded, "\x00\x01") === 0);
    }

    public function testEncodeDecodeSequence()
    {
        $content = "\x02\x01\x01\x02\x01\x02"; // Two integers
        $encoded = Asn1::encodeSequence($content);
        $this->assertEquals(chr(0x30), $encoded[0]); // SEQUENCE tag
    }

    public function testEncodeDecodeDerSignature()
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

    public function testEncodeDecodeDerSignatureFull()
    {
        $rHex = str_repeat('a', 64);
        $sHex = str_repeat('b', 64);

        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }

    public function testDecodeDerSignatureInvalidHex()
    {
        $this->expectException(CryptoException::class);
        Asn1::decodeDerSignature('not-valid-hex!');
    }

    public function testEncodeIntegerInvalidHex()
    {
        $this->expectException(CryptoException::class);
        Asn1::encodeInteger('zz');
    }

    public function testEncodeDecodeDerSignaturePadding()
    {
        // Ensure 64-char padded values round-trip correctly
        $rHex = str_pad('ff', 64, '0', STR_PAD_LEFT);
        $sHex = str_pad('abcd', 64, '0', STR_PAD_LEFT);

        $der = Asn1::encodeDerSignature($rHex, $sHex);
        [$decodedR, $decodedS] = Asn1::decodeDerSignature($der);
        $this->assertEquals($rHex, $decodedR);
        $this->assertEquals($sHex, $decodedS);
    }
}
