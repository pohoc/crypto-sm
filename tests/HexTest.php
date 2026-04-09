<?php

namespace CryptoSm\Tests;

use PHPUnit\Framework\TestCase;
use CryptoSm\Utils\Hex;

class HexTest extends TestCase
{
    public function testToBytesBasic()
    {
        $bytes = Hex::toBytes('0123456789abcdef');
        $this->assertEquals([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], $bytes);
    }

    public function testToBytesOddLength()
    {
        $bytes = Hex::toBytes('fff');
        $this->assertEquals([0x0f, 0xff], $bytes);
    }

    public function testToBytesWithWhitespace()
    {
        $bytes = Hex::toBytes('01 23 45');
        $this->assertEquals([0x01, 0x23, 0x45], $bytes);
    }

    public function testToBytesEmpty()
    {
        $bytes = Hex::toBytes('');
        $this->assertEquals([], $bytes);
    }

    public function testToHexBasic()
    {
        $hex = Hex::toHex([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        $this->assertEquals('0123456789abcdef', $hex);
    }

    public function testToHexEmpty()
    {
        $hex = Hex::toHex([]);
        $this->assertEquals('', $hex);
    }

    public function testToHexSingleByte()
    {
        $hex = Hex::toHex([0x00]);
        $this->assertEquals('00', $hex);
    }

    public function testToHexStringBasic()
    {
        $hex = Hex::toHexString('ABC');
        $this->assertEquals('414243', $hex);
    }

    public function testToHexStringEmpty()
    {
        $hex = Hex::toHexString('');
        $this->assertEquals('', $hex);
    }

    public function testToHexStringBinary()
    {
        $hex = Hex::toHexString(chr(0x00) . chr(0xff));
        $this->assertEquals('00ff', $hex);
    }

    public function testFromHexBasic()
    {
        $str = Hex::fromHex('414243');
        $this->assertEquals('ABC', $str);
    }

    public function testFromHexOddLength()
    {
        $str = Hex::fromHex('fff');
        $this->assertEquals(chr(0x0f) . chr(0xff), $str);
    }

    public function testFromHexEmpty()
    {
        $str = Hex::fromHex('');
        $this->assertEquals('', $str);
    }

    public function testFromHexWithWhitespace()
    {
        $str = Hex::fromHex('41 42');
        $this->assertEquals('AB', $str);
    }

    public function testRoundTripToBytesToHex()
    {
        $original = 'deadbeef0102030405';
        $bytes = Hex::toBytes($original);
        $result = Hex::toHex($bytes);
        $this->assertEquals($original, $result);
    }

    public function testRoundTripToHexStringFromHex()
    {
        $original = 'Hello World';
        $hex = Hex::toHexString($original);
        $result = Hex::fromHex($hex);
        $this->assertEquals($original, $result);
    }

    public function testFromHexAllZeros()
    {
        $str = Hex::fromHex('00000000');
        $this->assertEquals("\x00\x00\x00\x00", $str);
    }

    public function testFromHexAllOnes()
    {
        $str = Hex::fromHex('ffffffff');
        $this->assertEquals("\xff\xff\xff\xff", $str);
    }
}
