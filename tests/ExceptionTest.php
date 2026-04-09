<?php

namespace CryptoSm\Tests;

use CryptoSm\Exception\SmCryptoException;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use PHPUnit\Framework\TestCase;

/**
 * 异常类层次结构测试
 */
class ExceptionTest extends TestCase
{
    public function testCryptoExceptionExtendsBase()
    {
        $e = new CryptoException('test');
        $this->assertInstanceOf(SmCryptoException::class, $e);
        $this->assertInstanceOf(\Exception::class, $e);
        $this->assertEquals('test', $e->getMessage());
    }

    public function testInvalidKeyExceptionExtendsBase()
    {
        $e = new InvalidKeyException('invalid');
        $this->assertInstanceOf(SmCryptoException::class, $e);
        $this->assertInstanceOf(\Exception::class, $e);
        $this->assertEquals('invalid', $e->getMessage());
    }

    public function testCryptoExceptionCanBeCaughtByBase()
    {
        try {
            throw new CryptoException('crypto error');
        } catch (SmCryptoException $e) {
            $this->assertEquals('crypto error', $e->getMessage());
            return;
        }
        $this->fail('CryptoException should be caught as SmCryptoException');
    }

    public function testInvalidKeyExceptionCanBeCaughtByBase()
    {
        try {
            throw new InvalidKeyException('key error');
        } catch (SmCryptoException $e) {
            $this->assertEquals('key error', $e->getMessage());
            return;
        }
        $this->fail('InvalidKeyException should be caught as SmCryptoException');
    }

    public function testBothExceptionsCaughtByBase()
    {
        $exceptions = [
            new CryptoException('a'),
            new InvalidKeyException('b'),
        ];

        foreach ($exceptions as $e) {
            $this->assertInstanceOf(SmCryptoException::class, $e);
        }
    }

    public function testSm2ThrowsCorrectExceptionOnInvalidKey()
    {
        try {
            \CryptoSm\SM2\Sm2::doEncrypt('msg', str_repeat('1', 128));
        } catch (InvalidKeyException $e) {
            $this->assertInstanceOf(SmCryptoException::class, $e);
            return;
        }
        $this->fail('Should throw InvalidKeyException');
    }

    public function testSm4ThrowsCorrectExceptionOnInvalidKey()
    {
        try {
            \CryptoSm\SM4\Sm4::encrypt('msg', 'badkey');
        } catch (InvalidKeyException $e) {
            $this->assertInstanceOf(SmCryptoException::class, $e);
            return;
        }
        $this->fail('Should throw InvalidKeyException');
    }
}
