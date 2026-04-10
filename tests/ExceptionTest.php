<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Exception\SmCryptoException;
use PHPUnit\Framework\TestCase;

/**
 * 异常类层次结构测试
 */
class ExceptionTest extends TestCase
{
    // ========================================================================
    // 继承层次
    // ========================================================================

    public function testCryptoExceptionExtendsBase(): void
    {
        $e = new CryptoException('test');
        $this->assertInstanceOf(SmCryptoException::class, $e);
        $this->assertInstanceOf(\Exception::class, $e);
        $this->assertEquals('test', $e->getMessage());
    }

    public function testInvalidKeyExceptionExtendsBase(): void
    {
        $e = new InvalidKeyException('invalid');
        $this->assertInstanceOf(SmCryptoException::class, $e);
        $this->assertInstanceOf(\Exception::class, $e);
        $this->assertEquals('invalid', $e->getMessage());
    }

    public function testCryptoExceptionCanBeCaughtByBase(): void
    {
        $this->expectException(SmCryptoException::class);
        $this->expectExceptionMessage('crypto error');
        throw new CryptoException('crypto error');
    }

    public function testInvalidKeyExceptionCanBeCaughtByBase(): void
    {
        $this->expectException(SmCryptoException::class);
        $this->expectExceptionMessage('key error');
        throw new InvalidKeyException('key error');
    }

    public function testBothExceptionsCaughtByBase(): void
    {
        $exceptions = [
            new CryptoException('a'),
            new InvalidKeyException('b'),
        ];
        foreach ($exceptions as $e) {
            $this->assertInstanceOf(SmCryptoException::class, $e);
        }
    }

    // ========================================================================
    // 特定捕获
    // ========================================================================

    public function testCryptoExceptionCaughtSpecifically(): void
    {
        try {
            throw new CryptoException('specific');
        } catch (CryptoException $e) {
            $this->assertEquals('specific', $e->getMessage());
        }
    }

    public function testInvalidKeyExceptionCaughtSpecifically(): void
    {
        try {
            throw new InvalidKeyException('key specific');
        } catch (InvalidKeyException $e) {
            $this->assertEquals('key specific', $e->getMessage());
        }
    }

    // ========================================================================
    // 集成测试: SM2/SM4 抛出正确的异常
    // ========================================================================

    public function testSm2ThrowsCorrectExceptionOnInvalidKey(): void
    {
        try {
            \CryptoSm\SM2\Sm2::doEncrypt('msg', str_repeat('1', 128));
        } catch (InvalidKeyException $e) {
            $this->assertInstanceOf(SmCryptoException::class, $e);
            return;
        }
        $this->fail('Should throw InvalidKeyException');
    }

    public function testSm4ThrowsCorrectExceptionOnInvalidKey(): void
    {
        try {
            \CryptoSm\SM4\Sm4::encrypt('msg', 'badkey');
        } catch (InvalidKeyException $e) {
            $this->assertInstanceOf(SmCryptoException::class, $e);
            return;
        }
        $this->fail('Should throw InvalidKeyException');
    }

    // ========================================================================
    // 异常代码
    // ========================================================================

    public function testCryptoExceptionCode(): void
    {
        $e = new CryptoException('msg', 100);
        $this->assertEquals(100, $e->getCode());
    }

    public function testInvalidKeyExceptionCode(): void
    {
        $e = new InvalidKeyException('msg', 200);
        $this->assertEquals(200, $e->getCode());
    }

    // ========================================================================
    // SmCryptoException 是抽象基类
    // ========================================================================

    public function testSmCryptoExceptionIsBaseClass(): void
    {
        $this->assertTrue(class_exists(SmCryptoException::class));
        $ref = new \ReflectionClass(SmCryptoException::class);
        $this->assertTrue($ref->isSubclassOf(\Exception::class));
    }

    // ========================================================================
    // SmCryptoException 直接实例化
    // ========================================================================

    public function testSmCryptoExceptionCanBeInstantiated(): void
    {
        $e = new SmCryptoException('base error');
        $this->assertInstanceOf(\Exception::class, $e);
        $this->assertEquals('base error', $e->getMessage());
    }

    public function testSmCryptoExceptionCanBeCaughtDirectly(): void
    {
        try {
            throw new SmCryptoException('direct');
        } catch (SmCryptoException $e) {
            $this->assertEquals('direct', $e->getMessage());
        }
    }

    // ========================================================================
    // 异常链 (previous)
    // ========================================================================

    public function testCryptoExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('root cause');
        $e = new CryptoException('wrapped', 0, $previous);
        $this->assertSame($previous, $e->getPrevious());
    }

    public function testInvalidKeyExceptionWithPrevious(): void
    {
        $previous = new \InvalidArgumentException('bad arg');
        $e = new InvalidKeyException('invalid', 0, $previous);
        $this->assertSame($previous, $e->getPrevious());
    }

    // ========================================================================
    // 异常层次结构验证
    // ========================================================================

    public function testExceptionHierarchy(): void
    {
        $cryptoIsSubclass = (new \ReflectionClass(CryptoException::class))->isSubclassOf(SmCryptoException::class);
        $invalidIsSubclass = (new \ReflectionClass(InvalidKeyException::class))->isSubclassOf(SmCryptoException::class);
        $this->assertTrue($cryptoIsSubclass);
        $this->assertTrue($invalidIsSubclass);
    }

    public function testCryptoExceptionNotInstanceOfInvalidKeyException(): void
    {
        // CryptoException 和 InvalidKeyException 是兄弟类，不互为子类
        $cryptoRef = new \ReflectionClass(CryptoException::class);
        $invalidRef = new \ReflectionClass(InvalidKeyException::class);
        // 两者都继承 SmCryptoException
        $cryptoParent = $cryptoRef->getParentClass();
        $invalidParent = $invalidRef->getParentClass();
        $this->assertEquals(SmCryptoException::class, $cryptoParent !== false ? $cryptoParent->getName() : '');
        $this->assertEquals(SmCryptoException::class, $invalidParent !== false ? $invalidParent->getName() : '');
        // 彼此不是子类关系
        $this->assertNotSame($cryptoRef, $invalidRef);
    }

    public function testInvalidKeyExceptionNotInstanceOfCryptoException(): void
    {
        // 验证继承链独立性
        $cryptoRef = new \ReflectionClass(CryptoException::class);
        $invalidRef = new \ReflectionClass(InvalidKeyException::class);
        $this->assertNotSame($cryptoRef, $invalidRef);
        // 两者直接父类都是 SmCryptoException
        $cryptoParent = $cryptoRef->getParentClass();
        $invalidParent = $invalidRef->getParentClass();
        $this->assertEquals(
            $cryptoParent !== false ? $cryptoParent->getName() : '',
            $invalidParent !== false ? $invalidParent->getName() : ''
        );
    }
}
