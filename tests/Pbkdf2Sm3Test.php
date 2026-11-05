<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\SM3\Pbkdf2Sm3;
use CryptoSm\SmCrypto;
use PHPUnit\Framework\TestCase;

class Pbkdf2Sm3Test extends TestCase
{
    /**
     * Fixed outputs independently generated with OpenSSL's HMAC-SM3 primitive
     * and the RFC 8018 PBKDF2 block construction.
     */
    public function testMatchesIndependentHmacSm3Vectors(): void
    {
        $this->assertSame(
            '4612f922a1fdcefaf4312fc6f8f3322b489cbf24f2ea361b44c2bd8fa2c6dcb0',
            Pbkdf2Sm3::deriveHex('password', 'salt', 1, 32)
        );
        $this->assertSame(
            'fee723a2bc966e11dffb66133f4e8df577383c78ade30e3298edbd3e54ed85b7',
            Pbkdf2Sm3::deriveHex('password', 'salt', 2, 32)
        );
        $this->assertSame(
            'fee723a2bc966e11dffb66133f4e8df577383c78ade30e3298edbd3e54ed85b7'
                . '650006f9e15d3798b131bdb5106d5dddb15c00572aea1830e37a534acaa6f917',
            Pbkdf2Sm3::deriveHex('password', 'salt', 2, 64)
        );
        $this->assertSame(
            'd0a2d7b74c4b7bc44c9a9e147c60d72b218fb13cfbc76d62949420ee46a6f145'
                . 'f3d6f83b7d2e90a8855a69ab666be276',
            Pbkdf2Sm3::deriveHex('password', 'salt', 5, 48)
        );
        $this->assertSame(
            '8fa31559b2d4b2399a1a934b711d54439e1b9f35507b2a6fe2269dea5f98036a98',
            Pbkdf2Sm3::deriveHex(str_repeat('p', 80), "\0salt\xff", 3, 33)
        );
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testMatchesVectorWithPurePhpSm3Fallback(): void
    {
        $nativeSm3 = new \ReflectionProperty(Pbkdf2Sm3::class, 'nativeSm3Available');
        $nativeSm3->setValue(null, false);

        $this->assertSame(
            'fee723a2bc966e11dffb66133f4e8df577383c78ade30e3298edbd3e54ed85b7',
            Pbkdf2Sm3::deriveHex('password', 'salt', 2, 32)
        );
    }

    public function testReturnsRawBytesAndFacadeHex(): void
    {
        $raw = Pbkdf2Sm3::derive('password', 'salt', 2, 33);

        $this->assertSame(33, strlen($raw));
        $this->assertSame(bin2hex($raw), SmCrypto::pbkdf2Sm3('password', 'salt', 2, 33));
    }

    public function testRejectsNonPositiveIterationsAndOutputLength(): void
    {
        $rejected = 0;
        foreach ([[0, 1], [-1, 1], [1, 0], [1, -1]] as [$iterations, $keyLength]) {
            try {
                Pbkdf2Sm3::derive('password', 'salt', $iterations, $keyLength);
            } catch (CryptoException) {
                $rejected++;
                continue;
            }
            $this->fail('Invalid PBKDF2 parameters must be rejected');
        }
        $this->assertSame(4, $rejected);
    }

    public function testRejectsOutputBeyondRfcBlockIndexLimit(): void
    {
        if (PHP_INT_SIZE < 8) {
            $this->markTestSkipped('The PBKDF2 block-index limit cannot be represented on 32-bit PHP');
        }

        $tooLong = 0xFFFFFFFF * 32 + 1;

        $this->expectException(CryptoException::class);
        Pbkdf2Sm3::derive('password', 'salt', 1, $tooLong);
    }
}
