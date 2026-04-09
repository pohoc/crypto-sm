<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\SM2\Keypair;
use PHPUnit\Framework\TestCase;

/**
 * Keypair 数据类测试
 */
class KeypairTest extends TestCase
{
    public function testConstructorAndGetters()
    {
        $kp = new Keypair('private123', 'public456');
        $this->assertEquals('private123', $kp->getPrivateKey());
        $this->assertEquals('public456', $kp->getPublicKey());
    }

    public function testWithRealSm2KeyPair()
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $this->assertInstanceOf(Keypair::class, $kp);
        $this->assertEquals(64, strlen($kp->getPrivateKey()));
        $this->assertEquals(128, strlen($kp->getPublicKey()));
        $this->assertTrue(ctype_xdigit($kp->getPrivateKey()));
        $this->assertTrue(ctype_xdigit($kp->getPublicKey()));
    }

    public function testMultipleKeyPairsAreUnique()
    {
        $kp1 = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $kp2 = \CryptoSm\SM2\Sm2::generateKeyPairHex();

        $this->assertNotEquals($kp1->getPrivateKey(), $kp2->getPrivateKey());
        $this->assertNotEquals($kp1->getPublicKey(), $kp2->getPublicKey());
    }

    public function testKeyPairConsistency()
    {
        // 相同公钥对应的私钥能正确解密
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $msg = 'keypair consistency check';

        $ct = \CryptoSm\SM2\Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = \CryptoSm\SM2\Sm2::doDecrypt($ct, $kp->getPrivateKey());

        $this->assertEquals($msg, $pt);
    }
}
