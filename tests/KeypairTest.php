<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\Sm2;
use PHPUnit\Framework\TestCase;

/**
 * Keypair 数据类测试
 */
class KeypairTest extends TestCase
{
    public function testConstructorAndGetters(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $publicKey = Sm2::getPublicKey($privateKey);
        $kp = new Keypair($privateKey, $publicKey);
        $this->assertSame($privateKey, $kp->getPrivateKey());
        $this->assertSame($publicKey, $kp->getPublicKey());
    }

    public function testWithRealSm2KeyPair(): void
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $this->assertInstanceOf(Keypair::class, $kp);
        $this->assertEquals(64, strlen($kp->getPrivateKey()));
        $this->assertEquals(128, strlen($kp->getPublicKey()));
        $this->assertTrue(ctype_xdigit($kp->getPrivateKey()));
        $this->assertTrue(ctype_xdigit($kp->getPublicKey()));
    }

    public function testMultipleKeyPairsAreUnique(): void
    {
        $kp1 = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $kp2 = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $this->assertNotEquals($kp1->getPrivateKey(), $kp2->getPrivateKey());
        $this->assertNotEquals($kp1->getPublicKey(), $kp2->getPublicKey());
    }

    public function testKeyPairConsistency(): void
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $msg = 'keypair consistency check';
        $ct = \CryptoSm\SM2\Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = \CryptoSm\SM2\Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testKeyPairPrivateKeyIsHex(): void
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $kp->getPrivateKey());
    }

    public function testKeyPairPublicKeyIsHex(): void
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{128}$/', $kp->getPublicKey());
    }

    public function testKeyPairSignVerify(): void
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $msg = 'sign verify via keypair';
        $sig = \CryptoSm\SM2\Sm2::doSignature($msg, $kp->getPrivateKey());
        $this->assertTrue(\CryptoSm\SM2\Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    public function testKeyPairEncryptDecryptBothModes(): void
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $msg = 'both modes test';

        $opts0 = (new \CryptoSm\SM2\Sm2CipherOptions())->setCipherMode(\CryptoSm\SM2\Sm2::CIPHER_MODE_0);
        $ct0 = \CryptoSm\SM2\Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts0);
        $this->assertEquals($msg, \CryptoSm\SM2\Sm2::doDecrypt($ct0, $kp->getPrivateKey(), $opts0));

        $opts1 = (new \CryptoSm\SM2\Sm2CipherOptions())->setCipherMode(\CryptoSm\SM2\Sm2::CIPHER_MODE_1);
        $ct1 = \CryptoSm\SM2\Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts1);
        $this->assertEquals($msg, \CryptoSm\SM2\Sm2::doDecrypt($ct1, $kp->getPrivateKey(), $opts1));
    }

    // ========================================================================
    // 不可变验证
    // ========================================================================

    public function testKeypairGettersReturnSameValue(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $this->assertEquals($kp->getPrivateKey(), $kp->getPrivateKey());
        $this->assertEquals($kp->getPublicKey(), $kp->getPublicKey());
    }

    public function testKeypairRejectsEmptyKeys(): void
    {
        $this->expectException(InvalidKeyException::class);
        new Keypair('', '');
    }

    public function testKeypairRejectsMismatchedPublicKey(): void
    {
        $first = Sm2::generateKeyPairHex();
        $second = Sm2::generateKeyPairHex();

        $this->expectException(InvalidKeyException::class);
        new Keypair($first->getPrivateKey(), $second->getPublicKey());
    }

    public function testKeypairRejectsOffCurvePublicKey(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);

        $this->expectException(InvalidKeyException::class);
        new Keypair($privateKey, str_repeat('0', 128));
    }

    public function testKeypairAcceptsUppercaseMatchingPublicKey(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $publicKey = strtoupper(Sm2::getPublicKey($privateKey));
        $keypair = new Keypair($privateKey, $publicKey);

        $this->assertSame($publicKey, $keypair->getPublicKey());
    }

    public function testKeypairAcceptsMaximumEphemeralScalar(): void
    {
        $privateKey = 'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122';
        $publicKey = Sm2::getEphemeralPublicKey($privateKey);

        $keypair = new Keypair($privateKey, $publicKey);

        $this->assertSame($privateKey, $keypair->getPrivateKey());
        $this->assertSame($publicKey, $keypair->getPublicKey());
    }

    // ========================================================================
    // 通过 SmCrypto facade 使用
    // ========================================================================

    public function testKeypairViaSmCryptoFacade(): void
    {
        $kp = \CryptoSm\SmCrypto::generateKeyPair();
        $this->assertInstanceOf(Keypair::class, $kp);
        $this->assertEquals(64, strlen($kp->getPrivateKey()));
        $this->assertEquals(128, strlen($kp->getPublicKey()));
    }

    // ========================================================================
    // DER 签名 + 验证
    // ========================================================================

    public function testKeyPairDerSignVerify(): void
    {
        $kp = \CryptoSm\SM2\Sm2::generateKeyPairHex();
        $opts = (new \CryptoSm\SM2\SignatureOptions())->setDer(true);
        $msg = 'der sign verify via keypair';
        $sig = \CryptoSm\SM2\Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(\CryptoSm\SM2\Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }
}
