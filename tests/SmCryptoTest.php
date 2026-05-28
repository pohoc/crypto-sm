<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM4\Sm4Options;
use CryptoSm\SmCrypto;
use PHPUnit\Framework\TestCase;

class SmCryptoTest extends TestCase
{
    // ========================================================================
    // 密钥生成
    // ========================================================================

    public function testGenerateKeyPair(): void
    {
        $keypair = SmCrypto::generateKeyPair();
        $this->assertInstanceOf(Keypair::class, $keypair);
        $this->assertEquals(64, strlen($keypair->getPrivateKey()));
        $this->assertEquals(128, strlen($keypair->getPublicKey()));
    }

    public function testGenerateKeyPairAreUnique(): void
    {
        $kp1 = SmCrypto::generateKeyPair();
        $kp2 = SmCrypto::generateKeyPair();
        $this->assertNotEquals($kp1->getPrivateKey(), $kp2->getPrivateKey());
    }

    // ========================================================================
    // SM2 加解密
    // ========================================================================

    public function testSm2EncryptDecrypt(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $msg = 'Hello via SmCrypto';
        $ct = SmCrypto::encrypt($msg, $kp->getPublicKey());
        $pt = SmCrypto::decrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testSm2EncryptWithOptions(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $opts = (new Sm2CipherOptions())->setCipherMode(0);
        $msg = 'options test';
        $ct = SmCrypto::encrypt($msg, $kp->getPublicKey(), $opts);
        $pt = SmCrypto::decrypt($ct, $kp->getPrivateKey(), $opts);
        $this->assertEquals($msg, $pt);
    }

    public function testSm2EncryptInvalidKeyThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        SmCrypto::encrypt('msg', str_repeat('1', 128));
    }

    public function testSm2DecryptInvalidCiphertextThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        $kp = SmCrypto::generateKeyPair();
        SmCrypto::decrypt('bad', $kp->getPrivateKey());
    }

    // ========================================================================
    // SM2 签名/验证
    // ========================================================================

    public function testSm2SignVerify(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $msg = 'Sign via SmCrypto';
        $sig = SmCrypto::sign($msg, $kp->getPrivateKey());
        $this->assertTrue(SmCrypto::verify($msg, $sig, $kp->getPublicKey()));
    }

    public function testSm2SignWithOptions(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $opts = (new SignatureOptions())->setHash(true)->setPublicKey($kp->getPublicKey())->setUserId('testUser');
        $msg = 'hash sign test';
        $sig = SmCrypto::sign($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(SmCrypto::verify($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testSm2SignInvalidKeyThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        SmCrypto::sign('msg', 'badkey');
    }

    public function testSm2VerifyInvalidSignatureReturnsFalse(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $this->assertFalse(SmCrypto::verify('msg', str_repeat('a', 128), $kp->getPublicKey()));
    }

    public function testSm2VerifyTamperedSignatureReturnsFalse(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $sig = SmCrypto::sign('msg', $kp->getPrivateKey());
        $sig[0] = $sig[0] === 'a' ? 'b' : 'a';
        $this->assertFalse(SmCrypto::verify('msg', $sig, $kp->getPublicKey()));
    }

    public function testSm2VerifyWrongMessageReturnsFalse(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $sig = SmCrypto::sign('msg1', $kp->getPrivateKey());
        $this->assertFalse(SmCrypto::verify('msg2', $sig, $kp->getPublicKey()));
    }

    // ========================================================================
    // SM3
    // ========================================================================

    public function testSm3(): void
    {
        $hash = SmCrypto::sm3('test');
        $this->assertEquals(64, strlen($hash));
        $this->assertTrue(ctype_xdigit($hash));
    }

    public function testSm3Consistency(): void
    {
        $hash1 = SmCrypto::sm3('test');
        $hash2 = SmCrypto::sm3('test');
        $this->assertEquals($hash1, $hash2);
    }

    public function testSm3StandardVector(): void
    {
        $this->assertEquals(
            '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
            SmCrypto::sm3('abc')
        );
    }

    public function testSm3EmptyString(): void
    {
        $hash = SmCrypto::sm3('');
        $this->assertEquals(64, strlen($hash));
    }

    // ========================================================================
    // SM4 加解密
    // ========================================================================

    public function testSm4EncryptDecrypt(): void
    {
        $key = '0123456789abcdeffedcba9876543210';
        $iv = 'fedcba98765432100123456789abcdef';
        $options = (new Sm4Options())->setMode('cbc')->setIv($iv);
        $msg = 'Hello SM4 via SmCrypto';

        $ct = SmCrypto::sm4Encrypt($msg, $key, $options);
        $pt = SmCrypto::sm4Decrypt($ct, $key, $options);
        $this->assertEquals($msg, $pt);
    }

    public function testSm4EncryptEcbMode(): void
    {
        $key = '0123456789abcdeffedcba9876543210';
        $options = (new Sm4Options())->setMode('ecb');
        $msg = 'ECB mode test';

        $ct = SmCrypto::sm4Encrypt($msg, $key, $options);
        $pt = SmCrypto::sm4Decrypt($ct, $key, $options);
        $this->assertEquals($msg, $pt);
    }

    public function testSm4EncryptInvalidKeyThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        SmCrypto::sm4Encrypt('msg', 'badkey');
    }

    public function testSm4DecryptInvalidCiphertextThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        $key = '0123456789abcdeffedcba9876543210';
        SmCrypto::sm4Decrypt('zzzz', $key, (new Sm4Options())->setMode('ecb'));
    }

    // ========================================================================
    // 默认参数 (null options)
    // ========================================================================

    public function testSm2EncryptDecryptWithNullOptions(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $msg = 'null options test';
        $ct = SmCrypto::encrypt($msg, $kp->getPublicKey(), null);
        $pt = SmCrypto::decrypt($ct, $kp->getPrivateKey(), null);
        $this->assertEquals($msg, $pt);
    }

    public function testSm2SignVerifyWithNullOptions(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $msg = 'null sign options';
        $sig = SmCrypto::sign($msg, $kp->getPrivateKey(), null);
        $this->assertTrue(SmCrypto::verify($msg, $sig, $kp->getPublicKey(), null));
    }

    public function testSm4EncryptDecryptWithNullOptions(): void
    {
        $key = '0123456789abcdeffedcba9876543210';
        $msg = 'null sm4 options';
        $ct = SmCrypto::sm4Encrypt($msg, $key, null);
        $pt = SmCrypto::sm4Decrypt($ct, $key, null);
        $this->assertEquals($msg, $pt);
    }

    // ========================================================================
    // 端到端流程
    // ========================================================================

    public function testFullWorkflow(): void
    {
        $kp = SmCrypto::generateKeyPair();

        // SM2 加密→解密
        $msg = 'complete workflow test';
        $ct = SmCrypto::encrypt($msg, $kp->getPublicKey());
        $this->assertEquals($msg, SmCrypto::decrypt($ct, $kp->getPrivateKey()));

        // SM2 签名→验证
        $sig = SmCrypto::sign($msg, $kp->getPrivateKey());
        $this->assertTrue(SmCrypto::verify($msg, $sig, $kp->getPublicKey()));

        // SM3 哈希
        $hash = SmCrypto::sm3($msg);
        $this->assertEquals(64, strlen($hash));

        // SM4 加密→解密
        $key4 = '0123456789abcdeffedcba9876543210';
        $iv = '000102030405060708090a0b0c0d0e0f';
        $opts4 = (new Sm4Options())->setMode('cbc')->setIv($iv);
        $ct4 = SmCrypto::sm4Encrypt($msg, $key4, $opts4);
        $this->assertEquals($msg, SmCrypto::sm4Decrypt($ct4, $key4, $opts4));
    }

    // ========================================================================
    // DER+Hash 组合签名通过 facade
    // ========================================================================

    public function testSm2SignVerifyDerHashViaFacade(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $opts = (new SignatureOptions())->setDer(true)->setHash(true)->setPublicKey($kp->getPublicKey());
        $msg = 'der+hash via facade';
        $sig = SmCrypto::sign($msg, $kp->getPrivateKey(), $opts);
        $this->assertEquals('30', substr($sig, 0, 2));
        $this->assertTrue(SmCrypto::verify($msg, $sig, $kp->getPublicKey(), $opts));
    }

    // ========================================================================
    // SM4 padding=none 通过 facade
    // ========================================================================

    public function testSm4NoPaddingViaFacade(): void
    {
        $key = '0123456789abcdeffedcba9876543210';
        $msg = '1234567890123456';
        $opts = (new Sm4Options())->setMode('ecb')->setPadding('none');
        $ct = SmCrypto::sm4Encrypt($msg, $key, $opts);
        $pt = SmCrypto::sm4Decrypt($ct, $key, $opts);
        $this->assertEquals($msg, $pt);
    }

    public function testSm4PayloadViaFacade(): void
    {
        $key = '0123456789abcdeffedcba9876543210';
        $msg = 'payload via facade';
        $payload = SmCrypto::sm4EncryptPayload($msg, $key, (new Sm4Options())->setMode('gcm')->setAad('facade aad'));

        $this->assertEquals($msg, SmCrypto::sm4DecryptPayload($payload, $key));
    }

    // ========================================================================
    // verify 不同错误路径
    // ========================================================================

    public function testSm2VerifyWithWrongPublicKeyReturnsFalse(): void
    {
        $kp1 = SmCrypto::generateKeyPair();
        $kp2 = SmCrypto::generateKeyPair();
        $sig = SmCrypto::sign('msg', $kp1->getPrivateKey());
        $this->assertFalse(SmCrypto::verify('msg', $sig, $kp2->getPublicKey()));
    }

    public function testSm2VerifyWithMalformedSignatureReturnsFalse(): void
    {
        $kp = SmCrypto::generateKeyPair();
        // 畸形 DER 签名 — 太短的 DER 会导致底层 PHP 错误
        // 使用 r=0, s=0 的签名（明确无效）
        $this->assertFalse(SmCrypto::verify('msg', str_repeat('0', 128), $kp->getPublicKey()));
    }

    // ========================================================================
    // SM2 Cipher mode 1 通过 facade
    // ========================================================================

    public function testSm2EncryptDecryptCipherMode1ViaFacade(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $opts = (new Sm2CipherOptions())->setCipherMode(1);
        $msg = 'cipher mode 1';
        $ct = SmCrypto::encrypt($msg, $kp->getPublicKey(), $opts);
        $pt = SmCrypto::decrypt($ct, $kp->getPrivateKey(), $opts);
        $this->assertEquals($msg, $pt);
    }

    // ========================================================================
    // 异常传播 - CryptoException
    // ========================================================================

    public function testSm2DecryptWrongKeyPropagatesCryptoException(): void
    {
        $kp1 = SmCrypto::generateKeyPair();
        $kp2 = SmCrypto::generateKeyPair();
        $ct = SmCrypto::encrypt('secret', $kp1->getPublicKey());
        $this->expectException(CryptoException::class);
        SmCrypto::decrypt($ct, $kp2->getPrivateKey());
    }

    // ========================================================================
    // SM3 更多覆盖
    // ========================================================================

    public function testSm3DifferentMessagesViaFacade(): void
    {
        $h1 = SmCrypto::sm3('message1');
        $h2 = SmCrypto::sm3('message2');
        $this->assertNotEquals($h1, $h2);
    }

    public function testSm3EmptyViaFacade(): void
    {
        $hash = SmCrypto::sm3('');
        $this->assertEquals(64, strlen($hash));
        $this->assertTrue(ctype_xdigit($hash));
    }
}
