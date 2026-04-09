<?php

namespace CryptoSm\Tests;

use PHPUnit\Framework\TestCase;
use CryptoSm\SmCrypto;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM4\Sm4Options;

class SmCryptoTest extends TestCase
{
    public function testGenerateKeyPair()
    {
        $keypair = SmCrypto::generateKeyPair();
        $this->assertInstanceOf(Keypair::class, $keypair);
        $this->assertEquals(64, strlen($keypair->getPrivateKey()));
        $this->assertEquals(128, strlen($keypair->getPublicKey()));
    }

    public function testSm2EncryptDecrypt()
    {
        $kp = SmCrypto::generateKeyPair();
        $msg = 'Hello via SmCrypto';
        $ct = SmCrypto::encrypt($msg, $kp->getPublicKey());
        $pt = SmCrypto::decrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testSm2SignVerify()
    {
        $kp = SmCrypto::generateKeyPair();
        $msg = 'Sign via SmCrypto';
        $sig = SmCrypto::sign($msg, $kp->getPrivateKey());
        $this->assertTrue(SmCrypto::verify($msg, $sig, $kp->getPublicKey()));
    }

    public function testSm3()
    {
        $hash = SmCrypto::sm3('test');
        $this->assertEquals(64, strlen($hash));
        $this->assertTrue(ctype_xdigit($hash));
    }

    public function testSm3Consistency()
    {
        $hash1 = SmCrypto::sm3('test');
        $hash2 = SmCrypto::sm3('test');
        $this->assertEquals($hash1, $hash2);
    }

    public function testSm4EncryptDecrypt()
    {
        $key = '0123456789abcdeffedcba9876543210';
        $iv = 'fedcba98765432100123456789abcdef';
        $options = (new Sm4Options())->setMode('cbc')->setIv($iv);
        $msg = 'Hello SM4 via SmCrypto';

        $ct = SmCrypto::sm4Encrypt($msg, $key, $options);
        $pt = SmCrypto::sm4Decrypt($ct, $key, $options);
        $this->assertEquals($msg, $pt);
    }

    public function testSm2EncryptWithOptions()
    {
        $kp = SmCrypto::generateKeyPair();
        $opts = (new Sm2CipherOptions())->setCipherMode(0);
        $msg = 'options test';
        $ct = SmCrypto::encrypt($msg, $kp->getPublicKey(), $opts);
        $pt = SmCrypto::decrypt($ct, $kp->getPrivateKey(), $opts);
        $this->assertEquals($msg, $pt);
    }

    public function testSm2SignWithOptions()
    {
        $kp = SmCrypto::generateKeyPair();
        $opts = (new SignatureOptions())->setHash(true)->setPublicKey($kp->getPublicKey())->setUserId('testUser');
        $msg = 'hash sign test';
        $sig = SmCrypto::sign($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(SmCrypto::verify($msg, $sig, $kp->getPublicKey(), $opts));
    }
}
