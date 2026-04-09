<?php

namespace CryptoSm\Tests;

use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Exception\CryptoException;
use PHPUnit\Framework\TestCase;

class Sm2Test extends TestCase
{
    public function testGenerateKeyPair()
    {
        $keypair = Sm2::generateKeyPairHex();
        $this->assertInstanceOf(Keypair::class, $keypair);
        $this->assertEquals(64, strlen($keypair->getPrivateKey()));
        $this->assertEquals(128, strlen($keypair->getPublicKey()));
    }

    public function testEncryptDecryptRoundTrip()
    {
        $keypair = Sm2::generateKeyPairHex();
        $msg = 'Hello, SM2!';
        $ct = Sm2::doEncrypt($msg, $keypair->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $keypair->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testEncryptDecryptMode0()
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0);
        $msg = 'mode0';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts);
        $this->assertEquals($msg, Sm2::doDecrypt($ct, $kp->getPrivateKey(), $opts));
    }

    public function testEncryptDecryptMode1()
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_1);
        $msg = 'mode1 test';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts);
        $this->assertEquals($msg, Sm2::doDecrypt($ct, $kp->getPrivateKey(), $opts));
    }

    public function testSignVerify()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'sign me';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    public function testSignVerifyWithHashAndUserId()
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setHash(true)->setPublicKey($kp->getPublicKey())->setUserId('customUserId1234');
        $msg = 'hash mode';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testDerSignature()
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setDer(true);
        $msg = 'der format';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testTamperedSignatureFails()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'original';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        // flip a nibble
        $sig = substr_replace($sig, $sig[0] === 'a' ? 'b' : 'a', 0, 1);
        $this->assertFalse(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    public function testInvalidPublicKeyRejected()
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doEncrypt('msg', str_repeat('a', 128));
    }

    public function testInvalidCiphertextRejected()
    {
        $this->expectException(InvalidKeyException::class);
        $kp = Sm2::generateKeyPairHex();
        Sm2::doDecrypt(str_repeat('a', 190), $kp->getPrivateKey());
    }

    public function testSignatureOptionsChainable()
    {
        $options = new SignatureOptions();
        $result = $options->setDer(true)->setHash(true)->setPublicKey(str_repeat('0', 128))->setUserId('user');
        $this->assertInstanceOf(SignatureOptions::class, $result);
        $this->assertTrue($options->getDer());
        $this->assertTrue($options->getHash());
        $this->assertEquals('user', $options->getUserId());
    }

    public function testSm2CipherOptionsChainable()
    {
        $options = new Sm2CipherOptions();
        $this->assertSame($options, $options->setCipherMode(Sm2::CIPHER_MODE_0));
        $this->assertEquals(Sm2::CIPHER_MODE_0, $options->getCipherMode());
    }

    public function testSm2CipherOptionsInvalidMode()
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm2CipherOptions())->setCipherMode(99);
    }

    public function testPrivateKeyValidationInvalidHex()
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Private key must be 256 bits');
        Sm2::doSignature('test', 'not-hex-key');
    }

    public function testPrivateKeyValidationTooShort()
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doSignature('test', 'abc123');
    }

    public function testPrivateKeyValidationForDecrypt()
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doDecrypt(str_repeat('a', 192), 'badkey');
    }

    public function testEncryptDecryptAliases()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'alias test';
        $ct = Sm2::encrypt($msg, $kp->getPublicKey());
        $pt = Sm2::decrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testSignVerifyAliases()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'alias sign';
        $sig = Sm2::sign($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::verify($msg, $sig, $kp->getPublicKey()));
    }

    public function testDecryptWithWrongKeyFails()
    {
        $kp1 = Sm2::generateKeyPairHex();
        $kp2 = Sm2::generateKeyPairHex();
        $msg = 'secret';
        $ct = Sm2::doEncrypt($msg, $kp1->getPublicKey());
        $this->expectException(CryptoException::class);
        Sm2::doDecrypt($ct, $kp2->getPrivateKey());
    }

    public function testEncryptEmptyString()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = '';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testEncryptChineseText()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = '你好世界国密算法';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testWrongMessageSignatureFails()
    {
        $kp = Sm2::generateKeyPairHex();
        $sig = Sm2::doSignature('message1', $kp->getPrivateKey());
        $this->assertFalse(Sm2::doVerifySignature('message2', $sig, $kp->getPublicKey()));
    }

    public function testWrongKeySignatureFails()
    {
        $kp1 = Sm2::generateKeyPairHex();
        $kp2 = Sm2::generateKeyPairHex();
        $sig = Sm2::doSignature('message', $kp1->getPrivateKey());
        $this->assertFalse(Sm2::doVerifySignature('message', $sig, $kp2->getPublicKey()));
    }

    public function testImplementsInterfaces()
    {
        $this->assertInstanceOf(\CryptoSm\Interface\SignerInterface::class, new Sm2());
        $this->assertInstanceOf(\CryptoSm\Interface\CipherInterface::class, new Sm2());
    }
}
