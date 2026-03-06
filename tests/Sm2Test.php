<?php

namespace CryptoSm\Tests;

use PHPUnit\Framework\TestCase;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\Sm2CipherOptions;

class Sm2Test extends TestCase
{
    public function testGenerateKeyPair()
    {
        $keypair = Sm2::generateKeyPairHex();

        $this->assertInstanceOf(Keypair::class, $keypair);
        $this->assertNotEmpty($keypair->getPrivateKey());
        $this->assertNotEmpty($keypair->getPublicKey());
        $this->assertEquals(64, strlen($keypair->getPrivateKey()));
        $this->assertEquals(128, strlen($keypair->getPublicKey()));
    }

    public function testGenerateMultipleKeyPairs()
    {
        for ($i = 0; $i < 5; $i++) {
            $keypair = Sm2::generateKeyPairHex();
            $this->assertEquals(64, strlen($keypair->getPrivateKey()));
            $this->assertEquals(128, strlen($keypair->getPublicKey()));
        }
    }

    public function testSm2SignatureGeneratesValidSignature()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();

        $msg = 'test message';
        $signature = Sm2::doSignature($msg, $privateKey);

        $this->assertNotEmpty($signature);
        $this->assertGreaterThan(64, strlen($signature));
    }

    public function testSm2SignatureWithHash()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();
        $publicKey = $keypair->getPublicKey();

        $msg = 'test message';

        $options = new SignatureOptions();
        $options->setHash(true);
        $options->setPublicKey($publicKey);

        $signature = Sm2::doSignature($msg, $privateKey, $options);
        $this->assertNotEmpty($signature);
    }

    public function testSm2SignatureMultipleMessages()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();

        $msgs = ['hello', 'world', 'test123', '中文消息'];

        foreach ($msgs as $msg) {
            $signature = Sm2::doSignature($msg, $privateKey);
            $this->assertNotEmpty($signature, "Failed to sign message: $msg");
        }
    }

    public function testSm2SignatureConsistency()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();

        $msg = 'consistent message';

        $sig1 = Sm2::doSignature($msg, $privateKey);
        $sig2 = Sm2::doSignature($msg, $privateKey);

        $this->assertNotEmpty($sig1);
        $this->assertNotEmpty($sig2);
    }

    public function testSm2SignatureLongMessage()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();

        $msg = str_repeat('a', 1000);
        $signature = Sm2::doSignature($msg, $privateKey);

        $this->assertNotEmpty($signature);
    }

    public function testKeypairGetters()
    {
        $keypair = Sm2::generateKeyPairHex();

        $this->assertNotEmpty($keypair->getPrivateKey());
        $this->assertNotEmpty($keypair->getPublicKey());
        $this->assertEquals(64, strlen($keypair->getPrivateKey()));
        $this->assertEquals(128, strlen($keypair->getPublicKey()));
    }

    public function testSm2EncryptDecrypt()
    {
        $keypair = Sm2::generateKeyPairHex();
        $publicKey = $keypair->getPublicKey();
        $privateKey = $keypair->getPrivateKey();

        $msg = 'Hello, SM2!';

        $encrypted = Sm2::doEncrypt($msg, $publicKey);
        $this->assertNotEmpty($encrypted);
        $this->assertTrue(strlen($encrypted) > 128);

        $decrypted = Sm2::doDecrypt($encrypted, $privateKey);
        $this->assertEquals($msg, $decrypted);
    }

    public function testSm2EncryptDecryptWithCipherMode0()
    {
        $keypair = Sm2::generateKeyPairHex();
        $publicKey = $keypair->getPublicKey();
        $privateKey = $keypair->getPrivateKey();

        $msg = 'Test message for mode 0';

        $options = new Sm2CipherOptions();
        $options->setCipherMode(Sm2::CIPHER_MODE_0);

        $encrypted = Sm2::doEncrypt($msg, $publicKey, $options);
        $decrypted = Sm2::doDecrypt($encrypted, $privateKey, $options);

        $this->assertEquals($msg, $decrypted);
    }

    public function testSm2EncryptDecryptEmptyString()
    {
        $keypair = Sm2::generateKeyPairHex();
        $publicKey = $keypair->getPublicKey();
        $privateKey = $keypair->getPrivateKey();

        $msg = '';

        $encrypted = Sm2::doEncrypt($msg, $publicKey);
        $decrypted = Sm2::doDecrypt($encrypted, $privateKey);

        $this->assertEquals($msg, $decrypted);
    }

    public function testSm2EncryptDecryptChineseText()
    {
        $keypair = Sm2::generateKeyPairHex();
        $publicKey = $keypair->getPublicKey();
        $privateKey = $keypair->getPrivateKey();

        $msg = '你好，世界！这是中文测试。';

        $encrypted = Sm2::doEncrypt($msg, $publicKey);
        $decrypted = Sm2::doDecrypt($encrypted, $privateKey);

        $this->assertEquals($msg, $decrypted);
    }

    public function testSm2EncryptDecryptLongMessage()
    {
        $keypair = Sm2::generateKeyPairHex();
        $publicKey = $keypair->getPublicKey();
        $privateKey = $keypair->getPrivateKey();

        $msg = str_repeat('Long message test. ', 100);

        $encrypted = Sm2::doEncrypt($msg, $publicKey);
        $decrypted = Sm2::doDecrypt($encrypted, $privateKey);

        $this->assertEquals($msg, $decrypted);
    }

    public function testSm2VerifySignature()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();
        $publicKey = $keypair->getPublicKey();

        $msg = 'test message for verification';
        $signature = Sm2::doSignature($msg, $privateKey);

        $isValid = Sm2::doVerifySignature($msg, $signature, $publicKey);
        $this->assertTrue($isValid);
    }

    public function testSm2VerifySignatureWithHash()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();
        $publicKey = $keypair->getPublicKey();

        $msg = 'test message with hash';

        $options = new SignatureOptions();
        $options->setHash(true);
        $options->setPublicKey($publicKey);

        $signature = Sm2::doSignature($msg, $privateKey, $options);
        $isValid = Sm2::doVerifySignature($msg, $signature, $publicKey, $options);

        $this->assertTrue($isValid);
    }

    public function testSm2VerifySignatureInvalidSignature()
    {
        $keypair = Sm2::generateKeyPairHex();
        $publicKey = $keypair->getPublicKey();

        $msg = 'test message';
        $fakeSignature = str_repeat('a', 128);

        $isValid = Sm2::doVerifySignature($msg, $fakeSignature, $publicKey);
        $this->assertFalse($isValid);
    }

    public function testSm2VerifySignatureWrongMessage()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();
        $publicKey = $keypair->getPublicKey();

        $msg = 'original message';
        $signature = Sm2::doSignature($msg, $privateKey);

        $wrongMsg = 'wrong message';
        $isValid = Sm2::doVerifySignature($wrongMsg, $signature, $publicKey);
        $this->assertFalse($isValid);
    }

    public function testSignatureOptionsDerFormat()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();
        $publicKey = $keypair->getPublicKey();

        $msg = 'test DER format';

        $options = new SignatureOptions();
        $options->setDer(true);

        $signature = Sm2::doSignature($msg, $privateKey, $options);
        $this->assertNotEmpty($signature);

        $isValid = Sm2::doVerifySignature($msg, $signature, $publicKey, $options);
        $this->assertTrue($isValid);
    }

    public function testSignatureOptionsUserId()
    {
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();
        $publicKey = $keypair->getPublicKey();

        $msg = 'test with custom user ID';

        $options = new SignatureOptions();
        $options->setHash(true);
        $options->setPublicKey($publicKey);
        $options->setUserId('customUserId123');

        $signature = Sm2::doSignature($msg, $privateKey, $options);
        $isValid = Sm2::doVerifySignature($msg, $signature, $publicKey, $options);

        $this->assertTrue($isValid);
    }

    public function testSignatureOptionsChainable()
    {
        $options = new SignatureOptions();

        $result = $options->setDer(true)->setHash(true)->setPublicKey('test')->setUserId('userId');

        $this->assertInstanceOf(SignatureOptions::class, $result);
        $this->assertTrue($options->getDer());
        $this->assertTrue($options->getHash());
        $this->assertEquals('test', $options->getPublicKey());
        $this->assertEquals('userId', $options->getUserId());
    }

    public function testSm2CipherOptionsChainable()
    {
        $options = new Sm2CipherOptions();

        $result = $options->setCipherMode(Sm2::CIPHER_MODE_0);

        $this->assertInstanceOf(Sm2CipherOptions::class, $result);
        $this->assertEquals(Sm2::CIPHER_MODE_0, $options->getCipherMode());
    }

    public function testKeypairTypeSafety()
    {
        $keypair = Sm2::generateKeyPairHex();

        $this->assertIsString($keypair->getPrivateKey());
        $this->assertIsString($keypair->getPublicKey());
    }

    public function testSm2DecryptInvalidData()
    {
        $this->expectException(\Exception::class);

        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();

        $invalidData = str_repeat('a', 200);
        Sm2::doDecrypt($invalidData, $privateKey);
    }
}
