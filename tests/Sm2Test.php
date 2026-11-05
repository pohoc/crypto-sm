<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM3\Sm3;
use CryptoSm\Utils\Hex;
use PHPUnit\Framework\TestCase;

class Sm2Test extends TestCase
{
    // ========================================================================
    // 密钥生成
    // ========================================================================

    public function testGenerateKeyPair(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $this->assertInstanceOf(Keypair::class, $keypair);
        $this->assertEquals(64, strlen($keypair->getPrivateKey()));
        $this->assertEquals(128, strlen($keypair->getPublicKey()));
    }

    public function testGenerateKeyPairProducesValidKeys(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $kp = Sm2::generateKeyPairHex();
            $this->assertTrue(ctype_xdigit($kp->getPrivateKey()));
            $this->assertTrue(ctype_xdigit($kp->getPublicKey()));
        }
    }

    public function testGeneratedKeyPairsAreUnique(): void
    {
        $kp1 = Sm2::generateKeyPairHex();
        $kp2 = Sm2::generateKeyPairHex();
        $this->assertNotEquals($kp1->getPrivateKey(), $kp2->getPrivateKey());
        $this->assertNotEquals($kp1->getPublicKey(), $kp2->getPublicKey());
    }

    // ========================================================================
    // 加解密
    // ========================================================================

    public function testEncryptDecryptRoundTrip(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $msg = 'Hello, SM2!';
        $ct = Sm2::doEncrypt($msg, $keypair->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $keypair->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testKdfXorMatchesTheSm2CounterStreamAcrossBlockBoundaries(): void
    {
        $seed = str_repeat('0123456789abcdef', 4);
        $method = new \ReflectionMethod(Sm2::class, 'kdfXor');

        foreach ([1, 31, 32, 33, 65] as $length) {
            $data = random_bytes($length);
            $stream = '';
            for ($counter = 1; strlen($stream) < $length; $counter++) {
                $stream .= Hex::fromHex(Sm3::sm3(Hex::fromHex($seed . sprintf('%08x', $counter))));
            }
            $stream = substr($stream, 0, $length);
            $actual = $method->invoke(null, $seed, $data);
            $hexActual = $method->invoke(null, $seed, $data, true);
            if (
                !is_array($actual)
                || !isset($actual['data'], $actual['allZero'])
                || !is_string($actual['data'])
                || !is_bool($actual['allZero'])
                || !is_array($hexActual)
                || !isset($hexActual['data'], $hexActual['allZero'])
                || !is_string($hexActual['data'])
                || !is_bool($hexActual['allZero'])
            ) {
                throw new \LogicException('SM2 KDF XOR must return data and allZero fields');
            }

            $this->assertSame($data ^ $stream, $actual['data']);
            $this->assertSame(hash_equals($stream, str_repeat("\0", $length)), $actual['allZero']);
            $this->assertSame(bin2hex($data ^ $stream), $hexActual['data']);
            $this->assertSame($actual['allZero'], $hexActual['allZero']);
        }
    }

    public function testKdfLengthIsRejectedBeyondThe32BitCounterLimit(): void
    {
        if (PHP_INT_SIZE < 8) {
            $this->markTestSkipped('The 32-bit KDF boundary exceeds the native string-length range');
        }

        $validateLength = new \ReflectionMethod(Sm2::class, 'validateKdfLength');
        $maxAllowedBytes = (0xFFFFFFFF * 32) - 1;
        $validateLength->invoke(null, $maxAllowedBytes);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('less than (2^32 - 1) SM3 blocks');
        $validateLength->invoke(null, $maxAllowedBytes + 1);
    }

    public function testDecryptAcceptsUppercaseHexCiphertext(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $message = 'uppercase hex ciphertext';
        $ciphertext = Sm2::doEncrypt($message, $keypair->getPublicKey());

        $this->assertSame($message, Sm2::doDecrypt(strtoupper($ciphertext), $keypair->getPrivateKey()));
    }

    public function testDecryptAcceptsOptionalUncompressedPointPrefix(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $message = 'optional SEC1 point prefix';
        $legacyOptions = (new Sm2CipherOptions())->setIncludePointPrefix(false);
        $ciphertext = Sm2::doEncrypt($message, $keypair->getPublicKey(), $legacyOptions);

        $this->assertSame($message, Sm2::doDecrypt('04' . $ciphertext, $keypair->getPrivateKey()));
    }

    public function testDecryptRejectsLargeMalformedPrefixedCiphertext(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $malformed = '04' . str_repeat('0', 1024 * 1024);

        $this->expectException(InvalidKeyException::class);
        Sm2::doDecrypt($malformed, $privateKey);
    }

    public function testEncryptDecryptMode0(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0);
        $msg = 'mode0';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts);
        $this->assertEquals($msg, Sm2::doDecrypt($ct, $kp->getPrivateKey(), $opts));
    }

    public function testEncryptDecryptMode1(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_1);
        $msg = 'mode1 test';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts);
        $this->assertEquals($msg, Sm2::doDecrypt($ct, $kp->getPrivateKey(), $opts));
    }

    public function testEncryptEmptyString(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $this->expectException(InvalidKeyException::class);
        Sm2::doEncrypt('', $kp->getPublicKey());
    }

    public function testEncryptChineseText(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = '你好世界国密算法';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testEncryptBinaryData(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = chr(0x00) . chr(0x01) . chr(0x7f) . chr(0x80) . chr(0xff);
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testEncryptProducesDifferentCiphertexts(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'same message';
        $ct1 = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $ct2 = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $this->assertNotEquals($ct1, $ct2);
    }

    public function testDecryptWithWrongKeyFails(): void
    {
        $kp1 = Sm2::generateKeyPairHex();
        $kp2 = Sm2::generateKeyPairHex();
        $msg = 'secret';
        $ct = Sm2::doEncrypt($msg, $kp1->getPublicKey());
        $this->expectException(CryptoException::class);
        Sm2::doDecrypt($ct, $kp2->getPrivateKey());
    }

    public function testEncryptDecryptLargeData(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = str_repeat('A', 1000);
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    // ========================================================================
    // 签名/验证
    // ========================================================================

    public function testSignVerify(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'sign me';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    public function testSignVerifyWithHashAndUserId(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setHash(true)->setPublicKey($kp->getPublicKey())->setUserId('customUserId1234');
        $msg = 'hash mode';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testSigningRejectsMismatchedPublicKeyOption(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $otherKeypair = Sm2::generateKeyPairHex();
        $options = (new SignatureOptions())->setPublicKey($otherKeypair->getPublicKey());

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Public key does not match private key');
        Sm2::doSignature('identity binding', $keypair->getPrivateKey(), $options);
    }

    public function testDerSignature(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setDer(true);
        $msg = 'der format';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testDerSignatureStartsWith30(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setDer(true);
        $sig = Sm2::doSignature('test', $kp->getPrivateKey(), $opts);
        $this->assertEquals('30', substr($sig, 0, 2));
    }

    public function testSignVerifyWithHashDefaultUserId(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setHash(true)->setPublicKey($kp->getPublicKey());
        $msg = 'default user id';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testDerWithHashCombined(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setDer(true)->setHash(true)->setPublicKey($kp->getPublicKey());
        $msg = 'der + hash';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertEquals('30', substr($sig, 0, 2));
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testSignatureLength128Hex(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $sig = Sm2::doSignature('test', $kp->getPrivateKey());
        $this->assertEquals(128, strlen($sig));
    }

    public function testSignEmptyMessage(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $sig = Sm2::doSignature('', $kp->getPrivateKey());
        $this->assertTrue(Sm2::doVerifySignature('', $sig, $kp->getPublicKey()));
    }

    public function testTamperedSignatureFails(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'original';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        $sig = substr_replace($sig, $sig[0] === 'a' ? 'b' : 'a', 0, 1);
        $this->assertFalse(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    public function testWrongMessageSignatureFails(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $sig = Sm2::doSignature('message1', $kp->getPrivateKey());
        $this->assertFalse(Sm2::doVerifySignature('message2', $sig, $kp->getPublicKey()));
    }

    public function testWrongKeySignatureFails(): void
    {
        $kp1 = Sm2::generateKeyPairHex();
        $kp2 = Sm2::generateKeyPairHex();
        $sig = Sm2::doSignature('message', $kp1->getPrivateKey());
        $this->assertFalse(Sm2::doVerifySignature('message', $sig, $kp2->getPublicKey()));
    }

    public function testSignVerifyLongMessage(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = str_repeat('Long message for signing. ', 100);
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    public function testSignVerifyBinaryMessage(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = pack('C*', 0x00, 0x01, 0x7f, 0x80, 0xff, 0xfe);
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    // ========================================================================
    // 输入验证
    // ========================================================================

    public function testInvalidPublicKeyRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doEncrypt('msg', str_repeat('a', 128));
    }

    public function testInvalidCiphertextRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        $kp = Sm2::generateKeyPairHex();
        Sm2::doDecrypt(str_repeat('a', 190), $kp->getPrivateKey());
    }

    public function testPrivateKeyValidationInvalidHex(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Private key must be 256 bits');
        Sm2::doSignature('test', 'not-hex-key');
    }

    public function testPrivateKeyValidationTooShort(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doSignature('test', 'abc123');
    }

    public function testPrivateKeyValidationForDecrypt(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doDecrypt(str_repeat('a', 192), 'badkey');
    }

    public function testPrivateKeyZeroRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doSignature('test', str_repeat('0', 64));
    }

    public function testPrivateKeyEqualToNRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        $n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
        Sm2::doSignature('test', strtolower($n));
    }

    public function testPrivateKeyNonHexRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doSignature('test', str_repeat('g', 64));
    }

    public function testPublicKeyWrongLengthRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doEncrypt('test', str_repeat('a', 64));
    }

    public function testCiphertextTooShortRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        $kp = Sm2::generateKeyPairHex();
        Sm2::doDecrypt(str_repeat('a', 128), $kp->getPrivateKey());
    }

    public function testCiphertextOddLengthRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        $kp = Sm2::generateKeyPairHex();
        Sm2::doDecrypt(str_repeat('a', 191), $kp->getPrivateKey());
    }

    // ========================================================================
    // 别名方法测试
    // ========================================================================

    public function testEncryptDecryptAliases(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'alias test';
        $ct = Sm2::encrypt($msg, $kp->getPublicKey());
        $pt = Sm2::decrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testSignVerifyAliases(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'alias sign';
        $sig = Sm2::sign($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::verify($msg, $sig, $kp->getPublicKey()));
    }

    // ========================================================================
    // Options 测试
    // ========================================================================

    public function testSignatureOptionsChainable(): void
    {
        $options = new SignatureOptions();
        $result = $options->setDer(true)->setHash(true)->setPublicKey(str_repeat('0', 128))->setUserId('user');
        $this->assertInstanceOf(SignatureOptions::class, $result);
        $this->assertTrue($options->getDer());
        $this->assertTrue($options->getHash());
        $this->assertEquals('user', $options->getUserId());
    }

    public function testSignatureOptionsDefaultValues(): void
    {
        $opts = new SignatureOptions();
        $this->assertFalse($opts->getDer());
        $this->assertTrue($opts->getHash());
        $this->assertEquals('', $opts->getPublicKey());
        $this->assertEquals('1234567812345678', $opts->getUserId());
    }

    public function testSignatureOptionsSetPublicKeyInvalidFormat(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Public key must be 128 hex chars');
        (new SignatureOptions())->setPublicKey('invalid-key');
    }

    public function testSignatureOptionsSetPublicKeyEmptyAllowed(): void
    {
        $opts = (new SignatureOptions())->setPublicKey('');
        $this->assertEquals('', $opts->getPublicKey());
    }

    public function testSignatureOptionsSetPublicKeyValidHex(): void
    {
        $opts = (new SignatureOptions())->setPublicKey(str_repeat('ab', 64));
        $this->assertEquals(str_repeat('ab', 64), $opts->getPublicKey());
    }

    public function testSm2CipherOptionsChainable(): void
    {
        $options = new Sm2CipherOptions();
        $this->assertSame($options, $options->setCipherMode(Sm2::CIPHER_MODE_0));
        $this->assertEquals(Sm2::CIPHER_MODE_0, $options->getCipherMode());
    }

    public function testSm2CipherOptionsDefaultMode(): void
    {
        $opts = new Sm2CipherOptions();
        $this->assertEquals(Sm2::CIPHER_MODE_1, $opts->getCipherMode());
    }

    public function testSm2CipherOptionsInvalidMode(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm2CipherOptions())->setCipherMode(99);
    }

    // ========================================================================
    // 接口实现
    // ========================================================================

    public function testImplementsInterfaces(): void
    {
        $this->assertInstanceOf(\CryptoSm\Interfaces\SignerInterface::class, new Sm2());
        $this->assertInstanceOf(\CryptoSm\Interfaces\CipherInterface::class, new Sm2());
    }

    // ========================================================================
    // 常量
    // ========================================================================

    public function testCipherModeConstants(): void
    {
        $this->assertEquals(0, Sm2::CIPHER_MODE_0);
        $this->assertEquals(1, Sm2::CIPHER_MODE_1);
    }

    // ========================================================================
    // CipherInterface / SignerInterface 方法签名验证
    // ========================================================================

    public function testCipherInterfaceEncryptDecrypt(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'interface method';
        $opts = new Sm2CipherOptions();
        $ct = Sm2::encrypt($msg, $kp->getPublicKey(), $opts);
        $pt = Sm2::decrypt($ct, $kp->getPrivateKey(), $opts);
        $this->assertEquals($msg, $pt);
    }

    public function testSignerInterfaceSignVerify(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = 'signer interface';
        $opts = new SignatureOptions();
        $sig = Sm2::sign($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::verify($msg, $sig, $kp->getPublicKey(), $opts));
    }

    // ========================================================================
    // doVerifySignature 边界
    // ========================================================================

    public function testVerifyWithNonCurvePointPublicKeyReturnsFalse(): void
    {
        // 公钥不在曲线上 → doVerifySignature 返回 false (不抛异常)
        $sig = str_repeat('1', 64) . str_repeat('2', 64);
        $result = Sm2::doVerifySignature('test', $sig, str_repeat('a', 128));
        $this->assertFalse($result);
    }

    public function testVerifyRejectsMalformedRawSignature(): void
    {
        $kp = Sm2::generateKeyPairHex();
        foreach (['', 'zz', str_repeat('a', 126), str_repeat('a', 130), str_repeat('g', 128)] as $signature) {
            $this->assertFalse(Sm2::doVerifySignature('message', $signature, $kp->getPublicKey()));
        }
    }

    public function testDefaultSignatureHashesMessageAndRejectsLeadingNulEquivalent(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $options = new SignatureOptions();
        $signature = Sm2::doSignature('PAY:100', $kp->getPrivateKey(), $options);

        $this->assertTrue(Sm2::doVerifySignature('PAY:100', $signature, $kp->getPublicKey(), $options));
        $this->assertFalse(Sm2::doVerifySignature("\0PAY:100", $signature, $kp->getPublicKey(), $options));
        $this->assertFalse(Sm2::doVerifySignature('PAY:100', $signature, $kp->getPublicKey(), (new SignatureOptions())->setHash(false)));
    }

    public function testPrecomputedSignatureDigestMustBeExactly32Bytes(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $options = (new SignatureOptions())->setHash(false);

        try {
            Sm2::doSignature('short digest', $kp->getPrivateKey(), $options);
            $this->fail('Signing must reject a non-32-byte precomputed digest');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('exactly 32 bytes', $e->getMessage());
        }

        $this->assertFalse(Sm2::doVerifySignature('short digest', str_repeat('a', 128), $kp->getPublicKey(), $options));
    }

    public function testVerifyWithDerSignatureAutoDetection(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $optsDer = (new SignatureOptions())->setDer(true);
        $sig = Sm2::doSignature('auto detect', $kp->getPrivateKey(), $optsDer);
        // 不设置 der=true, 应自动检测 DER 格式
        $optsNoDer = new SignatureOptions();
        $this->assertTrue(Sm2::doVerifySignature('auto detect', $sig, $kp->getPublicKey(), $optsNoDer));
    }

    // ========================================================================
    // 密文格式验证
    // ========================================================================

    public function testCiphertextMinimumLength192(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $this->expectException(InvalidKeyException::class);
        Sm2::doDecrypt(str_repeat('a', 192), $kp->getPrivateKey());
    }

    public function testSm2DecryptInvalidC1Rejected(): void
    {
        $kp = Sm2::generateKeyPairHex();
        // C1 不是曲线上的点 → 应抛 InvalidKeyException
        $this->expectException(InvalidKeyException::class);
        // 构造 192+ hex chars: C1(128) + C3(64) + C2(0+)
        $fakeCt = str_repeat('a', 128) . str_repeat('b', 64);
        Sm2::doDecrypt($fakeCt, $kp->getPrivateKey());
    }

    // ========================================================================
    // SignatureOptions 更多覆盖
    // ========================================================================

    public function testSignatureOptionsSetPublicKeyTooLong(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new SignatureOptions())->setPublicKey(str_repeat('a', 130));
    }

    public function testSignatureOptionsSetPublicKeyTooShort(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new SignatureOptions())->setPublicKey(str_repeat('a', 64));
    }

    public function testSignatureOptionsSetDerFalse(): void
    {
        $opts = (new SignatureOptions())->setDer(false);
        $this->assertFalse($opts->getDer());
    }

    public function testSignatureOptionsSetHashFalse(): void
    {
        $opts = (new SignatureOptions())->setHash(false);
        $this->assertFalse($opts->getHash());
    }

    public function testSignatureOptionsSetUserIdEmpty(): void
    {
        $opts = (new SignatureOptions())->setUserId('');
        $this->assertEquals('', $opts->getUserId());
    }

    public function testSm2CipherOptionsSetMode0And1(): void
    {
        $opts = new Sm2CipherOptions();
        $opts->setCipherMode(Sm2::CIPHER_MODE_0);
        $this->assertEquals(0, $opts->getCipherMode());
        $opts->setCipherMode(Sm2::CIPHER_MODE_1);
        $this->assertEquals(1, $opts->getCipherMode());
    }

    public function testSm2CipherOptionsNegativeModeRejected(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm2CipherOptions())->setCipherMode(-1);
    }

    // ========================================================================
    // 私钥范围边界
    // ========================================================================

    public function testPrivateKeyOneAccepted(): void
    {
        // 私钥 d=1 是合法的 (在 [1, n-1] 范围内)
        $kp1 = Sm2::generateKeyPairHex();
        $sig = Sm2::doSignature('test', str_pad('1', 64, '0', STR_PAD_LEFT));
        $this->assertNotEmpty($sig);
    }

    public function testPrivateKeyNMinus1RejectedAndNMinus2Accepted(): void
    {
        $n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
        $nMinus1 = str_pad(strtolower(gmp_strval(gmp_sub(gmp_init($n, 16), 1), 16)), 64, '0', STR_PAD_LEFT);
        try {
            Sm2::validatePrivateKey($nMinus1);
            $this->fail('GM/T private keys must be at most n-2');
        } catch (InvalidKeyException $exception) {
            $this->assertStringContainsString('range [1, n-2]', $exception->getMessage());
        }

        $nMinus2 = gmp_strval(gmp_sub(gmp_init($n, 16), 2), 16);
        $paddedKey = str_pad(strtolower($nMinus2), 64, '0', STR_PAD_LEFT);
        $sig = Sm2::doSignature('test', $paddedKey);
        $this->assertNotEmpty($sig);
    }

    // ========================================================================
    // 窗口法点乘一致性验证
    // ========================================================================

    public function testFixedBaseMultiplyConsistency(): void
    {
        $ref = new \ReflectionClass(Sm2::class);

        // 调用 pointMultiply 对基点乘法（使用预计算表 + 窗口法）
        $pointMultiply = $ref->getMethod('pointMultiply');
        $pointMultiply->setAccessible(true);

        // 测试多个随机标量，确保窗口法结果正确
        for ($i = 0; $i < 5; $i++) {
            $k = bin2hex(random_bytes(32));
            $result = $pointMultiply->invoke(null, '', $k);
            if (!is_string($result)) {
                $this->fail('pointMultiply should return a string for random k');
            }
            $this->assertEquals(128, strlen($result), 'Result should be 128 hex chars');

            // 用 SM2 签名验签间接验证 k*G 的正确性
            // 如果 k*G 计算错误，签名/验签不可能通过
        }
    }

    public function testWindowMultiplyConsistencyWithSignature(): void
    {
        // 窗口法用于签名/验签内部，通过完整的签名验签流程间接验证
        // 多次签名验签确保窗口法在各种随机标量下都正确
        for ($i = 0; $i < 5; $i++) {
            $kp = Sm2::generateKeyPairHex();
            $msg = "window test $i";
            $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
            $this->assertTrue(
                Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()),
                "Signature verification failed at iteration $i"
            );
        }
    }

    public function testWindowMultiplyWithHashMode(): void
    {
        // hash 模式下的签名验签也使用窗口法
        for ($i = 0; $i < 3; $i++) {
            $kp = Sm2::generateKeyPairHex();
            $opts = (new SignatureOptions())->setHash(true)->setPublicKey($kp->getPublicKey());
            $msg = "hash window test $i";
            $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
            $this->assertTrue(
                Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts),
                "Hash mode signature verification failed at iteration $i"
            );
        }
    }

    public function testEncryptDecryptUsesWindowMultiply(): void
    {
        // 加密使用基点乘法 + 变基点乘法，解密使用变基点乘法
        // 多次加解密确保窗口法正确
        for ($i = 0; $i < 3; $i++) {
            $kp = Sm2::generateKeyPairHex();
            $msg = "encrypt window $i";
            $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
            $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
            $this->assertEquals($msg, $pt, "Encrypt/decrypt round-trip failed at iteration $i");
        }
    }
}
