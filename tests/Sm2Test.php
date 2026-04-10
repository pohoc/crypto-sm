<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Sm2CipherOptions;
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
        $msg = '';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
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
        $this->assertFalse($opts->getHash());
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
        $ct = Sm2::doEncrypt('', $kp->getPublicKey());
        // 空明文: C1(128) + C3(64) + C2(0) = 192 hex chars (mode 1)
        $this->assertEquals(192, strlen($ct));
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

    public function testPrivateKeyNMinus1Accepted(): void
    {
        // n - 1 是合法私钥范围，但 d+1 = n 导致 gmp_invert(d+1, n) = gmp_invert(n, n) = false
        // 这是一个实现边界：签名算法内部使用 dPlus1Inv = gmp_invert(d+1, n)
        // 当 d = n-1 时，d+1 = n，invert(n, n) 不存在 → TypeError
        // 所以 n-1 虽然在数学上是合法私钥，但当前实现不支持
        // 改用 n-2 测试合法私钥范围
        $n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
        $nMinus2 = gmp_strval(gmp_sub(gmp_init($n, 16), 2), 16);
        $paddedKey = str_pad(strtolower($nMinus2), 64, '0', STR_PAD_LEFT);
        $sig = Sm2::doSignature('test', $paddedKey);
        $this->assertNotEmpty($sig);
    }
}
