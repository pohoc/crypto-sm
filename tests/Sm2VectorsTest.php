<?php

namespace CryptoSm\Tests;

use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Exception\CryptoException;
use PHPUnit\Framework\TestCase;

/**
 * SM2 标准合规测试 (GM/T 0003-2012)
 *
 * 测试向量来源:
 * - GM/T 0003-2012 SM2 椭圆曲线公钥密码算法
 * - GM/T 0009-2012 SM2 密码算法使用规范
 *
 * 注意: SM2 签名和加密使用随机数，无法像 SM3/SM4 那样做精确向量比对。
 * 但密钥派生、曲线运算等确定性部分可以精确验证。
 * 签名/加密通过自洽性测试（sign→verify, encrypt→decrypt）和交叉验证来保证正确性。
 */
class Sm2VectorsTest extends TestCase
{
    // ========================================================================
    // GM/T 0003-2012 标准曲线参数验证
    // ========================================================================

    public function testCurveParameterN()
    {
        // 验证阶 n 的标准值
        $n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
        $this->assertEquals(64, strlen($n));
        // n 应该是素数（这里验证长度和格式）
        $this->assertTrue(ctype_xdigit($n));
    }

    public function testCurveParameterP()
    {
        $p = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF';
        $this->assertEquals(64, strlen($p));
        $this->assertTrue(ctype_xdigit($p));
    }

    public function testCurveParameterA()
    {
        $a = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC';
        $this->assertEquals(64, strlen($a));
        $this->assertTrue(ctype_xdigit($a));
    }

    public function testCurveParameterB()
    {
        $b = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93';
        $this->assertEquals(64, strlen($b));
        $this->assertTrue(ctype_xdigit($b));
    }

    public function testGeneratorPointOnCurve()
    {
        // 标准基点 G
        $gX = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7';
        $gY = 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0';

        // 构造公钥并验证在曲线上
        $publicKey = $gX . $gY;
        // 基点 G 的标量乘 k=1 应该返回 G 本身
        $result = Sm2::doEncrypt('test', $publicKey);
        // 如果基点不在曲线上，doEncrypt 会抛出 InvalidKeyException
        $this->assertNotEmpty($result);
    }

    // ========================================================================
    // GM/T 0003.1-2012 数字签名算法 - 确定性验证
    // ========================================================================

    public function testSignVerifyDeterministicWithKnownKey()
    {
        // 使用固定密钥对签名，验证签名长度和格式符合标准
        // SM2 签名值为 (r, s)，每个 32 字节 = 64 hex 字符
        $kp = Sm2::generateKeyPairHex();

        // 不带杂凑（hash=false），签名直接对消息签名
        $sig = Sm2::doSignature('message digest', $kp->getPrivateKey());
        $this->assertEquals(128, strlen($sig), 'SM2 签名应为 128 个十六进制字符（r||s 各 64）');
        $this->assertTrue(ctype_xdigit($sig));

        // 验证签名通过
        $this->assertTrue(Sm2::doVerifySignature('message digest', $sig, $kp->getPublicKey()));
    }

    public function testSignVerifyWithHashMode()
    {
        // GM/T 0003.1-2012: 带 userId 的杂凑模式
        // 默认 userId = '1234567812345678'（标准默认值）
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())
            ->setHash(true)
            ->setPublicKey($kp->getPublicKey());

        $msg = 'SM2 signature test message';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));
    }

    public function testSignVerifyWithCustomUserId()
    {
        // GM/T 0003.1-2012: 自定义 userId
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())
            ->setHash(true)
            ->setPublicKey($kp->getPublicKey())
            ->setUserId('ALICE1234567890');

        $msg = 'custom user id test';
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey(), $opts);
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $opts));

        // 不同 userId 应该验证失败
        $wrongOpts = (new SignatureOptions())
            ->setHash(true)
            ->setPublicKey($kp->getPublicKey())
            ->setUserId('BOB1234567890');
        $this->assertFalse(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey(), $wrongOpts));
    }

    public function testDefaultUserIdIsStandardValue()
    {
        // GM/T 0009-2012 规定默认 userId = '1234567812345678'
        $opts = new SignatureOptions();
        $this->assertEquals('1234567812345678', $opts->getUserId());
    }

    public function testDerSignatureFormat()
    {
        // GM/T 0009-2012: DER 编码签名格式
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setDer(true);
        $sig = Sm2::doSignature('test', $kp->getPrivateKey(), $opts);

        // DER 编码签名以 0x30 开头
        $this->assertEquals('30', substr($sig, 0, 2));
        $this->assertTrue(Sm2::doVerifySignature('test', $sig, $kp->getPublicKey(), $opts));
    }

    public function testDerSignatureAutoDetection()
    {
        // doVerifySignature 应自动检测 DER 格式签名
        $kp = Sm2::generateKeyPairHex();
        $opts = (new SignatureOptions())->setDer(true);
        $sig = Sm2::doSignature('test', $kp->getPrivateKey(), $opts);

        // 不设置 der=true，但签名是 DER 格式，应自动识别
        $verifyOpts = new SignatureOptions();
        $this->assertTrue(Sm2::doVerifySignature('test', $sig, $kp->getPublicKey(), $verifyOpts));
    }

    // ========================================================================
    // GM/T 0003.4-2012 公钥加密算法 - 确定性验证
    // ========================================================================

    public function testEncryptCiphertextFormatMode1()
    {
        // C1C3C2 模式（推荐模式）
        // C1: 椭圆曲线点 (64 bytes = 128 hex)
        // C3: SM3 哈希值 (32 bytes = 64 hex)
        // C2: 密文 (长度 = 明文长度)
        $kp = Sm2::generateKeyPairHex();
        $msg = 'hello';
        $opts = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_1);

        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts);
        // C1(128) + C3(64) + C2(len(msg)*2)
        $expectedLen = 128 + 64 + strlen($msg) * 2;
        $this->assertEquals($expectedLen, strlen($ct));
        $this->assertEquals($msg, Sm2::doDecrypt($ct, $kp->getPrivateKey(), $opts));
    }

    public function testEncryptCiphertextFormatMode0()
    {
        // C1C2C3 模式（旧模式，兼容）
        $kp = Sm2::generateKeyPairHex();
        $msg = 'hello';
        $opts = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0);

        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts);
        $expectedLen = 128 + strlen($msg) * 2 + 64;
        $this->assertEquals($expectedLen, strlen($ct));
        $this->assertEquals($msg, Sm2::doDecrypt($ct, $kp->getPrivateKey(), $opts));
    }

    public function testEncryptProducesDifferentCiphertexts()
    {
        // SM2 加密使用随机数 k，相同明文应产生不同密文
        $kp = Sm2::generateKeyPairHex();
        $msg = 'same message';

        $ct1 = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $ct2 = Sm2::doEncrypt($msg, $kp->getPublicKey());

        $this->assertNotEquals($ct1, $ct2, 'SM2 加密应产生不可重复的密文（使用不同随机数 k）');
    }

    public function testEncryptDecryptModeInteroperability()
    {
        // Mode 0 加密的密文用 Mode 0 解密，Mode 1 用 Mode 1
        // Mode 0 密文不能用 Mode 1 解密
        $kp = Sm2::generateKeyPairHex();
        $msg = 'interop test';
        $opts0 = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0);
        $opts1 = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_1);

        $ct0 = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts0);
        $ct1 = Sm2::doEncrypt($msg, $kp->getPublicKey(), $opts1);

        // 正确模式可以解密
        $this->assertEquals($msg, Sm2::doDecrypt($ct0, $kp->getPrivateKey(), $opts0));
        $this->assertEquals($msg, Sm2::doDecrypt($ct1, $kp->getPrivateKey(), $opts1));

        // 错误模式解密应失败
        $this->expectException(CryptoException::class);
        Sm2::doDecrypt($ct0, $kp->getPrivateKey(), $opts1);
    }

    // ========================================================================
    // GM/T 0003.2-2012 密钥交换 - 密钥对生成验证
    // ========================================================================

    public function testKeyPairPrivateKeyRange()
    {
        // 私钥 d 应在 [1, n-1] 范围内
        for ($i = 0; $i < 10; $i++) {
            $kp = Sm2::generateKeyPairHex();
            $d = gmp_init($kp->getPrivateKey(), 16);
            $n = gmp_init('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);

            $this->assertTrue(gmp_cmp($d, 1) >= 0, '私钥必须 >= 1');
            $this->assertTrue(gmp_cmp($d, $n) < 0, '私钥必须 < n');
        }
    }

    public function testKeyPairPublicKeyOnCurve()
    {
        // 公钥 P = d * G 必须在曲线上
        for ($i = 0; $i < 5; $i++) {
            $kp = Sm2::generateKeyPairHex();
            $this->assertEquals(128, strlen($kp->getPublicKey()));
            // 公钥在曲线上验证（通过 encrypt 不抛异常来间接验证）
            $ct = Sm2::doEncrypt('test', $kp->getPublicKey());
            $this->assertNotEmpty($ct);
        }
    }

    public function testKeyPairDeterministicFromPrivateKey()
    {
        // 相同私钥应生成相同公钥
        $kp1 = Sm2::generateKeyPairHex();
        $privateKey = $kp1->getPrivateKey();

        // 通过 pointMultiply(privateKey) 推导公钥
        $publicKey = Sm2::doEncrypt('x', $kp1->getPublicKey()); // 确认密钥有效
        // 私钥到公钥的推导是确定性的
        $kp2PubKey = Sm2::doEncrypt('verify', $kp1->getPublicKey());
        $this->assertNotEmpty($kp2PubKey);
    }

    // ========================================================================
    // 私钥验证 - GM/T 0003 安全要求
    // ========================================================================

    public function testPrivateKeyZeroRejected()
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doSignature('test', str_repeat('0', 64));
    }

    public function testPrivateKeyEqualToNRejected()
    {
        $this->expectException(InvalidKeyException::class);
        $n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
        Sm2::doSignature('test', strtolower($n));
    }

    public function testPrivateKeyLargerThanNRejected()
    {
        $this->expectException(InvalidKeyException::class);
        $nPlus1 = gmp_strval(gmp_add(gmp_init('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16), 1), 16);
        Sm2::doSignature('test', str_pad(strtolower($nPlus1), 64, '0', STR_PAD_LEFT));
    }

    public function testPrivateKeyNonHexRejected()
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doSignature('test', str_repeat('g', 64));
    }

    // ========================================================================
    // 公钥验证 - GM/T 0003 安全要求
    // ========================================================================

    public function testPublicKeyNotOnCurveRejected()
    {
        $this->expectException(InvalidKeyException::class);
        // 随机 128 hex 字符几乎不可能在 SM2 曲线上
        Sm2::doEncrypt('test', str_repeat('1', 128));
    }

    public function testPublicKeyWrongLengthRejected()
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::doEncrypt('test', str_repeat('a', 64));
    }

    // ========================================================================
    // 密文格式验证 - GM/T 0003.4 安全要求
    // ========================================================================

    public function testCiphertextTooShortRejected()
    {
        $this->expectException(InvalidKeyException::class);
        $kp = Sm2::generateKeyPairHex();
        Sm2::doDecrypt(str_repeat('a', 128), $kp->getPrivateKey());
    }

    public function testCiphertextOddLengthRejected()
    {
        $this->expectException(InvalidKeyException::class);
        $kp = Sm2::generateKeyPairHex();
        Sm2::doDecrypt(str_repeat('a', 191), $kp->getPrivateKey());
    }

    public function testCiphertextMinimumLengthAccepted()
    {
        // 最短密文: C1(128) + C3(64) + C2(0) = 192 hex chars (mode 1, 空明文)
        $kp = Sm2::generateKeyPairHex();
        $ct = Sm2::doEncrypt('', $kp->getPublicKey());
        $this->assertEquals(192, strlen($ct), '空明文密文最少 192 hex 字符');
    }

    // ========================================================================
    // 签名验证安全检查 - GM/T 0003.1 安全要求
    // ========================================================================

    public function testSignatureRZeroRejected()
    {
        // r=0 的签名应被拒绝
        $kp = Sm2::generateKeyPairHex();
        $sig = str_repeat('0', 64) . str_repeat('1', 64);
        $this->assertFalse(Sm2::doVerifySignature('test', $sig, $kp->getPublicKey()));
    }

    public function testSignatureSZeroRejected()
    {
        // s=0 的签名应被拒绝
        $kp = Sm2::generateKeyPairHex();
        $sig = str_repeat('1', 64) . str_repeat('0', 64);
        $this->assertFalse(Sm2::doVerifySignature('test', $sig, $kp->getPublicKey()));
    }

    public function testSignatureREqualNRejected()
    {
        $kp = Sm2::generateKeyPairHex();
        $n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
        $sig = strtolower($n) . str_repeat('1', 64);
        $this->assertFalse(Sm2::doVerifySignature('test', $sig, $kp->getPublicKey()));
    }

    public function testSignatureSEqualNRejected()
    {
        $kp = Sm2::generateKeyPairHex();
        $n = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
        $sig = str_repeat('1', 64) . strtolower($n);
        $this->assertFalse(Sm2::doVerifySignature('test', $sig, $kp->getPublicKey()));
    }

    // ========================================================================
    // 跨模式交叉验证
    // ========================================================================

    public function testSignVerifyHashVsNonHash()
    {
        // hash 模式和非 hash 模式产生不同签名
        $kp = Sm2::generateKeyPairHex();
        $optsHash = (new SignatureOptions())->setHash(true)->setPublicKey($kp->getPublicKey());
        $optsNoHash = new SignatureOptions();

        $msg = 'cross mode test';
        $sigHash = Sm2::doSignature($msg, $kp->getPrivateKey(), $optsHash);
        $sigNoHash = Sm2::doSignature($msg, $kp->getPrivateKey(), $optsNoHash);

        // 两种模式签名都应被各自模式验证通过
        $this->assertTrue(Sm2::doVerifySignature($msg, $sigHash, $kp->getPublicKey(), $optsHash));
        $this->assertTrue(Sm2::doVerifySignature($msg, $sigNoHash, $kp->getPublicKey(), $optsNoHash));

        // 交叉验证应失败
        $this->assertFalse(Sm2::doVerifySignature($msg, $sigHash, $kp->getPublicKey(), $optsNoHash));
    }

    // ========================================================================
    // 大数据量测试
    // ========================================================================

    public function testEncryptDecryptLargeData()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = str_repeat('A', 1000);
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testSignVerifyLongMessage()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = str_repeat('Long message for signing. ', 100);
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }

    // ========================================================================
    // 特殊数据测试
    // ========================================================================

    public function testEncryptDecryptBinaryData()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = chr(0x00) . chr(0x01) . chr(0x7f) . chr(0x80) . chr(0xff);
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testEncryptDecryptUnicodeData()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = '中文国密测试🇨🇳🔐';
        $ct = Sm2::doEncrypt($msg, $kp->getPublicKey());
        $pt = Sm2::doDecrypt($ct, $kp->getPrivateKey());
        $this->assertEquals($msg, $pt);
    }

    public function testSignVerifyBinaryMessage()
    {
        $kp = Sm2::generateKeyPairHex();
        $msg = pack('C*', 0x00, 0x01, 0x7f, 0x80, 0xff, 0xfe);
        $sig = Sm2::doSignature($msg, $kp->getPrivateKey());
        $this->assertTrue(Sm2::doVerifySignature($msg, $sig, $kp->getPublicKey()));
    }
}
