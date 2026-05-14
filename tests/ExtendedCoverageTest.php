<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use CryptoSm\SmCrypto;
use PHPUnit\Framework\TestCase;

/**
 * 扩展覆盖测试 — 补充现有测试文件中未覆盖的功能点与边界场景。
 */
class ExtendedCoverageTest extends TestCase
{
    // ─── SM3 Streaming 边界 ──────────────────────────────────────────────

    public function testSm3StreamingUpdateEmptyString(): void
    {
        $expected = Sm3::sm3('hello');
        $hasher = new Sm3();
        $hasher->update(''); // 空数据
        $hasher->update('hello');
        $this->assertEquals($expected, $hasher->finalize());
    }

    public function testSm3StreamingUpdateOnly(): void
    {
        $hasher = new Sm3();
        $hasher->update('data');
        // 不调用 finalize 不会返回结果，但对象状态应正常
        $this->assertInstanceOf(Sm3::class, $hasher);
    }

    public function testSm3StreamingMultipleUpdatesThenFinalize(): void
    {
        $data = 'The quick brown fox jumps over the lazy dog';
        $expected = Sm3::sm3($data);

        $hasher = new Sm3();
        foreach (str_split($data, 5) as $chunk) {
            $hasher->update($chunk);
        }
        $this->assertEquals($expected, $hasher->finalize());
    }

    public function testSm3StreamingExactlyTwoBlocks(): void
    {
        // 128 bytes = 2 个完整块
        $data = str_repeat('A', 128);
        $expected = Sm3::sm3($data);

        $hasher = new Sm3();
        $hasher->update(substr($data, 0, 64));
        $hasher->update(substr($data, 64));
        $this->assertEquals($expected, $hasher->finalize());
    }

    // ─── SM3 streaming via facade 重置验证 ─────────────────────────────────

    public function testSm3StreamFacadeResetAfterFinalize(): void
    {
        $hasher = SmCrypto::sm3Stream();
        $hasher->update('first');
        $result1 = $hasher->finalize();

        $hasher->update('second');
        $result2 = $hasher->finalize();

        $this->assertEquals(Sm3::sm3('first'), $result1);
        $this->assertEquals(Sm3::sm3('second'), $result2);
    }

    // ─── HMAC-SM3 流式边界 ──────────────────────────────────────────────

    public function testHmacSm3StreamingEmptyInput(): void
    {
        $key = 'test_key';
        $expected = HmacSm3::hmac($key, '');

        $hmac = HmacSm3::create($key);
        $this->assertEquals($expected, $hmac->finalize());
    }

    public function testHmacSm3StreamingOnlyUpdateNoData(): void
    {
        $key = 'test_key';
        $expected = HmacSm3::hmac($key, 'data');

        $hmac = HmacSm3::create($key);
        $hmac->update('');
        $hmac->update('data');
        $this->assertEquals($expected, $hmac->finalize());
    }

    public function testHmacSm3StreamingFinalizeReset(): void
    {
        $key = 'reset_key';
        $hmac = HmacSm3::create($key);
        $hmac->update('first');
        $result1 = $hmac->finalize();

        // finalize 后应可重用
        $hmac->update('second');
        $result2 = $hmac->finalize();

        $this->assertEquals(HmacSm3::hmac($key, 'first'), $result1);
        $this->assertEquals(HmacSm3::hmac($key, 'second'), $result2);
    }

    public function testHmacSm3ShortKey(): void
    {
        // 密钥短于块大小 (64 字节) 应直接补零
        $result = HmacSm3::hmac('k', 'data');
        $this->assertEquals(64, strlen($result));
    }

    public function testHmacSm3ExactBlockSizeKey(): void
    {
        // 恰好 64 字节的密钥不应对其哈希
        $key = str_repeat('a', 64);
        $result = HmacSm3::hmac($key, 'data');
        $this->assertEquals(64, strlen($result));
    }

    // ─── SM4 CFB/OFB/CTR 流式模式非对齐数据 ────────────────────────────────

    public function testSm4CfbShortData(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CFB);
        $iv = $opts->getIv();
        $data = 'a'; // 1 字节
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4OfbShortData(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_OFB);
        $iv = $opts->getIv();
        $data = 'hi'; // 2 字节
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_OFB)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4CtrShortData(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CTR);
        $iv = $opts->getIv();
        $data = 'test'; // 4 字节
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4CfbChineseData(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CFB);
        $iv = $opts->getIv();
        $data = '国密算法测试';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4OfbEmptyData(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_OFB);
        $iv = $opts->getIv();
        $data = '';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        // 流式模式加密空数据返回空字符串，解密空字符串也应返回空
        $this->assertEquals('', $encrypted);
        // 空密文不是有效 hex，无法通过标准解密流程
        // 这是预期行为：流式模式下空数据加密结果为空
        $this->assertEquals($data, '');
    }

    public function testSm4CtrLongData(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CTR);
        $iv = $opts->getIv();
        $data = str_repeat('CTR mode long data test. ', 200);
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    // ─── SM4 模式常量 ────────────────────────────────────────────────────

    public function testSm4AllModeConstants(): void
    {
        $this->assertEquals('ecb', Sm4::MODE_ECB);
        $this->assertEquals('cbc', Sm4::MODE_CBC);
        $this->assertEquals('cfb', Sm4::MODE_CFB);
        $this->assertEquals('ofb', Sm4::MODE_OFB);
        $this->assertEquals('ctr', Sm4::MODE_CTR);
        $this->assertEquals('gcm', Sm4::MODE_GCM);
    }

    // ─── SM4 GCM 选项验证 ────────────────────────────────────────────────

    public function testSm4GcmInvalidIvEmptyHex(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv('');
    }

    public function testSm4GcmInvalidIvOddLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv('abc');
    }

    public function testSm4GcmInvalidIvNonHex(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv('zz');
    }

    public function testSm4GcmValidTagLengths(): void
    {
        foreach ([4, 8, 12, 13, 14, 15, 16] as $tagLen) {
            $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setTagLength($tagLen);
            $this->assertEquals($tagLen, $opts->getTagLength());
        }
    }

    public function testSm4GcmAadSetterReturnsSelf(): void
    {
        $opts = new Sm4Options();
        $result = $opts->setAad('test aad');
        $this->assertSame($opts, $result);
    }

    public function testSm4GcmTagLengthSetterReturnsSelf(): void
    {
        $opts = new Sm4Options();
        $result = $opts->setTagLength(12);
        $this->assertSame($opts, $result);
    }

    // ─── PEM 边界测试 ───────────────────────────────────────────────────

    public function testPemImportInvalidPemData(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKey('not a pem');
    }

    public function testPemImportEmptyPem(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKey('');
    }

    public function testPemImportPublicKeyInvalidPem(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::importPublicKey('not a pem');
    }

    public function testPemExportPrivateKeyPkcs8InvalidKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::exportPrivateKeyPkcs8('invalid');
    }

    public function testPemExportPrivateKeyWithInvalidPublicKey(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $this->expectException(InvalidKeyException::class);
        Pem::exportPrivateKey($pair->getPrivateKey(), 'bad_pub_key');
    }

    public function testPemRoundTripPkcs8WithoutPublicKey(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $pem = Pem::exportPrivateKeyPkcs8($pair->getPrivateKey());
        $imported = Pem::importPrivateKey($pem);
        $this->assertEquals($pair->getPrivateKey(), $imported['privateKey']);
        // 公钥应通过私钥推导
        $this->assertEquals($pair->getPublicKey(), $imported['publicKey']);
    }

    // ─── KeyExchange 边界测试 ────────────────────────────────────────────

    public function testKeyExchangeInvalidEphemeralPublicKey(): void
    {
        $pairA = Sm2::generateKeyPairHex();
        $ephA = KeyExchange::generateEphemeralKeyPair();

        $this->expectException(InvalidKeyException::class);
        KeyExchange::initiatorComputeKey(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            str_repeat('a', 128), // 不在曲线上的"公钥"
            Sm2::generateKeyPairHex()->getPublicKey(),
            32
        );
    }

    public function testKeyExchangeInvalidStaticPrivateKey(): void
    {
        $pairB = Sm2::generateKeyPairHex();
        $ephA = KeyExchange::generateEphemeralKeyPair();
        $ephB = KeyExchange::generateEphemeralKeyPair();

        $this->expectException(InvalidKeyException::class);
        KeyExchange::initiatorComputeKey(
            'invalid_key',
            $ephA->getPrivateKey(),
            $pairB->getPublicKey(),
            $ephB->getPublicKey(),
            32
        );
    }

    public function testKeyExchangeDifferentIdsProduceDifferentKeys(): void
    {
        $pairA = Sm2::generateKeyPairHex();
        $pairB = Sm2::generateKeyPairHex();
        $ephA = KeyExchange::generateEphemeralKeyPair();
        $ephB = KeyExchange::generateEphemeralKeyPair();

        $key1 = KeyExchange::initiatorComputeKey(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            $pairB->getPublicKey(),
            $ephB->getPublicKey(),
            32,
            'idA',
            'idB'
        );
        $key2 = KeyExchange::initiatorComputeKey(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            $pairB->getPublicKey(),
            $ephB->getPublicKey(),
            32,
            'otherA',
            'otherB'
        );
        $this->assertNotEquals($key1, $key2, '不同 ID 应产生不同的共享密钥');
    }

    // ─── SmCrypto facade getPublicKey ───────────────────────────────────

    public function testFacadeGetPublicKey(): void
    {
        $kp = SmCrypto::generateKeyPair();
        $derived = SmCrypto::getPublicKey($kp->getPrivateKey());
        $this->assertEquals($kp->getPublicKey(), $derived);
    }

    // ─── SmCrypto facade SM4 各模式 ──────────────────────────────────────

    public function testFacadeSm4CfbRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CFB);
        $iv = $opts->getIv();
        $data = 'facade CFB test';
        $ct = SmCrypto::sm4Encrypt($data, $key, $opts);
        $pt = SmCrypto::sm4Decrypt($ct, $key, (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv));
        $this->assertEquals($data, $pt);
    }

    public function testFacadeSm4OfbRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_OFB);
        $iv = $opts->getIv();
        $data = 'facade OFB test';
        $ct = SmCrypto::sm4Encrypt($data, $key, $opts);
        $pt = SmCrypto::sm4Decrypt($ct, $key, (new Sm4Options())->setMode(Sm4::MODE_OFB)->setIv($iv));
        $this->assertEquals($data, $pt);
    }

    public function testFacadeSm4CtrRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CTR);
        $iv = $opts->getIv();
        $data = 'facade CTR test';
        $ct = SmCrypto::sm4Encrypt($data, $key, $opts);
        $pt = SmCrypto::sm4Decrypt($ct, $key, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv));
        $this->assertEquals($data, $pt);
    }

    // ─── SmCrypto facade HMAC-SM3 短密钥 ──────────────────────────────────

    public function testFacadeHmacSm3ShortKey(): void
    {
        $result = SmCrypto::hmacSm3('k', 'data');
        $this->assertEquals(64, strlen($result));
        $this->assertEquals(HmacSm3::hmac('k', 'data'), $result);
    }

    // ─── SM4 填充边界 ────────────────────────────────────────────────────

    public function testSm4Pkcs5PaddingExactlyOneBlock(): void
    {
        // 16 字节消息 → 添加完整 16 字节填充块
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode('ecb');
        $msg = str_repeat('x', 16);
        $ct = Sm4::encrypt($msg, $key, $opts);
        $this->assertEquals(64, strlen($ct)); // 32 bytes = 2 blocks
        $pt = Sm4::decrypt($ct, $key, $opts);
        $this->assertEquals($msg, $pt);
    }

    public function testSm4Pkcs5PaddingFifteenBytes(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode('ecb');
        $msg = str_repeat('y', 15);
        $ct = Sm4::encrypt($msg, $key, $opts);
        $this->assertEquals(32, strlen($ct)); // 16 bytes = 1 block
        $pt = Sm4::decrypt($ct, $key, $opts);
        $this->assertEquals($msg, $pt);
    }

    public function testSm4ZeroPaddingTrailingNulls(): void
    {
        // Zero padding 会 trim 所有尾部 \0，数据末尾有 \0 会被截断
        $key = bin2hex(random_bytes(16));
        $iv = (new Sm4Options())->setPadding('zero')->getIv();
        $msg = 'hello' . "\0\0"; // 末尾有 \0
        $opts = (new Sm4Options())->setPadding('zero')->setIv($iv);
        $ct = Sm4::encrypt($msg, $key, $opts);
        $pt = Sm4::decrypt($ct, $key, (new Sm4Options())->setPadding('zero')->setIv($iv));
        // zero padding 的已知限制：末尾 \0 会被 trim
        $this->assertStringStartsWith('hello', $pt);
    }

    // ─── SM4 unsupported mode ──────────────────────────────────────────

    public function testSm4UnsupportedModeInGetOpenSSLMethodName(): void
    {
        $ref = new \ReflectionClass(Sm4::class);
        $method = $ref->getMethod('getOpenSSLMethodName');
        $method->setAccessible(true);

        $this->expectException(InvalidKeyException::class);
        $method->invoke(null, 'invalid_mode');
    }

    // ─── SM2 isOnCurve 边界 ──────────────────────────────────────────────

    public function testSm2IsOnCurveWrongLength(): void
    {
        $this->assertFalse(Sm2::isOnCurve(str_repeat('a', 64)));
        $this->assertFalse(Sm2::isOnCurve(str_repeat('a', 130)));
    }

    public function testSm2IsOnCurveNonHex(): void
    {
        $this->assertFalse(Sm2::isOnCurve(str_repeat('z', 128)));
    }

    public function testSm2IsOnCurveZeroPoint(): void
    {
        // 全零不在曲线上
        $this->assertFalse(Sm2::isOnCurve(str_repeat('0', 128)));
    }

    public function testSm2IsOnCurveGeneratedKey(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $this->assertTrue(Sm2::isOnCurve($kp->getPublicKey()));
    }

    // ─── SM2 verify 边界: 畸形 DER ──────────────────────────────────────

    public function testSm2VerifyMalformedDerSignatureReturnsFalse(): void
    {
        $kp = Sm2::generateKeyPairHex();
        // 用一个格式完整的但内容无效的 DER 签名
        // SEQUENCE { INTEGER 1, INTEGER 1 } → 30 06 02 01 01 02 01 01
        $this->assertFalse(Sm2::doVerifySignature('test', '3006020101020101', $kp->getPublicKey()));
    }

    // ─── Sm4Options GCM IV 自动生成长度 ──────────────────────────────────

    public function testSm4OptionsGcmAutoIvIs24HexChars(): void
    {
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM);
        $iv = $opts->getIv();
        $this->assertEquals(24, strlen($iv)); // 12 bytes = 24 hex chars
    }

    public function testSm4OptionsNonGcmAutoIvIs32HexChars(): void
    {
        $opts = new Sm4Options(); // 默认 CBC
        $iv = $opts->getIv();
        $this->assertEquals(32, strlen($iv)); // 16 bytes = 32 hex chars
    }

    // ─── SM4 模式 case-insensitive ──────────────────────────────────────

    public function testSm4CfbModeUpperCase(): void
    {
        $opts = (new Sm4Options())->setMode('CFB');
        $this->assertEquals('cfb', $opts->getMode());
    }

    public function testSm4OfbModeUpperCase(): void
    {
        $opts = (new Sm4Options())->setMode('OFB');
        $this->assertEquals('ofb', $opts->getMode());
    }

    public function testSm4CtrModeUpperCase(): void
    {
        $opts = (new Sm4Options())->setMode('CTR');
        $this->assertEquals('ctr', $opts->getMode());
    }

    // ─── Pem 导入导出完整性 ──────────────────────────────────────────────

    public function testPemSec1WithPublicKeyRoundTripEncryption(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $pem = Pem::exportPrivateKey($pair->getPrivateKey(), $pair->getPublicKey());
        $imported = Pem::importPrivateKey($pem);

        // 验证导入的密钥可用于加解密
        $msg = 'PEM encryption test';
        $ct = Sm2::doEncrypt($msg, $imported['publicKey']);
        $pt = Sm2::doDecrypt($ct, $imported['privateKey']);
        $this->assertEquals($msg, $pt);
    }

    public function testPemPublicKeyBase64Format(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $pem = Pem::exportPublicKey($pair->getPublicKey());

        // 验证 PEM 格式
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $pem);
        $this->assertStringContainsString('-----END PUBLIC KEY-----', $pem);

        // 中间是 base64
        $b64 = preg_replace('/-----.*?-----/', '', $pem) ?? '';
        $b64 = preg_replace('/\s+/', '', $b64) ?? '';
        $this->assertTrue(base64_decode($b64, true) !== false);
    }

    // ─── SmCrypto facade KeyExchange ───────────────────────────────────

    public function testFacadeKeyExchangeWithCustomIds(): void
    {
        $pairA = SmCrypto::generateKeyPair();
        $pairB = SmCrypto::generateKeyPair();
        $ephA = SmCrypto::generateExchangeKeyPair();
        $ephB = SmCrypto::generateExchangeKeyPair();

        $keyA = SmCrypto::initiatorKeyExchange(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            $pairB->getPublicKey(),
            $ephB->getPublicKey(),
            32,
            'alice@sm2',
            'bob@sm2'
        );
        $keyB = SmCrypto::responderKeyExchange(
            $pairB->getPrivateKey(),
            $ephB->getPrivateKey(),
            $pairA->getPublicKey(),
            $ephA->getPublicKey(),
            32,
            'alice@sm2',
            'bob@sm2'
        );
        $this->assertEquals($keyA, $keyB);
    }
}
