<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Gcm;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use PHPUnit\Framework\TestCase;

/**
 * 安全加固回归测试
 *
 * 覆盖以下修复点：
 * 1. ISO 10126 填充在 padLen=1 时不再触发 random_bytes(0) 崩溃
 * 2. 解密缺少 IV 时显式报错而非静默返回乱码
 * 3. SM2 用户 ID 超过 ENTL 16 位上限时按 GM/T 0003-2012 拒绝
 * 4. GCM IV 重用检测默认开启，支持重置与关闭
 * 5. GCM tagLength 在 Sm4Options 与 Gcm 层校验一致
 * 6. setMode 相同模式为幂等操作（不重置已设置的 IV）
 * 7. PEM BEGIN/END 标签必须匹配
 * 8. 密钥交换 klen 上界保护
 */
class SecurityRegressionTest extends TestCase
{
    // ─── ISO 10126 填充边界 ───────────────────────────────────────────────

    /**
     * 数据长度 ≡ 15 (mod 16) 时 padLen=1，此前会调用 random_bytes(0) 抛出 ValueError。
     */
    public function testIso10126PaddingWithSinglePadByte(): void
    {
        $key = str_repeat('ab', 16);
        $iv = str_repeat('00', 16);

        // 15 字节 → padLen=1；以及所有 mod 16 余数都应正常往返
        foreach ([15, 31, 47] as $len) {
            $data = str_repeat('A', $len - 1) . 'B';
            $options = (new Sm4Options())->setPadding('iso10126')->setIv($iv);
            $ciphertext = Sm4::encrypt($data, $key, $options);
            $this->assertSame($data, Sm4::decrypt($ciphertext, $key, $options));
        }
    }

    // ─── 解密缺少 IV 必须显式失败 ─────────────────────────────────────────

    public function testDecryptWithoutExplicitIvThrows(): void
    {
        $key = str_repeat('cd', 16);

        foreach ([Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR] as $mode) {
            $encOptions = (new Sm4Options())->setMode($mode)->setIv(str_repeat('11', 16));
            $ciphertext = Sm4::encrypt('secret', $key, $encOptions);

            try {
                // 新建 options 且未设置 IV：必须拒绝而不是随机生成 IV 返回乱码
                Sm4::decrypt($ciphertext, $key, (new Sm4Options())->setMode($mode));
                $this->fail("Expected InvalidKeyException for mode {$mode}");
            } catch (InvalidKeyException $e) {
                $this->assertStringContainsString('IV is required', $e->getMessage());
            }
        }
    }

    public function testGcmDecryptWithoutExplicitIvThrows(): void
    {
        $key = str_repeat('ef', 16);
        $encOptions = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(bin2hex(random_bytes(12)));
        $ciphertext = Sm4::encrypt('secret', $key, $encOptions);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('IV is required');
        Sm4::decrypt($ciphertext, $key, (new Sm4Options())->setMode(Sm4::MODE_GCM));
    }

    public function testSelfContainedCbcDecryptStillWorksWithoutOptions(): void
    {
        $key = str_repeat('9a', 16);
        $ciphertext = Sm4::encrypt('self contained', $key);
        $this->assertSame('self contained', Sm4::decrypt($ciphertext, $key));
    }

    public function testRoundTripReusingSameOptionsObjectStillWorks(): void
    {
        $key = str_repeat('bc', 16);
        $options = (new Sm4Options())->setIv(str_repeat('22', 16));

        $ciphertext = Sm4::encrypt('roundtrip', $key, $options);
        $this->assertSame('roundtrip', Sm4::decrypt($ciphertext, $key, $options));
    }

    // ─── SM2 用户 ID 长度限制 (GM/T 0003-2012 附录 A) ─────────────────────

    public function testUserIdLongerThanEntlLimitIsRejected(): void
    {
        $method = new \ReflectionMethod(Sm2::class, 'getUserIdHash');
        $method->setAccessible(true);
        $x = str_pad('1', 64, '0');
        $y = str_pad('2', 64, '0');

        // 8192 字节 = 65536 bit > ENTL 上限
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('ENTL is a 16-bit field');
        $method->invoke(null, str_repeat('u', 8192), $x, $y);
    }

    public function testUserIdAtEntlLimitIsAccepted(): void
    {
        $method = new \ReflectionMethod(Sm2::class, 'getUserIdHash');
        $method->setAccessible(true);
        $x = str_pad('1', 64, '0');
        $y = str_pad('2', 64, '0');

        // 8191 字节 = 65528 bit，恰好在上限内；ENTL 前缀必须是 4 个 hex 字符
        $hash = $method->invoke(null, str_repeat('u', 8191), $x, $y);
        if (!is_string($hash)) {
            $this->fail('getUserIdHash must return a string');
        }
        $this->assertSame('fff8', substr($hash, 0, 4));
        $this->assertMatchesRegularExpression('/^[0-9a-fA-F]{4}[0-9a-fA-F]+$/', $hash);
    }

    // ─── GCM IV 重用检测 ──────────────────────────────────────────────────

    public function testGcmIvReuseDetectedByDefault(): void
    {
        $key = str_repeat('77', 16);
        $iv = bin2hex(random_bytes(12));
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv);

        Sm4::enableGcmIvTracking();
        try {
            Sm4::encrypt('first', $key, $options);
            $this->expectException(CryptoException::class);
            $this->expectExceptionMessage('GCM IV reuse detected');
            Sm4::encrypt('second', $key, $options);
        } finally {
            Sm4::resetGcmIvTracking();
        }
    }

    public function testGcmIvTrackingResetAllowsFreshIvReuseOfOptionsObject(): void
    {
        $key = str_repeat('78', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('33', 12));

        Sm4::enableGcmIvTracking();
        try {
            Sm4::encrypt('a', $key, $options);
            Sm4::resetGcmIvTracking();
            Sm4::encrypt('b', $key, $options); // 重置后允许（测试场景），生产环境应始终使用新 IV
            $this->addToAssertionCount(1);
        } finally {
            Sm4::resetGcmIvTracking();
        }
    }

    public function testGcmIvTrackingCanBeDisabled(): void
    {
        $key = str_repeat('79', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('44', 12));

        Sm4::enableGcmIvTracking(false);
        try {
            Sm4::encrypt('a', $key, $options);
            Sm4::encrypt('b', $key, $options); // 关闭后不再拦截（向后兼容逃生口）
            $this->addToAssertionCount(1);
        } finally {
            Sm4::enableGcmIvTracking();
            Sm4::resetGcmIvTracking();
        }
    }

    public function testEncryptPayloadNeverTriggersIvReuseDetection(): void
    {
        $key = str_repeat('7a', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM);

        Sm4::enableGcmIvTracking();
        try {
            $p1 = Sm4::encryptPayload('same data', $key, $options);
            $p2 = Sm4::encryptPayload('same data', $key, $options);
            $iv1 = is_string($p1['iv'] ?? null) ? $p1['iv'] : null;
            $iv2 = is_string($p2['iv'] ?? null) ? $p2['iv'] : null;
            $this->assertNotNull($iv1);
            $this->assertNotNull($iv2);
            $this->assertNotSame($iv1, $iv2);
            $this->assertSame('same data', Sm4::decryptPayload($p1, $key));
            $this->assertSame('same data', Sm4::decryptPayload($p2, $key));
        } finally {
            Sm4::resetGcmIvTracking();
        }
    }

    // ─── GCM tagLength 校验一致性 ─────────────────────────────────────────

    public function testGcmClassRejectsNonStandardTagLengths(): void
    {
        $gcm = Gcm::fromKey(random_bytes(16));

        foreach ([5, 6, 7, 9, 10, 11, 0, -1, 17] as $badTagLength) {
            try {
                $gcm->encrypt('x', random_bytes(12), '', $badTagLength);
                $this->fail("Expected CryptoException for tagLength={$badTagLength}");
            } catch (CryptoException $e) {
                $this->assertStringContainsString('invalid tag length', $e->getMessage());
            }
        }
    }

    // ─── setMode 幂等性 ──────────────────────────────────────────────────

    public function testSetModeSameValuePreservesIv(): void
    {
        $iv = str_repeat('55', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setIv($iv);
        $options->setMode(Sm4::MODE_CBC)->setMode('CBC');

        $this->assertSame($iv, $options->getIv());
    }

    public function testSetModeDifferentValueResetsIv(): void
    {
        $options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setIv(str_repeat('66', 16));
        $options->setMode(Sm4::MODE_CTR);

        $this->assertFalse($options->hasIv());
    }

    // ─── PEM 标签严格匹配 ────────────────────────────────────────────────

    public function testPemWithMismatchedBeginEndLabelsIsRejected(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $pem = Pem::exportPrivateKey($kp->getPrivateKey(), $kp->getPublicKey());
        $mismatched = str_replace(
            '-----END EC PRIVATE KEY-----',
            '-----END PRIVATE KEY-----',
            $pem
        );

        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKey($mismatched);
    }

    // ─── 密钥交换 klen 边界 ───────────────────────────────────────────────

    public function testKeyExchangeRejectsOversizedKlen(): void
    {
        $kp = Sm2::generateKeyPairHex();

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('must not exceed');
        KeyExchange::initiatorComputeKey(
            $kp->getPrivateKey(),
            $kp->getPrivateKey(),
            $kp->getPublicKey(),
            $kp->getPublicKey(),
            KeyExchange::MAX_KLEN + 1
        );
    }

    public function testKeyExchangeAcceptsKlenAtUpperBound(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $ephemeral = Sm2::generateKeyPairHex();

        $key = KeyExchange::initiatorComputeKey(
            $kp->getPrivateKey(),
            $ephemeral->getPrivateKey(),
            $kp->getPublicKey(),
            $ephemeral->getPublicKey(),
            KeyExchange::MAX_KLEN
        );

        $this->assertSame(KeyExchange::MAX_KLEN * 2, strlen($key));
    }
}
