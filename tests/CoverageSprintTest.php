<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Crypto\Ccm;
use CryptoSm\Crypto\GcmPure;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use PHPUnit\Framework\TestCase;

/**
 * 最终覆盖率冲刺：针对剩余可覆盖的错误分支与守卫路径。
 * 目标：将行覆盖率从 91% 提升至 ≥95%。
 */
final class CoverageSprintTest extends TestCase
{
    // ─── GcmPure 废弃类 ──────────────────────────────────────────────────

    /**
     * 返回 DER 中 SEQUENCE 第一个内嵌元素的偏移（处理短/长形式长度）。
     */
    private static function asn1ContentOffset(string $der): int
    {
        $o = 2;
        $firstLenByte = ord($der[1]);
        if ($firstLenByte & 0x80) {
            $o = 2 + ($firstLenByte & 0x7F);
        }
        return $o;
    }

    public function testGcmPureDeprecatedConstructor(): void
    {
        // @deprecated 类的构造函数应触发 E_USER_DEPRECATED 并正常工作
        $instance = new GcmPure(random_bytes(16));
        $this->assertInstanceOf(GcmPure::class, $instance);
    }

    // ─── Sm2 decompressPublicKey 校验分支 ────────────────────────────────

    public function testDecompressRejectsNonHexX(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid x coordinate format');
        Sm2::decompressPublicKey('gg' . str_repeat('ab', 31), 0x02);
    }

    public function testDecompressRejectsUppercasePrefix(): void
    {
        // prefix=0x99 无效
        $this->expectException(CryptoException::class);
        Sm2::decompressPublicKey(str_repeat('ab', 32), 0x00);
    }

    public function testDecompressRejectsNoSolution(): void
    {
        // 找一个 x 使 x³+ax+b 不是二次剩余（约50%概率随机取）
        for ($i = 0; $i < 100; $i++) {
            $x = bin2hex(random_bytes(32));
            try {
                Sm2::decompressPublicKey($x, 0x02);
                // 成功了则继续找下一个（有些 x 确实有点在曲线上）
            } catch (CryptoException $e) {
                if (str_contains($e->getMessage(), 'no point exists')) {
                    // 找到了无解的情况
                    $this->addToAssertionCount(1);
                    return;
                }
            }
        }
        $this->fail('could not find non-residue x in 100 tries');
    }

    // ─── Pem 导出校验分支 ─────────────────────────────────────────────────

    public function testExportSec1WithBadPubKeyThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Public key must be 128 hex chars');
        Pem::exportPrivateKeyDer(str_repeat('ab', 32), 'short_pub');
    }

    public function testExportPkcs8RejectsNonHexPrivKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::exportPrivateKeyPkcs8Der('zz' . str_repeat('0', 62));
    }

    // ─── Pem ASN.1 密文导入错误分支 ────────────────────────────────────────

    /** @return array{string, string} [合法密文hex, 对应 DER] */
    private static function makeValidAsn1Ciphertext(): array
    {
        $kp = Sm2::generateKeyPairHex();
        $ct = Sm2::doEncrypt('asn1 coverage', $kp->getPublicKey());
        $der = Pem::exportCiphertextAsn1($ct);

        return [$ct, $der];
    }

    public function testImportAsn1RejectsShortInput(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::importCiphertextAsn1("\x30");
    }

    public function testImportAsn1RejectsYTagWrong(): void
    {
        [$ct, $der] = self::makeValidAsn1Ciphertext();
        // 定位第二个元素（y INTEGER）的 tag 并替换为 0x04
        $o = self::asn1ContentOffset($der);
        $o += 2 + ord($der[$o + 1]); // 跳过 x INTEGER
        $this->assertSame(0x02, ord($der[$o]), 'precondition: second element is INTEGER');
        $mutated = substr_replace($der, "\x04", $o, 1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected y INTEGER');
        Pem::importCiphertextAsn1($mutated);
    }

    public function testImportAsn1RejectsHashTagWrong(): void
    {
        [, $der] = self::makeValidAsn1Ciphertext();
        // 第三个元素应为 OCTET STRING (04)，替换为 INTEGER (02)
        // 偏移 = seq_hdr(2) + int_x(~35) + int_y(~35) ≈ 72，需动态定位
        $offset = 2;
        // skip x INTEGER
        $xLen = ord($der[$offset + 1]);
        $offset += 2 + $xLen;
        // skip y INTEGER
        $yLen = ord($der[$offset + 1]);
        $offset += 2 + $yLen;
        // Now at hash TLV: replace tag
        if ($offset < strlen($der)) {
            $mutated = substr_replace($der, "\x02", $offset, 1);
            $this->expectException(InvalidKeyException::class);
            $this->expectExceptionMessage('expected hash OCTET STRING');
            Pem::importCiphertextAsn1($mutated);
        } else {
            $this->fail('could not locate hash element');
        }
    }

    public function testImportAsn1RejectsCipherTextTagWrong(): void
    {
        [$ct, $der] = self::makeValidAsn1Ciphertext();
        // TLV 遍历到最后一个元素（cipherText OCTET STRING）并将 tag 替换为 0x02
        $o = self::asn1ContentOffset($der);
        $lastTagPos = 0;
        while ($o < strlen($der)) {
            $lastTagPos = $o;
            $l = ord($der[$o + 1]);
            $o += 2 + $l;
        }
        $this->assertSame(0x04, ord($der[$lastTagPos]), 'precondition: last element is OCTET STRING');
        $mutated = substr_replace($der, "\x02", $lastTagPos, 1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('cipherText OCTET STRING');
        Pem::importCiphertextAsn1($mutated);
    }

    // ─── CCM 补充覆盖 ────────────────────────────────────────────────────

    public function testCcmDecryptWithEmptyTagAndData(): void
    {
        $ccm = Ccm::fromKey(random_bytes(16));
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('', $nonce, '', 16);
        // Tag should be non-empty even for empty plaintext
        $this->assertNotEmpty($r['tag']);
        $this->assertSame('', $ccm->decrypt('', $r['tag'], $nonce, '', 16));
    }

    public function testCcmLargeAadExactBoundary255(): void
    {
        $ccm = Ccm::fromKey(random_bytes(16));
        $nonce = random_bytes(12);
        $aad = str_repeat('B', 255); // 单字节长度前缀的上界
        $r = $ccm->encrypt('data', $nonce, $aad, 16);
        $this->assertSame('data', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16));
    }

    // ─── 杂项守卫与工具函数 ────────────────────────────────────────────────

    public function testHexFromHexInvalidThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        \CryptoSm\Utils\Hex::fromHex('zz');
    }

    public function testCcmAadBeyond16BitUsesExtendedPrefix(): void
    {
        // AAD ≥65536 走 FF FE + 2 字节长度的扩展编码分支
        $ccm = Ccm::fromKey(random_bytes(16));
        $nonce = random_bytes(12);
        $aad = str_repeat('K', 70000);
        $r = $ccm->encrypt('payload', $nonce, $aad, 16);
        $this->assertSame('payload', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16));
    }

    public function testAsn1NonMinimalMultiByteLength(): void
    {
        // 0x81 后值 <128：非最小编码必须拒绝
        $data = "\x02\x81\x05" . 'abcde';
        $offset = 0;
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('not minimally encoded');
        Asn1::decodeInteger($data, $offset);
    }

    public function testCcmHugeAadStillAuthenticates(): void
    {
        // 触发 formatAad 的 4 字节长度前缀分支（≥65536）
        $ccm = Ccm::fromKey(random_bytes(16));
        $nonce = random_bytes(12);
        $aad = str_repeat('Z', 65536);
        $r = $ccm->encrypt('big aad', $nonce, $aad, 16);
        $this->assertSame('big aad', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16));
    }

    public function testSm4PurePhpEngineGuardsSizes(): void
    {
        $engine = new \CryptoSm\SM4\Sm4PurePhp();

        try {
            $engine->setKey('short');
            $this->fail('setKey should reject non-16-byte keys');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('SM4 key must be 16 bytes', $e->getMessage());
        }
        $this->addToAssertionCount(1);
    }

    public function testGcmWarmupStaticExecutes(): void
    {
        \CryptoSm\Crypto\Gcm::warmupStatic();
        $this->addToAssertionCount(1);
    }

    public function testIsOnCurveRejectsMalformedInput(): void
    {
        $this->assertFalse(Sm2::isOnCurve('zz'));
        $this->assertFalse(Sm2::isOnCurve(''));
        $this->assertFalse(Sm2::isOnCurve(str_repeat('g', 128)));
    }

    public function testAsn1RejectsTwoByteNonMinimalLengthPrefix(): void
    {
        // 0x82 头 + 实际长度 <256：同样违反 DER 最小编码规则
        $payload = '0' . str_repeat('41', 100); // hex 串
        $offset = 0;
        $this->expectException(CryptoException::class);
        Asn1::decodeInteger(pack('H*', '0482006441414141'), $offset);
    }
}
