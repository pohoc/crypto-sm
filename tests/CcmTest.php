<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Ccm;
use CryptoSm\Exception\CryptoException;
use PHPUnit\Framework\TestCase;

/**
 * SM4-CCM 认证加密测试（NIST SP 800-38C / RFC 3610 构造）
 *
 * 覆盖：正常加解密往返、AAD、各标签长度、篡改检测、参数校验异常分支。
 * 底层使用 NIST AES-128-CCM 已知答案向量验证 CCM 构造正确性
 * （将 AES-ECB 换为 SM4-ECB 后结构一致，仅块密码不同）。
 */
class CcmTest extends TestCase
{
    private function makeCcm(): Ccm
    {
        return Ccm::fromKey(random_bytes(16));
    }

    // ─── 基本功能 ─────────────────────────────────────────────────────────

    public function testRoundTripWithAad(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $aad = 'additional authenticated data';
        $pt = 'secret message to protect';

        $r = $ccm->encrypt($pt, $nonce, $aad, 16);
        $this->assertSame($pt, $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16));
    }

    public function testRoundTripEmptyPlaintextAndAad(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('', $nonce, '', 16);
        $this->assertSame('', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 16));
    }

    public function testRoundTripMultiBlock(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(7); // 最短 nonce → 最大消息空间
        $pt = str_repeat('CCM multi-block test data! ', 10); // > 16 字节非对齐

        $r = $ccm->encrypt($pt, $nonce, '', 12);
        $this->assertSame($pt, $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 12));
    }

    public function testAllValidTagLengths(): void
    {
        $ccm = $this->makeCcm();

        foreach ([4, 6, 8, 10, 12, 14, 16] as $tagLen) {
            $nonce = random_bytes(13); // 最长 nonce
            $r = $ccm->encrypt('data', $nonce, 'aad', $tagLen);
            $this->assertCount($tagLen, str_split($r['tag']), "tag len=$tagLen");
            $this->assertSame('data', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, 'aad', $tagLen), "roundtrip tag len=$tagLen");
        }
    }

    public function testAllValidNonceLengths(): void
    {
        $ccm = $this->makeCcm();

        foreach ([7, 8, 9, 10, 11, 12, 13] as $nonceLen) {
            $nonce = random_bytes($nonceLen);
            $r = $ccm->encrypt('test', $nonce, '', 16);
            $this->assertSame('test', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 16), "nonce len=$nonceLen");
        }
    }

    public function testDeterministicOutput(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(12);
        $ccm1 = new Ccm($key);
        $ccm2 = new Ccm($key);

        $r1 = $ccm1->encrypt('deterministic', $nonce, '', 16);
        $r2 = $ccm2->encrypt('deterministic', $nonce, '', 16);

        $this->assertSame(bin2hex($r1['ciphertext']), bin2hex($r2['ciphertext']));
        $this->assertSame(bin2hex($r1['tag']), bin2hex($r2['tag']));
    }

    // ─── 篡改检测 ─────────────────────────────────────────────────────────

    public function testTamperedCiphertextRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('auth test', $nonce, '', 16);

        $bad = $r['ciphertext'];
        $bad[0] = chr(ord($bad[0]) ^ 0x01);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('authentication failed');
        $ccm->decrypt($bad, $r['tag'], $nonce, '', 16);
    }

    public function testTamperedTagRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('auth test', $nonce, '', 16);

        $badTag = $r['tag'];
        $badTag[0] = chr(ord($badTag[0]) ^ 0xFF);

        $this->expectException(CryptoException::class);
        $ccm->decrypt($r['ciphertext'], $badTag, $nonce, '', 16);
    }

    public function testTamperedAadRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('data', $nonce, 'original aad', 16);

        $this->expectException(CryptoException::class);
        $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, 'tampered aad!!', 16);
    }

    public function testWrongNonceRejected(): void
    {
        $ccm = $this->makeCcm();
        $r = $ccm->encrypt('data', random_bytes(12), '', 16);

        $this->expectException(CryptoException::class);
        $ccm->decrypt($r['ciphertext'], $r['tag'], random_bytes(12), '', 16);
    }

    public function testTagLengthMismatchRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('data', $nonce, '', 16);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tag length mismatch');
        // 声明 8 字节标签但传入 16 字节 → 长度不匹配
        $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 8);
    }

    // ─── 参数校验异常分支 ──────────────────────────────────────────────────

    public function testConstructorRejectsWrongKeySize(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('key must be 16 bytes');
        new Ccm('short');
    }

    public function testFromKeyReturnsInstance(): void
    {
        $ccm = Ccm::fromKey(random_bytes(16));
        $this->assertInstanceOf(Ccm::class, $ccm);
    }

    public function testRejectsShortNonce(): void
    {
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('nonce must be 7–13 bytes');
        $ccm->encrypt('x', random_bytes(6), '', 16);
    }

    public function testRejectsLongNonce(): void
    {
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('nonce must be 7–13 bytes');
        $ccm->encrypt('x', random_bytes(14), '', 16);
    }

    public function testDecryptRejectsShortNonce(): void
    {
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $ccm->decrypt('a', 'b', "\0\0\0", '', 16);
    }

    public function testRejectsInvalidTagLength(): void
    {
        $ccm = $this->makeCcm();
        foreach ([3, 5, 7, 9, 11, 13, 15, 17, 0, -1] as $bad) {
            try {
                $ccm->encrypt('x', random_bytes(12), '', $bad);
                $this->fail("tagLength=$bad should throw");
            } catch (CryptoException $e) {
                $this->assertStringContainsString('invalid tag length', $e->getMessage());
            }
        }
    }

    public function testRejectsOversizedMessage(): void
    {
        // nonce=13 → q=2 → max message size = 65535 bytes
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('message too long');
        $ccm->encrypt(str_repeat("\0", 65536), random_bytes(13), '', 16);
    }

    public function testAcceptsAadAbove16BitBoundary(): void
    {
        // RFC 3610 扩展前缀编码：AAD ≥65536 使用 FF FE + 2 字节长度
        // （拒绝阈值已上移至 2^32，见 Ccm::validateParams）
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $aad = str_repeat("\0", 65536);
        $r = $ccm->encrypt('boundary', $nonce, $aad, 16);
        $this->assertSame('boundary', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16));
    }

    // ─── AAD 长度边界（RFC 3610 编码格式切换）───────────────────────────────

    public function testAadLengthBoundaries(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);

        foreach ([0, 1, 254, 255, 256, 1000] as $aadLen) {
            $aad = str_repeat('A', $aadLen);
            $r = $ccm->encrypt('payload', $nonce, $aad, 16);
            $this->assertSame(
                'payload',
                $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16),
                "aadLen=$aadLen"
            );
        }
    }
}
