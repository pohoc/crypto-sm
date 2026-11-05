<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use PHPUnit\Framework\TestCase;

/**
 * 本轮新增功能的错误分支与边界覆盖：
 * - SM2 密文 ASN.1 导出/导入（GM/T 0009）
 * - 压缩公钥导入（GM/T 0003.1）
 * - decompressPublicKey 校验分支
 */
class NewFeatureCoverageTest extends TestCase
{
    private static function derCoordinate(string $coordinateHex): string
    {
        $bytes = ltrim((string) hex2bin($coordinateHex), "\0");
        if ($bytes === '') {
            $bytes = "\0";
        } elseif ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\0" . $bytes;
        }

        return "\x02" . chr(strlen($bytes)) . $bytes;
    }

    // ─── SM2 密文 ASN.1 导出 ──────────────────────────────────────────────

    /**
     * @return array{0: string, 1: \CryptoSm\SM2\Keypair}
     */
    private function makeCiphertext(int $mode): array
    {
        $kp = Sm2::generateKeyPairHex();
        $opts = (new \CryptoSm\SM2\Sm2CipherOptions())->setCipherMode($mode);
        $ct = Sm2::doEncrypt('test payload', $kp->getPublicKey(), $opts);

        return [$ct, $kp];
    }

    public function testExportAsn1RejectsShortCiphertext(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('too short');
        Pem::exportCiphertextAsn1('aabb', Sm2::CIPHER_MODE_1);
    }

    public function testExportAsn1RejectsNonHexCoordinates(): void
    {
        $bad = 'zz' . str_repeat('ab', 63) . str_repeat('cd', 32) . str_repeat('ef', 19);
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('not valid hex');
        Pem::exportCiphertextAsn1($bad, Sm2::CIPHER_MODE_1);
    }

    public function testExportAsn1RejectsNonHexC3(): void
    {
        [$ciphertext] = $this->makeCiphertext(Sm2::CIPHER_MODE_1);
        $ciphertext[130] = 'z';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('C2/C3 is not valid hex');
        Pem::exportCiphertextAsn1($ciphertext, Sm2::CIPHER_MODE_1);
    }

    public function testExportAsn1RejectsNonHexC2(): void
    {
        [$ciphertext] = $this->makeCiphertext(Sm2::CIPHER_MODE_1);
        $ciphertext[194] = 'z';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('C2/C3 is not valid hex');
        Pem::exportCiphertextAsn1($ciphertext, Sm2::CIPHER_MODE_1);
    }

    public function testExportAsn1RejectsEmptyC2(): void
    {
        [$ciphertext] = $this->makeCiphertext(Sm2::CIPHER_MODE_1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('C2/C3 is not valid hex');
        Pem::exportCiphertextAsn1(substr($ciphertext, 0, 194), Sm2::CIPHER_MODE_1);
    }

    public function testExportAsn1RejectsOffCurveC1(): void
    {
        $ciphertext = str_repeat('0', 128) . str_repeat('a', 64) . '00';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('C1 point is not on SM2 curve');
        Pem::exportCiphertextAsn1($ciphertext, Sm2::CIPHER_MODE_1);
    }

    public function testCiphertextAsn1RejectsInvalidMode(): void
    {
        [$ciphertext] = $this->makeCiphertext(Sm2::CIPHER_MODE_1);

        try {
            Pem::exportCiphertextAsn1($ciphertext, 2);
            $this->fail('Invalid export mode should be rejected');
        } catch (InvalidKeyException $exception) {
            $this->assertStringContainsString('Cipher mode must be', $exception->getMessage());
        }

        $der = Pem::exportCiphertextAsn1($ciphertext);
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Cipher mode must be');
        Pem::importCiphertextAsn1($der, 2);
    }

    public function testPrivateKeyExportRejectsOutOfRangeScalars(): void
    {
        $exporters = [
            static fn (string $key): string => Pem::exportPrivateKey($key),
            static fn (string $key): string => Pem::exportPrivateKeyPkcs8($key),
            static fn (string $key): string => Pem::exportPrivateKeyPkcs8Der($key),
        ];
        $invalidKeys = [
            str_repeat('0', 64),
            'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123',
        ];

        foreach ($invalidKeys as $invalidKey) {
            foreach ($exporters as $export) {
                try {
                    $export($invalidKey);
                    $this->fail('Out-of-range SM2 private scalar should not be exported');
                } catch (InvalidKeyException $exception) {
                    $this->assertStringContainsString('range', $exception->getMessage());
                }
            }
        }
    }

    public function testSec1PrivateKeyExportRejectsMismatchedPublicKey(): void
    {
        $privateKey = Sm2::generateKeyPairHex();
        $otherKey = Sm2::generateKeyPairHex();
        $exporters = [
            static fn (): string => Pem::exportPrivateKey($privateKey->getPrivateKey(), $otherKey->getPublicKey()),
            static fn (): string => Pem::exportPrivateKeyDer($privateKey->getPrivateKey(), $otherKey->getPublicKey()),
        ];

        foreach ($exporters as $export) {
            try {
                $export();
                $this->fail('SEC1 export must reject a public key that does not match the private key');
            } catch (InvalidKeyException $exception) {
                $this->assertStringContainsString('public key does not match', $exception->getMessage());
            }
        }
    }

    public function testExportAsn1Mode0ProducesCorrectOrder(): void
    {
        [$ct, ] = $this->makeCiphertext(Sm2::CIPHER_MODE_0);
        $der = Pem::exportCiphertextAsn1($ct, Sm2::CIPHER_MODE_0);
        // DER 结构必须以 SEQUENCE 开头
        $this->assertSame(0x30, ord($der[0]));
        // DER INTEGER 坐标不携带 SEC1 04 前缀；导入结果规范化为 x||y。
        // 去掉加密输出中的前缀后，验证 C1C2C3 的顺序和内容一致。
        $back = Pem::importCiphertextAsn1($der, Sm2::CIPHER_MODE_0);
        $this->assertStringStartsWith('04', $ct);
        $this->assertSame(strtolower(substr($ct, 2)), strtolower($back));
    }

    public function testImportAsn1RejectsNonSequence(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected SEQUENCE');
        Pem::importCiphertextAsn1("\x31\x03\x01\x02\x03");
    }

    public function testImportAsn1RejectsTrailingData(): void
    {
        // 构造一个合法密文再附加垃圾字节
        [$ct, ] = $this->makeCiphertext(Sm2::CIPHER_MODE_1);
        $der = Pem::exportCiphertextAsn1($ct, Sm2::CIPHER_MODE_1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('trailing data');
        Pem::importCiphertextAsn1($der . "\x00");
    }

    public function testImportAsn1RejectsWrongFirstTag(): void
    {
        // SEQUENCE 后第一个元素应为 INTEGER (0x02)，用 OCTET STRING (0x04) 替代
        $fakeDer = "\x30\x06\x04\x02\x00\x01\x02\x00";
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected x INTEGER');
        Pem::importCiphertextAsn1($fakeDer);
    }

    public function testImportAsn1RejectsOversizedX(): void
    {
        // x 长度 34 > 最大 33
        $content = "\x02\x22" . str_repeat("\x01", 34) . "\x02\x20" . str_repeat("\x02", 32) . "\x04\x20" . str_repeat("\x03", 32) . "\x04\x00";
        $der = "\x30" . chr(strlen($content)) . $content;
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('invalid x length');
        Pem::importCiphertextAsn1($der);
    }

    public function testImportAsn1RejectsMissingY(): void
    {
        // x 正确但 y 缺失
        $content = "\x02\x20" . str_repeat("\x01", 32) . "\x04\x20" . str_repeat("\x03", 32) . "\x04\x00";
        $der = "\x30" . chr(strlen($content)) . $content;
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected y INTEGER');
        Pem::importCiphertextAsn1($der);
    }

    public function testImportAsn1RejectsOversizedY(): void
    {
        $yBin = str_repeat("\x02", 34);
        $content = "\x02\x20" . str_repeat("\x01", 32)
            . "\x02\x22" . $yBin
            . "\x04\x20" . str_repeat("\x03", 32) . "\x04\x00";
        $der = "\x30" . chr(strlen($content)) . $content;
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('invalid y length');
        Pem::importCiphertextAsn1($der);
    }

    public function testImportAsn1RejectsWrongHashLength(): void
    {
        $pub = Sm2::generateKeyPairHex()->getPublicKey();

        $content = self::derCoordinate(substr($pub, 0, 64))
            . self::derCoordinate(substr($pub, 64, 64))
            . "\x04\x10" . str_repeat("\xCC", 16); // hash 只有 16 字节
        $der = "\x30" . chr(strlen($content)) . $content;
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('hash must be 32 bytes');
        Pem::importCiphertextAsn1($der);
    }

    public function testImportAsn1RejectsOffCurvePoint(): void
    {
        // 构造一个不在曲线上的点
        $xBin = str_repeat("\x01", 32);
        $yBin = str_repeat("\x02", 32);
        $content = "\x02\x20" . $xBin
            . "\x02\x20" . $yBin
            . "\x04\x20" . str_repeat("\x03", 32)
            . "\x04\x01\x00";
        $der = "\x30" . chr(strlen($content)) . $content;
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('not on curve');
        Pem::importCiphertextAsn1($der);
    }

    public function testImportAsn1RejectsEmptyCipherText(): void
    {
        $publicKey = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $x = self::derCoordinate(substr($publicKey, 0, 64));
        $y = self::derCoordinate(substr($publicKey, 64, 64));
        $hash = "\x04\x20" . str_repeat("\0", 32);
        $cipherText = "\x04\x00";
        $content = $x . $y . $hash . $cipherText;
        $der = "\x30" . chr(strlen($content)) . $content;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('cipherText must not be empty');
        Pem::importCiphertextAsn1($der);
    }

    public function testImportAsn1RejectsMissingCipherText(): void
    {
        // 使用合法点但缺少 cipherText 字段
        $pub = Sm2::generateKeyPairHex()->getPublicKey();
        $content = self::derCoordinate(substr($pub, 0, 64))
            . self::derCoordinate(substr($pub, 64, 64))
            . "\x04\x20" . str_repeat("\x03", 32);
        // 无最后的 OCTET STRING
        $der = "\x30" . chr(strlen($content)) . $content;
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('cipherText');
        Pem::importCiphertextAsn1($der);
    }

    // ─── 压缩公钥解压 ────────────────────────────────────────────────────

    public function testDecompressRejectsBadPrefix(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('must be 0x02 or 0x03');
        Sm2::decompressPublicKey(str_repeat('ab', 32), 0x99);
    }

    public function testDecompressRejectsOddLengthX(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid x coordinate format');
        Sm2::decompressPublicKey('abc', 0x02);
    }

    public function testDecompressRejectsOutOfRangeX(): void
    {
        // x >= p → 超出域
        $bigX = gmp_strval(gmp_add(Sm2::gmpParamPublic('p'), gmp_init(1)), 16);
        $xHex = str_pad($bigX, 64, '0', STR_PAD_LEFT);
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('out of range');
        Sm2::decompressPublicKey($xHex, 0x02);
    }

    public function testDecompressBothParitiesOnCurve(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $x = substr($kp->getPublicKey(), 0, 64);
        $y = substr($kp->getPublicKey(), 64, 64);
        $isOdd = (int) gmp_strval(gmp_mod(gmp_init($y, 16), gmp_init(2))) === 1;

        foreach ([0x02, 0x03] as $prefix) {
            $result = Sm2::decompressPublicKey($x, $prefix);
            $this->assertTrue(Sm2::isOnCurve($result), 'prefix=0x' . dechex($prefix));
            // 检查 y 奇偶是否正确
            $rY = substr($result, 64, 64);
            $rIsOdd = (int) gmp_strval(gmp_mod(gmp_init($rY, 16), gmp_init(2))) === 1;
            if ($prefix === 0x02) {
                $this->assertFalse($rIsOdd, 'prefix 02 must produce even y');
            } else {
                $this->assertTrue($rIsOdd, 'prefix 03 must produce odd y');
            }
        }
        unset($isOdd);
    }
}
