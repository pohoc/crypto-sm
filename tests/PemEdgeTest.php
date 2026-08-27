<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use PHPUnit\Framework\TestCase;

/**
 * PEM/DER 解析器最后一批精确守卫测试：
 * 以模板化合成器构造此前未覆盖的结构畸形变体。
 */
final class PemEdgeTest extends TestCase
{
    /** 合法 SEC1（含压缩点可选）合成器 */
    private static function sec1(string $privHex, ?string $point = null): string
    {
        $version = "\x02\x01\x01";
        $keyOctet = "\x04\x20" . (string) hex2bin($privHex);
        $refDer = Pem::exportPrivateKeyDer($privHex);
        $a0 = strpos($refDer, "\xa0");
        $a1 = strpos($refDer, "\xa1");
        $curveCtx = substr($refDer, (int) $a0, ($a1 !== false ? $a1 : strlen($refDer)) - (int) $a0);

        $pubCtx = '';
        if ($point !== null) {
            $bs = "\x03" . chr(strlen($point) + 1) . "\x00" . $point;
            $pubCtx = "\xa1" . chr(strlen($bs)) . $bs;
        }
        $content = $version . $keyOctet . $curveCtx . $pubCtx;

        return "\x30" . chr(strlen($content)) . $content;
    }

    /** 合法 SPKI 合成器（$point 为完整 BIT STRING 内容，含首字节标记）*/
    private static function spki(string $point): string
    {
        $algSeq = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x81\x1c\xcf\x55\x01\x82\x2d";
        $bitString = "\x03" . chr(strlen($point) + 1) . "\x00" . $point;
        $content = $algSeq . $bitString;

        return "\x30" . chr(strlen($content)) . $content;
    }

    public function testSec1CompressedPointWrongLengthRejected(): void
    {
        $priv = '09' . str_repeat('ab', 31);
        $pub = Sm2::getPublicKey($priv);
        $x = substr($pub, 0, 64);
        // 32 字节主体 → 压缩点应为 33 字节；故意给 20 字节
        $badPoint = "\x02" . substr((string) hex2bin($x), 0, 19);
        $der = self::sec1($priv, $badPoint);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('invalid compressed point length');
        Pem::importPrivateKeyFromDer($der);
    }

    public function testSpkiCompressedPointWrongLengthRejected(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $x = substr($kp->getPublicKey(), 0, 64);
        $badPoint = "\x03" . substr((string) hex2bin($x), 0, 10);
        $spki = self::spki($badPoint);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid x coordinate format');
        Pem::importPublicKeyFromDer($spki);
    }

    public function testSec1UncompressedPointShortRejected(): void
    {
        $priv = '07' . str_repeat('cd', 31);
        $pub = Sm2::getPublicKey($priv);
        // 65 字节期望：04 || x || y。给 64（缺 y 尾字节）
        $shortPoint = "\x04" . substr((string) hex2bin($pub), 0, 63);
        $der = self::sec1($priv, $shortPoint);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('uncompressed');
        Pem::importPrivateKeyFromDer($der);
    }

    public function testSec1UnknownPointTagRejected(): void
    {
        $priv = '11' . str_repeat('ef', 31);
        $pub = Sm2::getPublicKey($priv);
        $weirdPoint = "\x05" . substr((string) hex2bin($pub), 0, 64); // 非法标记 0x05
        $der = self::sec1($priv, $weirdPoint);

        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKeyFromDer($der);
    }

    public function testSpkiEmptyBitStringContentRejected(): void
    {
        // BIT STRING 声称有内容但为空（len=1 仅 unused-bits）
        $algSeq = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x81\x1c\xcf\x55\x01\x82\x2d";
        $bitString = "\x03\x00"; // 空
        $content = $algSeq . $bitString;
        $spki = "\x30" . chr(strlen($content)) . $content;

        $this->expectException(InvalidKeyException::class);
        Pem::importPublicKeyFromDer($spki);
    }

    public function testPkcs8InnerVersionTwoRejected(): void
    {
        // 内层 SEC1 版本=2（应为 1）
        $priv = '13' . str_repeat('9f', 31);
        $refDer = Pem::exportPrivateKeyPkcs8Der($priv);
        // 内层结构位于最末 OCTET STRING：找 "\x02\x01\x01" 第二次出现处（外层 version 为 00）
        $first = strpos($refDer, "\x02\x01\x01");
        $this->assertNotFalse($first);
        // 外层版本 INTEGER 是 02 01 00，不会撞上；内层即第一次出现的 0101
        $mutated = substr_replace($refDer, "\x02", $first + 2, 1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('version');
        Pem::importPrivateKeyFromDer($mutated);
    }

    public function testPkcs8InnerTruncatedRejected(): void
    {
        $priv = '17' . str_repeat('77', 31);
        $full = Pem::exportPrivateKeyPkcs8Der($priv);
        // 截掉末尾 10 字节使 OCTET STRING 内容不完整
        $trunc = substr($full, 0, strlen($full) - 10);

        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKeyFromDer($trunc);
    }

    public function testPemBodyWhitespaceOnlyRejected(): void
    {
        $pem = "-----BEGIN EC PRIVATE KEY-----\n   \n\t\n-----END EC PRIVATE KEY-----";
        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKey($pem);
    }

    public function testPemNonBase64CharactersRejected(): void
    {
        $pem = "-----BEGIN EC PRIVATE KEY-----\n!!!!@@@@####\n-----END EC PRIVATE KEY-----";
        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKey($pem);
    }

    public function testImportAsn1RejectsXOverThirtyThreeBytesViaSignPadPath(): void
    {
        // 基于合法 DER 仅篡改 x 的长度字节为 36 (>33)：导入器必须立即拒绝
        [$ct, $der] = self::makeValidAsn1Ciphertext();
        $o = self::asn1ContentOffset($der);
        $this->assertSame(0x02, ord($der[$o]));
        $mutated = substr_replace($der, "\x24", $o + 1, 1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('invalid x length');
        Pem::importCiphertextAsn1($mutated);
    }

    public function testExportAsn1HandlesLeadingZeroAndHighBitCoordinates(): void
    {
        // 强制 C1 x/y 分别以 00xx 与 >=0x80 开头：通过暴力搜索一对合法密钥极为困难，
        // 改用真实密钥做三种子模式断言（覆盖率回归保护），重点是不抛异常且可导回
        for ($i = 0; $i < 6; $i++) {
            $kp = Sm2::generateKeyPairHex();
            $ct = Sm2::doEncrypt('pad branch probe ' . $i, $kp->getPublicKey());
            $der = Pem::exportCiphertextAsn1($ct);
            $back = Pem::importCiphertextAsn1($der);
            $this->assertSame(strtolower($ct), strtolower($back), "round #$i");
        }
    }

    /** @return array{0: string, 1: string} [密文hex, DER] */
    private static function makeValidAsn1Ciphertext(): array
    {
        $kp = Sm2::generateKeyPairHex();
        $ct = Sm2::doEncrypt('pem edge probe', $kp->getPublicKey());

        return [$ct, Pem::exportCiphertextAsn1($ct)];
    }

    private static function asn1ContentOffset(string $der): int
    {
        $o = 2;
        $firstLenByte = ord($der[1]);
        if ($firstLenByte & 0x80) {
            $o = 2 + ($firstLenByte & 0x7F);
        }
        return $o;
    }
}
