<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Asn1;
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
    public function testOidDecoderRejectsNonMinimalAndOversizedComponents(): void
    {
        $decodeOid = new \ReflectionMethod(Pem::class, 'decodeOid');
        $cases = [
            ["\x06\x02\x80\x2a", 'non-minimal OID component'],
            ["\x06\x0b" . str_repeat("\xff", 10) . "\x00", 'OID component exceeds supported range'],
        ];

        foreach ($cases as [$der, $message]) {
            try {
                $decodeOid->invoke(null, $der, 0);
                $this->fail('Malformed OID component must be rejected');
            } catch (InvalidKeyException $exception) {
                $this->assertStringContainsString($message, $exception->getMessage());
            }
        }

        $kp = Sm2::generateKeyPairHex();
        $nonMinimalAlgorithmOid = "\x06\x08\x80\x2a\x86\x48\xce\x3d\x02\x01";
        $sm2CurveOid = "\x06\x08\x2a\x81\x1c\xcf\x55\x01\x82\x2d";
        $algorithm = "\x30\x14" . $nonMinimalAlgorithmOid . $sm2CurveOid;
        $point = "\x04" . (string) hex2bin($kp->getPublicKey());
        $bitString = "\x03" . chr(strlen($point) + 1) . "\0" . $point;
        $content = $algorithm . $bitString;
        $spki = "\x30" . chr(strlen($content)) . $content;

        try {
            Pem::importPublicKeyFromDer($spki);
            $this->fail('Non-minimal algorithm OID must not be accepted in SPKI');
        } catch (InvalidKeyException $exception) {
            $this->assertStringContainsString('non-minimal OID component', $exception->getMessage());
        }
    }

    public function testDerLengthRejectsDeclaredLengthBeyondInput(): void
    {
        $parseLength = new \ReflectionMethod(Pem::class, 'parseDerLength');
        $oversizedLength = "\x84\x80\x00\x00\x00"; // 2 GiB cannot fit in this buffer

        $this->expectException(InvalidKeyException::class);
        $parseLength->invoke(null, $oversizedLength, 0);
    }

    public function testPemImportRejectsOversizedInputBeforeDecoding(): void
    {
        $oversizedPem = "-----BEGIN PUBLIC KEY-----\n"
            . str_repeat('A', 1024 * 1024)
            . "\n-----END PUBLIC KEY-----";

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Invalid PEM data');
        Pem::importPublicKey($oversizedPem);
    }

    public function testDerKeyImportsRejectOversizedInputBeforeParsing(): void
    {
        $oversizedDer = str_repeat("\0", 16 * 1024 + 1);

        foreach ([
            static fn () => Pem::importPrivateKeyFromDer($oversizedDer),
            static fn () => Pem::importPublicKeyFromDer($oversizedDer),
        ] as $import) {
            try {
                $import();
                $this->fail('Oversized DER key input must be rejected before parsing');
            } catch (InvalidKeyException $exception) {
                $this->assertSame('Invalid DER data: exceeds maximum key input size', $exception->getMessage());
            }
        }
    }

    public function testDerLengthRejectsNegativeOffset(): void
    {
        $parseLength = new \ReflectionMethod(Pem::class, 'parseDerLength');

        try {
            $parseLength->invoke(null, "\x00\x02", -1);
            $this->fail('Negative DER length offset must be rejected');
        } catch (InvalidKeyException $exception) {
            $this->assertSame('Invalid DER: unexpected end of length field', $exception->getMessage());
        }
    }

    public function testDerLengthRejectsLongFormForShortLength(): void
    {
        $parseLength = new \ReflectionMethod(Pem::class, 'parseDerLength');

        try {
            $parseLength->invoke(null, "\x81\x7f" . str_repeat("\0", 127), 0);
            $this->fail('DER short lengths must use the short form');
        } catch (InvalidKeyException $exception) {
            $this->assertSame('Invalid DER: non-minimal length encoding', $exception->getMessage());
        }
    }

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

    private static function pkcs8WithInnerSec1(string $inner): string
    {
        $algorithm = hex2bin('301306072a8648ce3d020106082a811ccf5501822d');
        self::assertIsString($algorithm);
        $octetString = "\x04" . Asn1::encodeLength(strlen($inner)) . $inner;
        $content = "\x02\x01\x00" . $algorithm . $octetString;

        return "\x30" . Asn1::encodeLength(strlen($content)) . $content;
    }

    public function testSec1AndPkcs8ImportRejectMismatchedEmbeddedPublicKey(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $otherPrivateKey = str_pad('2', 64, '0', STR_PAD_LEFT);
        $otherPublicKey = hex2bin(Sm2::getPublicKey($otherPrivateKey));
        self::assertIsString($otherPublicKey);

        $sec1 = self::sec1($privateKey, "\x04" . $otherPublicKey);
        $encodings = [$sec1, self::pkcs8WithInnerSec1($sec1)];

        foreach ($encodings as $der) {
            try {
                Pem::importPrivateKeyFromDer($der);
                $this->fail('Private-key import must reject a mismatched embedded public key');
            } catch (InvalidKeyException $exception) {
                $this->assertStringContainsString('public key does not match private key', $exception->getMessage());
            }
        }
    }

    public function testStandaloneSec1RequiresCurveParameters(): void
    {
        $priv = '09' . str_repeat('ab', 31);
        $withParameters = self::sec1($priv);
        $curveOffset = strpos($withParameters, "\xa0");
        self::assertNotFalse($curveOffset);
        $curveLength = ord($withParameters[$curveOffset + 1]) + 2;
        $withoutParametersBody = substr($withParameters, 2, $curveOffset - 2)
            . substr($withParameters, $curveOffset + $curveLength);
        $withoutParameters = "\x30" . chr(strlen($withoutParametersBody)) . $withoutParametersBody;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('missing required SM2 curve parameters');
        Pem::importPrivateKeyFromDer($withoutParameters);
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

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Invalid public key: Invalid x coordinate format');
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

    public function testPkcs8ExportIncludesRequiredInnerCurveParameters(): void
    {
        $privateKey = str_pad('19', 64, '0', STR_PAD_LEFT);
        $der = Pem::exportPrivateKeyPkcs8Der($privateKey);

        // RFC 5915 requires ECPrivateKey.parameters in conforming encodings.
        $innerSec1WithCurve = "\x02\x01\x01\x04\x20" . hex2bin($privateKey)
            . "\xa0\x0a\x06\x08\x2a\x81\x1c\xcf\x55\x01\x82\x2d";
        $this->assertStringContainsString($innerSec1WithCurve, $der);

        $imported = Pem::importPrivateKeyFromDer($der);
        $this->assertSame($privateKey, $imported['privateKey']);
        $this->assertSame(Sm2::getPublicKey($privateKey), $imported['publicKey']);
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

    public function testImportAsn1RejectsNegativeCoordinateInteger(): void
    {
        $c1 = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
            . 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0';
        $der = Pem::exportCiphertextAsn1($c1 . str_repeat('0', 64) . '00');
        $o = self::asn1ContentOffset($der);
        $xLen = ord($der[$o + 1]);
        $x = substr($der, $o + 2, $xLen);
        $rest = substr($der, $o + 2 + $xLen);
        $negativeX = "\x80" . $x;
        $content = "\x02" . chr(strlen($negativeX)) . $negativeX . $rest;
        $mutated = "\x30" . chr(strlen($content)) . $content;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('x INTEGER must be non-negative');
        Pem::importCiphertextAsn1($mutated);
    }

    public function testImportAsn1RejectsNonMinimalCoordinateInteger(): void
    {
        $c1 = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
            . 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0';
        $der = Pem::exportCiphertextAsn1($c1 . str_repeat('0', 64) . '00');
        $o = self::asn1ContentOffset($der);
        $xLen = ord($der[$o + 1]);
        $x = substr($der, $o + 2, $xLen);
        $rest = substr($der, $o + 2 + $xLen);
        $redundantX = "\0" . $x;
        $content = "\x02" . chr(strlen($redundantX)) . $redundantX . $rest;
        $mutated = "\x30" . chr(strlen($content)) . $content;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('non-minimal x INTEGER');
        Pem::importCiphertextAsn1($mutated);
    }

    public function testExportAsn1CiphertextRejectsTrailingNewlineInC2(): void
    {
        $publicKey = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $ciphertext = $publicKey . str_repeat('a', 64) . "a1\n";

        $this->expectException(InvalidKeyException::class);
        Pem::exportCiphertextAsn1($ciphertext);
    }

    public function testExportAsn1NormalizesPrefixedC1AndHighBitCoordinate(): void
    {
        // DER carries the C1 coordinates as INTEGERs, so import returns the
        // canonical x||y form without SEC1's optional 04 point prefix.
        // The fixed SM2 base point also guarantees a high-bit y coordinate,
        // exercising DER's required leading 00 sign pad without random cases.
        $c1 = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
            . 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0';
        $c3 = str_repeat('ab', 32);
        $c2 = 'cafe';
        $der = Pem::exportCiphertextAsn1('04' . $c1 . $c3 . $c2);
        $back = Pem::importCiphertextAsn1($der);

        $this->assertSame($c1 . $c3 . $c2, $back);

        $offset = self::asn1ContentOffset($der);
        $this->assertSame(32, ord($der[$offset + 1]));
        $yOffset = $offset + 2 + 32;
        $this->assertSame(33, ord($der[$yOffset + 1]));
        $this->assertSame("\0", $der[$yOffset + 2]);
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
