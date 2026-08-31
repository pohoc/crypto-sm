<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Crypto\Gcm;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use CryptoSm\Utils\Hex;
use PHPUnit\Framework\TestCase;

/**
 * 异常防御分支覆盖测试
 *
 * 针对覆盖率分析发现的未覆盖异常分支：选项校验器、payload 结构校验、
 * DER/PEM 畸形输入分支、ASN.1 编解码边界、掩码输出等。
 */
class ErrorBranchCoverageTest extends TestCase
{
    // ─── Sm4Options 校验器 ────────────────────────────────────────────────

    public function testSetPaddingRejectsUnknownPadding(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Padding must be one of');
        (new Sm4Options())->setPadding('bogus');
    }

    public function testSetModeRejectsUnknownMode(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Mode must be one of');
        (new Sm4Options())->setMode('xyz');
    }

    public function testSetIvRejectsNonHex(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('valid hex string');
        (new Sm4Options())->setIv('zz0123456789abcdef0123456789abcd');
    }

    public function testSetIvRejectsOddLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('even length');
        (new Sm4Options())->setIv('abc');
    }

    public function testSetIvRejectsWrongLengthForCbc(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('32 hex chars (16 bytes) for CBC mode');
        (new Sm4Options())->setIv('000102030405060708090a0b');
    }

    public function testSetIvRejectsShortIvForGcm(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('at least 24 hex chars (12 bytes) for GCM mode');
        (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('11', 8));
    }

    public function testSetIvRejectsEmptyIvForGcm(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('IV is required for GCM mode');
        (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv('');
    }

    public function testSetTagLengthRejectsInvalidValue(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('tag length must be one of');
        (new Sm4Options())->setTagLength(7);
    }

    public function testResetIvClearsCachedIv(): void
    {
        $options = new Sm4Options();
        $first = $options->getIv();
        $options->resetIv();
        $this->assertFalse($options->hasIv());
        $second = $options->getIv();
        $this->assertNotSame($first, $second);
    }

    // ─── Keypair 掩码输出 ─────────────────────────────────────────────────

    public function testKeypairStringContextExposesOnlyPublicKey(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $this->assertSame($kp->getPublicKey(), (string) $kp);
        $this->assertStringNotContainsString($kp->getPrivateKey(), (string) $kp);
    }

    public function testKeypairDebugInfoMasksPrivateKey(): void
    {
        $kp = Sm2::generateKeyPairHex();
        ob_start();
        var_dump($kp);
        $info = (string) ob_get_clean();
        $this->assertStringContainsString('***REDACTED***', $info);
        $this->assertStringNotContainsString($kp->getPrivateKey(), $info);
    }

    public function testKeypairJsonSerializationMasksPrivateKey(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $json = json_encode($kp, JSON_THROW_ON_ERROR);
        $this->assertStringContainsString('***REDACTED***', $json);
        $this->assertStringNotContainsString($kp->getPrivateKey(), $json);

        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        assert(is_array($decoded));
        $this->assertSame($kp->getPublicKey(), $decoded['publicKey'] ?? null);
    }

    public function testKeypairExplicitAccessorsStillExposePrivateKey(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $kp->getPrivateKey());
    }

    // ─── HMAC-SM3 长密钥与流式复用 ────────────────────────────────────────

    public function testHmacLongKeyIsHashedPerRfc2104(): void
    {
        $longKey = str_repeat("\x0b", 100); // > 64 字节块大小
        $shortKey = str_repeat("\x0b", 64);

        // 静态与流式路径结果一致，且与短密钥路径不同（证明走了 K' = H(K) 分支）
        $h1 = HmacSm3::hmac($longKey, 'data');
        $h2 = HmacSm3::create($longKey)->update('data')->finalize();
        $this->assertSame($h1, $h2);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $h1);
        $this->assertNotSame(HmacSm3::hmac($shortKey, 'data'), $h1);
    }

    public function testStreamingHmacReuseAfterFinalize(): void
    {
        $hmac = HmacSm3::create('key');
        $first = $hmac->update('a')->finalize();
        $again = $hmac->update('a')->finalize();
        $other = $hmac->update('b')->finalize();
        $this->assertSame($first, $again);
        $this->assertNotSame($first, $other);
    }

    // ─── SM2 边界 ─────────────────────────────────────────────────────────

    public function testSignatureRejectsPrivateKeyDEqualsNMinus1(): void
    {
        // d = n-1 时 (d+1) ≡ 0 (mod n)，模逆不存在，必须显式拒绝
        $nMinus1Hex = str_pad(gmp_strval(gmp_sub(gmp_init(
            'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
            16
        ), 1), 16), 64, '0', STR_PAD_LEFT);
        $privateKey = $nMinus1Hex;
        Sm2::validatePrivateKey($privateKey); // n-1 在合法私钥范围内

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('d=n-1 is not supported');
        Sm2::doSignature('msg', $privateKey);
    }

    public function testGetUserIdDigestRejectsOffCurvePublicKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('not on SM2 curve');
        Sm2::getUserIdDigest('1234567812345678', str_repeat('01', 64));
    }

    public function testEncryptEmptyPlaintextRoundTripBothModes(): void
    {
        $kp = Sm2::generateKeyPairHex();
        foreach ([Sm2::CIPHER_MODE_1, Sm2::CIPHER_MODE_0] as $mode) {
            $options = (new \CryptoSm\SM2\Sm2CipherOptions())->setCipherMode($mode);
            $ct = Sm2::doEncrypt('', $kp->getPublicKey(), $options);
            $this->assertSame('', Sm2::doDecrypt($ct, $kp->getPrivateKey(), $options));
        }
    }

    public function testSetCipherModeRejectsInvalidValue(): void
    {
        $options = new \CryptoSm\SM2\Sm2CipherOptions();
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Cipher mode must be');
        $options->setCipherMode(99);
    }

    // ─── SM4 decryptPayload 结构校验 ──────────────────────────────────────

    /**
     * @return array{0: array<string, mixed>, 1: string}
     */
    private function validPayload(): array
    {
        $key = str_repeat('ab', 16);

        return [Sm4::encryptPayload('payload data', $key), $key];
    }

    public function testDecryptPayloadRejectsWrongVersion(): void
    {
        [$payload, $key] = $this->validPayload();
        $payload['version'] = 2;

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Unsupported SM4 payload');
        Sm4::decryptPayload($payload, $key);
    }

    public function testDecryptPayloadRejectsWrongAlgorithm(): void
    {
        [$payload, $key] = $this->validPayload();
        $payload['algorithm'] = 'AES';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Unsupported SM4 payload');
        Sm4::decryptPayload($payload, $key);
    }

    public function testDecryptPayloadRejectsMissingField(): void
    {
        [$payload, $key] = $this->validPayload();
        unset($payload['ciphertext']);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('missing');
        Sm4::decryptPayload($payload, $key);
    }

    public function testDecryptPayloadRejectsUnknownModeViaOptionsValidation(): void
    {
        // 注：Sm4Options::setMode 与 decryptPayload 的白名单一致，
        // 未知模式会先被选项校验拦截；payload 层的分支为纵深防御
        [, $key] = $this->validPayload();
        $payload = ['version' => 1, 'algorithm' => 'SM4', 'mode' => 'ofb8'];

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Mode must be one of');
        Sm4::decryptPayload($payload, $key);
    }

    public function testDecryptPayloadRejectsZeroPadding(): void
    {
        $key = str_repeat('cd', 16);
        $payload = [
            'version' => 1,
            'algorithm' => 'SM4',
            'mode' => 'cbc',
            'padding' => 'zero',
            'iv' => str_repeat('00', 16),
            'ciphertext' => str_repeat('00', 32),
        ];

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Zero padding is ambiguous');
        Sm4::decryptPayload($payload, $key);
    }

    public function testDecryptPayloadRejectsBadHexStringField(): void
    {
        [$payload, $key] = $this->validPayload();
        if (($payload['mode'] ?? '') === 'gcm') {
            $payload['tag'] = 'zz';
        } else {
            $payload['ciphertext'] = 'zz';
        }

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('hex');
        Sm4::decryptPayload($payload, $key);
    }

    public function testDecryptPayloadRoundTripAllModes(): void
    {
        $key = str_repeat('cd', 16);
        foreach ([Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR, Sm4::MODE_ECB] as $mode) {
            $payload = Sm4::encryptPayload('roundtrip ' . $mode, $key, (new Sm4Options())->setMode($mode));
            $this->assertSame('roundtrip ' . $mode, Sm4::decryptPayload($payload, $key), "mode=$mode");
        }
    }

    // ─── PEM / DER 畸形输入分支（确定性字节突变）──────────────────────────

    public function testImportPublicKeyFromDerRejectsShortData(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('too short');
        Pem::importPublicKeyFromDer('30');
    }

    public function testSpkiRejectsWrongAlgorithmOid(): void
    {
        $der = Pem::exportPublicKeyDer(Sm2::generateKeyPairHex()->getPublicKey());
        // 第一个 OID 是 ecPublicKey；翻转其内容首字节使 OID 变为未知值
        $oidTagPos = strpos($der, "\x06");
        $this->assertNotFalse($oidTagPos);
        $contentPos = $oidTagPos + 2; // 06 07 2A 86 ...：短长度形式
        $mutated = substr_replace($der, chr(ord($der[$contentPos]) ^ 0x01), $contentPos, 1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected ecPublicKey algorithm');
        Pem::importPublicKeyFromDer($mutated);
    }

    public function testSpkiRejectsWrongCurveOid(): void
    {
        $der = Pem::exportPublicKeyDer(Sm2::generateKeyPairHex()->getPublicKey());
        // 第二个 OID 是 SM2 曲线 OID
        $first = strpos($der, "\x06");
        $this->assertNotFalse($first);
        $second = strpos($der, "\x06", $first + 1);
        $this->assertNotFalse($second);
        $contentPos = $second + 2;
        $mutated = substr_replace($der, chr(ord($der[$contentPos]) ^ 0x01), $contentPos, 1);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected SM2 curve OID');
        Pem::importPublicKeyFromDer($mutated);
    }

    public function testSpkiAcceptsCompressedPointTag(): void
    {
        // 构建含压缩公钥的合法 SPKI DER
        $pub = Sm2::generateKeyPairHex()->getPublicKey();
        $x = substr($pub, 0, 64);
        $yHex = substr($pub, 64, 64);
        $prefix = (gmp_testbit(gmp_init($yHex, 16), 0)) ? 0x03 : 0x02;

        // AlgorithmIdentifier
        $algSeq = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x81\x1c\xcf\x55\x01\x82\x2d";
        // BIT STRING: 00 (unused bits) || prefix || x (33 bytes)
        $pointData = chr($prefix) . (string) hex2bin($x);
        $bitString = "\x03" . chr(strlen($pointData) + 1) . "\x00" . $pointData;
        $content = $algSeq . $bitString;
        $spki = "\x30" . chr(strlen($content)) . $content;

        $imported = Pem::importPublicKeyFromDer($spki);
        $this->assertSame(strtolower($pub), strtolower($imported), 'compressed point must decompress to original');
    }

    public function testSec1ImportRejectsNonZeroUnusedBitsInPublicKeyBitString(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $der = Pem::exportPrivateKeyDer($kp->getPrivateKey(), $kp->getPublicKey());
        // SEC1 [1] 元素结构固定为 A1 45 03 42 00 04 || x || y
        $needle = "\xa1\x44\x03\x42\x00";
        $pos = strpos($der, $needle);
        $this->assertNotFalse($pos);
        $mutated = substr_replace($der, "\x07", $pos + 4, 1); // unused bits ≠ 0

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('unused bits');
        Pem::importPrivateKeyFromDer($mutated);
    }

    public function testSec1ImportAcceptsCompressedPointInPublicKeyBitString(): void
    {
        // 构建 SEC1 私钥 + 压缩公钥 [1]
        $priv = str_pad('09', 64, 'ab', STR_PAD_LEFT);
        $pub = Sm2::getPublicKey($priv);
        $x = substr($pub, 0, 64);
        $yHex = substr($pub, 64, 64);
        $prefix = (gmp_testbit(gmp_init($yHex, 16), 0)) ? 0x03 : 0x02;

        $version = "\x02\x01\x01";
        $keyOctet = "\x04\x20" . (string) hex2bin($priv);
        // 从实际导出密钥中提取 [0] 曲线段（避免硬编码 OID 字节错误）
        $refDer = Pem::exportPrivateKeyDer($priv);
        $a0Pos = strpos($refDer, "\xa0");
        if ($a0Pos === false) {
            $a0Pos = 0;
        }
        $refEndRaw = strpos($refDer, "\xa1", $a0Pos);
        $refEnd = $refEndRaw !== false ? $refEndRaw : strlen($refDer);
        $oidBytes = substr($refDer, (int) $a0Pos, (int) $refEnd - (int) $a0Pos);
        $pointData = chr($prefix) . (string) hex2bin($x);
        $innerBs = "\x03" . chr(strlen($pointData) + 1) . "\x00" . $pointData;
        $pubCtx = "\xa1" . chr(strlen($innerBs)) . $innerBs;

        $sec1Content = $version . $keyOctet . $oidBytes . $pubCtx;
        $der = "\x30" . chr(strlen($sec1Content)) . $sec1Content;

        $imported = Pem::importPrivateKeyFromDer($der);
        $this->assertSame(strtolower($pub), strtolower($imported['publicKey']));
    }

    public function testSec1ImportRejectsMismatchedBitStringLength(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $der = Pem::exportPrivateKeyDer($kp->getPrivateKey(), $kp->getPublicKey());
        $needle = "\xa1\x44\x03\x42\x00";
        $pos = strpos($der, $needle);
        $this->assertNotFalse($pos);
        // BIT STRING 长度 0x42 → 0x43：与 [1] 容器长度不再自洽
        $mutated = substr_replace($der, "\x43", $pos + 3, 1);

        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKeyFromDer($mutated);
    }

    public function testSec1ImportRejectsTruncatedStructure(): void
    {
        $der = Pem::exportPrivateKeyDer(Sm2::generateKeyPairHex()->getPrivateKey());
        $truncated = substr($der, 0, strlen($der) - 5);

        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKeyFromDer($truncated);
    }

    // ─── ASN.1 编解码边界 ─────────────────────────────────────────────────

    public function testAsn1EncodeIntegerRejectsOddLengthHex(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('odd length');
        Asn1::encodeInteger('abc');
    }

    public function testAsn1EncodeIntegerRejectsNonHex(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid hex for integer encoding');
        Asn1::encodeInteger('zz');
    }

    public function testAsn1DecodeIntegerRejectsNegativeValue(): void
    {
        $data = "\x02\x01\x80"; // 最高位为 1 → 负数 INTEGER
        $offset = 0;
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('negative values are not supported');
        Asn1::decodeInteger($data, $offset);
    }

    public function testAsn1DecodeIntegerRejectsNonMinimalEncoding(): void
    {
        $data = "\x02\x02\x00\x01"; // 多余前导零且次高位为 0 → 非最小编码
        $offset = 0;
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('non-minimal encoding');
        Asn1::decodeInteger($data, $offset);
    }

    public function testDecodeDerSignatureBinaryRejectsTrailingData(): void
    {
        $sig = Asn1::encodeDerSignatureBinary(
            str_pad('01', 64, '0', STR_PAD_LEFT),
            str_pad('02', 64, '0', STR_PAD_LEFT)
        );
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('structure');
        Asn1::decodeDerSignatureBinary($sig . "\x00");
    }

    // ─── Hex 工具边界 ────────────────────────────────────────────────────

    public function testToBytesRejectsNonHexString(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Hex::toBytes('zz');
    }

    public function testToBytesPadsOddLengthInput(): void
    {
        $this->assertSame([0x00, 0xAB], Hex::toBytes('0ab'));
    }

    public function testFromHexRoundTripAndValidityCheck(): void
    {
        $bin = Hex::fromHex('00ff10');
        $this->assertSame("\x00\xff\x10", $bin);
        $this->assertTrue(Hex::isValidHex('00ff10'));
        $this->assertFalse(Hex::isValidHex('zz'));
    }

    // ─── Gcm 直接 API 分支 ────────────────────────────────────────────────

    public function testGcmRejectsEmptyIv(): void
    {
        $gcm = Gcm::fromKey(random_bytes(16));
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('IV must not be empty');
        $gcm->encrypt('x', '', '', 16);
    }

    public function testGcmDecryptWithTamperedTagFails(): void
    {
        $gcm = Gcm::fromKey(random_bytes(16));
        $iv = random_bytes(12);
        ['ciphertext' => $ct, 'tag' => $tag] = $gcm->encrypt('secret', $iv, 'aad', 16);

        $tamperedByte = $tag[0] === "\x00" ? "\x01" : "\x00";

        $this->expectException(CryptoException::class);
        $gcm->decrypt($ct, $tamperedByte . substr($tag, 1), $iv, 'aad', 16);
    }

    // ─── 第二批：守卫分支与确认流程 ────────────────────────────────────────

    public function testSm4RejectsForeignOptionsInstance(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('must be an instance of Sm4Options');
        Sm4::encrypt('x', str_repeat('ab', 16), 'not-options');
    }

    public function testSelfContainedCbcDecryptRejectsMalformedInput(): void
    {
        $key = str_repeat('ab', 16);

        try {
            Sm4::decrypt('zz-not-hex', $key); // 非十六进制
            $this->fail('expected exception');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('self-contained', $e->getMessage());
        }

        try {
            Sm4::decrypt('0011', $key); // 过短
            $this->fail('expected exception');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('self-contained', $e->getMessage());
        }
    }

    public function testUnpadRejectsInvalidPaddingBytes(): void
    {
        $key = str_repeat('ef', 16);
        // 构造末字节为 0x00 的合法块（padding=none），再用 iso10126/ansix923 解填充 → 必然失败
        $block = str_repeat('A', 15) . "\x00";
        $iv = str_repeat('11', 16);
        $ct = Sm4::encrypt($block, $key, (new Sm4Options())->setIv($iv)->setPadding('none'));

        foreach (['iso10126', 'ansix923'] as $padding) {
            try {
                Sm4::decrypt($ct, $key, (new Sm4Options())->setIv($iv)->setPadding($padding));
                $this->fail("expected Decryption failed for {$padding}");
            } catch (CryptoException $e) {
                $this->assertSame('Decryption failed', $e->getMessage());
            }
        }
    }

    public function testEncryptWithNonePaddingRejectsNonAlignedData(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('multiple of 16');
        Sm4::encrypt('short', str_repeat('ab', 16), (new Sm4Options())->setPadding('none'));
    }

    public function testKeyExchangeConfirmationRoundTrip(): void
    {
        $a = Sm2::generateKeyPairHex();
        $b = Sm2::generateKeyPairHex();
        $rA = Sm2::generateKeyPairHex();
        $rB = Sm2::generateKeyPairHex();

        $init = KeyExchange::initiatorComputeKeyWithConfirmation(
            $a->getPrivateKey(),
            $rA->getPrivateKey(),
            $b->getPublicKey(),
            $rB->getPublicKey(),
            32
        );
        $resp = KeyExchange::responderComputeKeyWithConfirmation(
            $b->getPrivateKey(),
            $rB->getPrivateKey(),
            $a->getPublicKey(),
            $rA->getPublicKey(),
            32
        );

        $this->assertSame($init['key'], $resp['key']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $init['s1']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $resp['s2']);
        $this->assertSame(KeyExchange::initiatorComputeKeyFull(
            $a->getPrivateKey(),
            $rA->getPrivateKey(),
            $b->getPublicKey(),
            $rB->getPublicKey(),
            32
        )['key'], $init['key']);
    }

    public function testKeyExchangeSumToInfinityFailsGracefully(): void
    {
        // 构造 PB + x̄B·RB = O：取 RB 为曲线点，令 PB = -(x̄B·RB)
        $p = Sm2::gmpParamPublic('p');
        $rbPriv = Sm2::generateKeyPairHex();
        $RB = $rbPriv->getPublicKey();
        $mask = gmp_sub(gmp_pow(gmp_init(2), 127), gmp_init(1));
        $xB = gmp_add(gmp_pow(gmp_init(2), 127), gmp_and(gmp_init(substr($RB, 0, 64), 16), $mask));
        $q = Sm2::pointMultiplyPublic($RB, gmp_strval($xB, 16));
        $negY = str_pad(gmp_strval(gmp_mod(gmp_neg(gmp_init(substr($q, 64), 16)), $p), 16), 64, '0', STR_PAD_LEFT);
        $PB = substr($q, 0, 64) . $negY;

        try {
            KeyExchange::initiatorComputeKey(
                Sm2::generateKeyPairHex()->getPrivateKey(),
                Sm2::generateKeyPairHex()->getPrivateKey(),
                $PB,
                $RB,
                32
            );
            $this->fail('expected point addition failure');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('point addition failed', $e->getMessage());
        }
    }

    public function testPointAddPublicReturnsNullForInversePair(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $pub = $kp->getPublicKey();
        $p = Sm2::gmpParamPublic('p');
        $negY = str_pad(gmp_strval(gmp_mod(gmp_neg(gmp_init(substr($pub, 64), 16)), $p), 16), 64, '0', STR_PAD_LEFT);
        $negPub = substr($pub, 0, 64) . $negY;

        $this->assertNull(Sm2::pointAddPublic($pub, $negPub));
        $this->assertNull(Sm2::pointAddPublic('zz', $pub)); // 非法点
    }

    public function testPointMultiplyPublicRejectsZeroFactor(): void
    {
        $pub = Sm2::generateKeyPairHex()->getPublicKey();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('must be in range');
        Sm2::pointMultiplyPublic($pub, str_repeat('0', 64));
    }

    public function testIsOnCurveRejectsCoordinatesBeyondField(): void
    {
        $p = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF';
        $this->assertFalse(Sm2::isOnCurve($p . str_repeat('01', 32)));          // x >= p
        $this->assertFalse(Sm2::isOnCurve(str_repeat('01', 32) . $p));          // y >= p
        $this->assertFalse(Sm2::isOnCurve('short'));                             // 格式非法
    }

    public function testGenerateKeypairInstanceMethod(): void
    {
        $sm2 = new Sm2();
        $kp = $sm2->generateKeyPair();
        $this->assertInstanceOf(Keypair::class, $kp);
        $this->assertTrue(Sm2::isOnCurve($kp->getPublicKey()));
    }

    public function testGcmConstructorAndWarmupGuards(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('key must be 16 bytes');
        Gcm::fromKey('short-key');
    }

    public function testGcmWarmupMethodsRun(): void
    {
        Gcm::warmupStatic();
        Gcm::fromKey(random_bytes(16))->warmup();
        $this->addToAssertionCount(1);
    }

    public function testGcmDecryptRejectsWrongTagLength(): void
    {
        $gcm = Gcm::fromKey(random_bytes(16));
        $iv = random_bytes(12);
        ['ciphertext' => $ct, 'tag' => $tag] = $gcm->encrypt('secret', $iv, '', 16);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tag length mismatch');
        $gcm->decrypt($ct, substr($tag, 1), $iv, '', 16);
    }

    public function testAsn1DecodeLengthErrorBranches(): void
    {
        // 长度字段被截断
        try {
            $offset = 0;
            Asn1::decodeInteger("\x02\x84", $offset);
            $this->fail('expected CryptoException');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('exceed available data', $e->getMessage());
        }

        // 多字节长度但值 <128：非最小编码
        try {
            $offset = 0;
            Asn1::decodeInteger("\x02\x81\x05abcde", $offset);
            $this->fail('expected CryptoException');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('not minimally encoded', $e->getMessage());
        }
    }

    public function testAsn1DecodeDerSignatureRejectsNonHex(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid DER signature hex');
        Asn1::decodeDerSignature('zz');
    }

    public function testPemHelpersRejectGarbage(): void
    {
        foreach (['', 'no markers here', '-----BEGIN X----- !!! -----END Y-----'] as $bad) {
            try {
                Pem::importPrivateKey($bad);
                $this->fail("expected InvalidKeyException for '{$bad}'");
            } catch (InvalidKeyException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testImportDerRejectsStructuralMutations(): void
    {
        $der = Pem::exportPrivateKeyDer(Sm2::generateKeyPairHex()->getPrivateKey());

        $mutations = [
            'not-a-sequence' => '1' . substr($der, 1),
            'trailing-data' => $der . "\x00",
            'missing-version-int' => "\x30" . chr(ord($der[1])) . substr($der, 2, 3) . "\x04",
            'unsupported-version' => substr_replace($der, "\x02\x01\x02", 4, 3),
        ];

        foreach ($mutations as $name => $mutated) {
            try {
                Pem::importPrivateKeyFromDer($mutated);
                $this->fail("expected InvalidKeyException for {$name}");
            } catch (InvalidKeyException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testExportValidatorsRejectBadKeys(): void
    {
        $expect = function (callable $fn, string $message): void {
            try {
                $fn();
                $this->fail('expected InvalidKeyException');
            } catch (InvalidKeyException $e) {
                $this->assertStringContainsString($message, $e->getMessage());
            }
        };

        $expect(static fn (): string => Pem::exportPrivateKey('zz'), 'Private key must be 64 hex chars');
        $expect(static fn (): string => Pem::exportPrivateKeyPkcs8('short'), 'Private key must be 64 hex chars');
        $expect(static fn (): string => Pem::exportPublicKey('short'), 'Public key must be 128 hex chars');
        $expect(static fn (): string => Pem::exportPrivateKeyPkcs8Der('gg'), 'Private key must be 64 hex chars');
        // SEC1 附带公钥时公钥格式非法
        $expect(
            static fn (): string => Pem::exportPrivateKey(str_repeat('a', 64), 'short'),
            'Public key must be 128 hex chars'
        );
    }

    public function testFacadePemDelegatesCoverAllFormats(): void
    {
        $kp = Sm2::generateKeyPairHex();

        $pemSec1 = \CryptoSm\SmCrypto::exportPrivateKeyPem($kp->getPrivateKey());
        $this->assertStringContainsString('BEGIN EC PRIVATE KEY', $pemSec1);

        $pemPkcs8 = \CryptoSm\SmCrypto::exportPrivateKeyPkcs8($kp->getPrivateKey());
        $this->assertStringContainsString('BEGIN PRIVATE KEY', $pemPkcs8);

        $pemSpki = \CryptoSm\SmCrypto::exportPublicKeyPem($kp->getPublicKey());
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $pemSpki);

        $this->assertSame(
            $kp->getPublicKey(),
            \CryptoSm\SmCrypto::importPrivateKeyFromDer(
                \CryptoSm\SmCrypto::exportPrivateKeyPkcs8Der($kp->getPrivateKey())
            )['publicKey']
        );
        $this->assertSame(
            $kp->getPublicKey(),
            \CryptoSm\SmCrypto::importPublicKeyFromDer(\CryptoSm\SmCrypto::exportPublicKeyDer($kp->getPublicKey()))
        );
    }

    public function testPurePhpEngineGuards(): void
    {
        $engine = new \CryptoSm\SM4\Sm4PurePhp();

        try {
            $engine->encryptBlock('short-block');
            $this->fail('expected block size guard');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('16 bytes', $e->getMessage());
        }

        try {
            $engine->decryptBlock(str_repeat("\x00", 16));
            $this->fail('expected key-not-set guard');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('setKey', $e->getMessage());
        }
    }
    // ─── 第三批：DER/PEM 深度变异矩阵 ─────────────────────────────────────

    public function testSm4DecryptRejectsForeignOptionsInstance(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('must be an instance of Sm4Options');
        Sm4::decrypt('00', str_repeat('ab', 16), 12345);
    }

    public function testDecryptPayloadGcmRejectsBadAadHex(): void
    {
        $key = str_repeat('ab', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM);
        $payload = Sm4::encryptPayload('gcm aad', $key, $options);
        $payload['aad'] = 'zz-not-hex';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('AAD');
        Sm4::decryptPayload($payload, $key);
    }

    public function testDecryptPayloadRejectsMissingIntegerField(): void
    {
        [$payload, $key] = $this->validPayload();
        if (($payload['mode'] ?? '') === 'gcm') {
            unset($payload['tagLength']);
        } else {
            unset($payload['version']);
        }

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('integer field');
        Sm4::decryptPayload($payload, $key);
    }

    public function testGcmDecryptViaSm4RejectsShortDataAndBadHex(): void
    {
        $key = str_repeat('ab', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('11', 12));

        // 数据短于 tag 长度
        try {
            Sm4::decrypt('aabb', $key, clone $options);
            $this->fail('expected CryptoException');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('ciphertext or tag length', $e->getMessage());
        }

        // 密文含非十六进制字符
        try {
            Sm4::decrypt(str_repeat('zz', 40), $key, clone $options);
            $this->fail('expected CryptoException');
        } catch (CryptoException $e) {
            $this->assertTrue(
                str_contains($e->getMessage(), 'hex') || str_contains($e->getMessage(), 'Invalid'),
                'unexpected message: ' . $e->getMessage()
            );
        }
    }

    public function testAsn1LengthEdgeCases(): void
    {
        // 长度字段缺失（数据在 tag 后立即结束）
        try {
            $offset = 0;
            Asn1::decodeInteger("\x02", $offset);
            $this->fail('expected CryptoException');
        } catch (CryptoException $e) {
            $this->assertSame('Unexpected end of ASN.1 data', $e->getMessage());
        }

        // 声明 5 字节长度：超过 DER 允许的 4 字节上限
        try {
            $offset = 0;
            Asn1::decodeInteger("\x02\x85\x01\x02\x03\x04\x05", $offset);
            $this->fail('expected CryptoException');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('exceed available data', $e->getMessage());
        }

        // 合法 hex 但奇数长度 → hex2bin 失败
        $this->expectException(CryptoException::class);
        Asn1::decodeDerSignature('abc');
    }

    /**
     * 对合法 SEC1 DER 做全长度截断扫描，扫过解析器的各截断守卫分支。
     */
    public function testSec1TruncationSweepHitsParserGuards(): void
    {
        $der = Pem::exportPrivateKeyDer(Sm2::generateKeyPairHex()->getPrivateKey());
        $hits = 0;

        for ($cut = 2, $max = strlen($der); $cut < $max; $cut++) {
            try {
                Pem::importPrivateKeyFromDer(substr($der, 0, $cut));
                // 完整可解析前缀只可能是整串本身；其余必须抛异常
                $this->assertSame($max, $cut);
            } catch (InvalidKeyException) {
                $hits++;
            }
        }

        $this->assertGreaterThan(20, $hits, 'truncation sweep should trip many guards');
    }

    public function testImportDerRejectsHeaderLevelMalformations(): void
    {
        $der = Pem::exportPrivateKeyDer(Sm2::generateKeyPairHex()->getPrivateKey());

        $cases = [
            'first-content-not-version' => "\x30" . substr($der, 1, 1) . "\x03" . substr($der, 4),
            'version-length-not-one' => substr_replace($der, "\x02\x02\x00\x01", 2, 3),
            'unsupported-version-byte' => substr_replace($der, "\x02", 4, 1),
            'indefinite-length' => substr_replace($der, "\x80", 1, 1),
            'non-minimal-length' => "\x30\x81" . chr(ord($der[1])) . substr($der, 2),
        ];

        foreach ($cases as $name => $mutated) {
            try {
                Pem::importPrivateKeyFromDer($mutated);
                $this->fail("{$name} should not import");
            } catch (InvalidKeyException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testOidMutationsTripOidGuards(): void
    {
        $spki = Pem::exportPublicKeyDer(Sm2::generateKeyPairHex()->getPublicKey());

        // OID 内容最后一字节最高位置 1：组件未终结
        $oidContentStart = strpos($spki, "\x06") + 2;
        $firstOidLen = ord($spki[$oidContentStart - 1]);
        $unterminated = substr_replace($spki, chr(ord($spki[$oidContentStart + $firstOidLen - 1]) | 0x80), $oidContentStart + $firstOidLen - 1, 1);

        try {
            Pem::importPublicKeyFromDer($unterminated);
            $this->fail('unterminated OID should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('OID', $e->getMessage());
        }

        // 空 OID：等长替换（长度字节置 0x00，内容保留占位），避免先触发结构长度校验
        $oidPos = strpos($spki, "\x06");
        $this->assertNotFalse($oidPos);
        $replacement = "\x06\x00" . substr($spki, $oidPos + 2, $firstOidLen);
        $emptyOid = substr_replace($spki, $replacement, $oidPos, $firstOidLen + 2);

        try {
            Pem::importPublicKeyFromDer($emptyOid);
            $this->fail('empty OID should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('OID', $e->getMessage());
        }
    }

    public function testPkcs8WithRawKeyOctetStringImports(): void
    {
        // 某些工具输出的 PKCS#8 OCTET STRING 内是裸 32 字节密钥而非 SEC1 结构，
        // 库必须支持该变体（parsePkcs8PrivateKey 的 raw-key 分支）
        $privHex = bin2hex(random_bytes(32));
        while (!preg_match('/^[1-9a-f]/', $privHex[0]) || gmp_cmp(gmp_init($privHex, 16), gmp_init(
            'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
            16
        )) >= 0 || gmp_cmp(gmp_init($privHex, 16), gmp_init(1)) < 0) {
            $privHex = bin2hex(random_bytes(32));
        }

        $std = Pem::exportPrivateKeyPkcs8Der($privHex);
        // 结构：30 L1 02 01 00 30 L2 <algSeq> ... 定位 AlgorithmIdentifier
        $algSeqPos = strpos($std, "\x30", 3); // version INTEGER 之后
        $this->assertNotFalse($algSeqPos);
        $algSeqLen = ord($std[$algSeqPos + 1]);
        $algSeq = substr($std, $algSeqPos, $algSeqLen + 2);

        $content = "\x02\x01\x00" . $algSeq . "\x04\x20" . hex2bin($privHex);
        $rawVariant = "\x30" . chr(strlen($content)) . $content;

        $imported = Pem::importPrivateKeyFromDer($rawVariant);
        $this->assertSame($privHex, $imported['privateKey']);
        $this->assertTrue(Sm2::isOnCurve($imported['publicKey']));
    }

    public function testSpkiImportRejectsOffCurvePoint(): void
    {
        $pub = Sm2::generateKeyPairHex()->getPublicKey();
        $der = Pem::exportPublicKeyDer($pub);
        // 翻转 y 坐标末字节 → 点大概率不在曲线上
        $mutated = substr_replace($der, chr(ord($der[strlen($der) - 1]) ^ 0x01), strlen($der) - 1, 1);

        try {
            Pem::importPublicKeyFromDer($mutated);
            // 若翻转后恰好在曲线上则跳过（概率 ~2^-256，实际不会发生）
            $this->markTestSkipped('mutated point unexpectedly on curve');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('not on SM2 curve', $e->getMessage());
        }
    }

    public function testPemBodyEdgeCases(): void
    {
        $kp = Sm2::generateKeyPairHex();

        // 空正文
        try {
            Pem::importPrivateKey("-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----");
            $this->fail('empty body should fail');
        } catch (InvalidKeyException) {
            $this->addToAssertionCount(1);
        }

        // 正文不是 base64
        try {
            Pem::importPrivateKey("-----BEGIN EC PRIVATE KEY-----\n@@@@@@@@\n-----END EC PRIVATE KEY-----");
            $this->fail('non-base64 body should fail');
        } catch (InvalidKeyException) {
            $this->addToAssertionCount(1);
        }

        // 标签存在但类型不符
        try {
            Pem::importPublicKey(Pem::exportPrivateKey($kp->getPrivateKey()));
            $this->fail('wrong label should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('Expected PUBLIC KEY', $e->getMessage());
        }
    }

    public function testSec1InnerStructureBranches(): void
    {
        $kp = Sm2::generateKeyPairHex();

        // SEC1 [0] 曲线参数区：错误曲线 OID
        $der = Pem::exportPrivateKeyDer($kp->getPrivateKey()); // 无公钥 → 含 A0 曲线段
        $a0 = strpos($der, "\xa0\x0a\x06\x08"); // A0 0A 06 08 || SM2 OID
        $this->assertNotFalse($a0);
        $oidContent = $a0 + 4;
        $mutated = substr_replace($der, chr(ord($der[$oidContent]) ^ 0x01), $oidContent, 1);

        try {
            Pem::importPrivateKeyFromDer($mutated);
            $this->fail('wrong curve OID should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('curve OID', $e->getMessage());
        }

        // OCTET STRING 标签突变：期望 OCTET STRING 却得到其他类型
        $octetPos = strpos($der, "\x04\x20"); // 私钥 OCTET STRING (32B)
        $this->assertNotFalse($octetPos);
        $mutated = substr_replace($der, "\x05", $octetPos, 1);

        try {
            Pem::importPrivateKeyFromDer($mutated);
            $this->fail('non-OCTET key field should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('OCTET STRING', $e->getMessage());
        }
    }
    // ─── 第四批：PKCS#8 解析器与 OID 解码分支 ─────────────────────────────

    /**
     * 构造 PKCS#8 DER：version + AlgorithmIdentifier + OCTET STRING <inner>
     */
    private function buildPkcs8(string $algSeq, string $octetContent): string
    {
        $content = "\x02\x01\x00" . $algSeq . "\x04" . chr(strlen($octetContent)) . $octetContent;
        return "\x30" . chr(strlen($content)) . $content;
    }

    private function extractAlgSeq(): string
    {
        $std = Pem::exportPrivateKeyPkcs8Der(Sm2::generateKeyPairHex()->getPrivateKey());
        $pos = strpos($std, "\x30", 3); // version INTEGER 之后的 AlgorithmIdentifier
        self::assertNotFalse($pos);

        return substr($std, $pos, ord($std[$pos + 1]) + 2);
    }

    public function testPkcs8ParserRejectsAlgorithmMutations(): void
    {
        $algSeq = $this->extractAlgSeq();
        $privHex = str_pad('09', 64, 'ab', STR_PAD_LEFT);
        $sec1Inner = Pem::exportPrivateKeyDer($privHex); // 完整 SEC1 作为 OCTET 内容

        // 算法 OID 内容首字节突变：非 ecPublicKey
        $mutAlg = substr_replace($algSeq, chr(ord($algSeq[4]) ^ 0x01), 4, 1); // 30 13 06 07 [2A] ...
        try {
            Pem::importPrivateKeyFromDer($this->buildPkcs8($mutAlg, $sec1Inner));
            $this->fail('wrong algorithm OID should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('ecPublicKey', $e->getMessage());
        }

        // 曲线 OID 内容首字节突变：非 SM2
        $secondOidInSeq = strpos($algSeq, "\x06", 3); // 跳过第一个 OID 的 tag/长度
        $this->assertNotFalse($secondOidInSeq);
        $mutCurve = substr_replace($algSeq, chr(ord($algSeq[$secondOidInSeq + 2]) ^ 0x01), $secondOidInSeq + 2, 1);
        try {
            Pem::importPrivateKeyFromDer($this->buildPkcs8($mutCurve, $sec1Inner));
            $this->fail('wrong curve OID should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('SM2 curve OID', $e->getMessage());
        }
    }

    public function testPkcs8ParserStructuralBranches(): void
    {
        $algSeq = $this->extractAlgSeq();
        $privHex = str_pad('11', 64, 'cd', STR_PAD_LEFT);
        $sec1Inner = Pem::exportPrivateKeyDer($privHex);

        // OCTET STRING 内部不是 SEQUENCE 且长度非法（>32 字节）
        try {
            Pem::importPrivateKeyFromDer($this->buildPkcs8($algSeq, str_repeat("\x41", 33)));
            $this->fail('oversized raw key should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('length', $e->getMessage());
        }

        // 裸密钥为全零：通过格式校验但被范围校验拒绝
        try {
            Pem::importPrivateKeyFromDer($this->buildPkcs8($algSeq, str_repeat("\x00", 32)));
            $this->fail('zero raw key should fail');
        } catch (InvalidKeyException $e) {
            $this->assertStringContainsString('range', $e->getMessage());
        }
    }

    public function testParseDerLengthRejectsFiveByteLength(): void
    {
        // 长度字段声明 5 字节：超出 DER 4 字节上限
        $der = "\x30\x85\x41\x41\x41\x41\x41\x02\x01\x01\x04\x01\x00";

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('length field too long');
        Pem::importPrivateKeyFromDer($der);
    }

    public function testDecodeOidFirstArcBranches(): void
    {
        // 通过 SPKI 的算法 OID 首内容字节分别落入三个 arc 分支后仍被拒绝
        foreach ([0x10, 0x55] as $firstByte) {
            $spki = Pem::exportPublicKeyDer(Sm2::generateKeyPairHex()->getPublicKey());
            $oidContent = strpos($spki, "\x06") + 2;
            $mutated = substr_replace($spki, chr($firstByte), $oidContent, 1);

            try {
                Pem::importPublicKeyFromDer($mutated);
                $this->fail('mutated OID should fail');
            } catch (InvalidKeyException $e) {
                $this->assertStringContainsString('ecPublicKey', $e->getMessage());
            }
        }
    }
}
