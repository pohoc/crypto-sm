<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Exception\SmCryptoException;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use CryptoSm\Utils\Hex;
use PHPUnit\Framework\TestCase;

/**
 * 解析器模糊测试（种子化，可复现）
 *
 * 核心不变量：
 * 1. ASN.1/PEM 解析器面对任意输入只允许抛出 SmCryptoException 及其子类；
 *    任何 \Error、\ValueError、\TypeError 或 PHP 警告逃逸都视为缺陷
 *    （PHPUnit failOnWarning 会将 E_WARNING/E_NOTICE 转为失败）
 * 2. 合法签名的 DER 编解码必须是精确的往返恒等
 * 3. 对合法 DER 的随机单字节突变只能产生：域异常、或（未命中语义时）正常导入
 */
class FuzzTest extends TestCase
{
    /** 固定种子保证可复现；如需扩展用例请更换种子而非移除断言 */
    private const SEED = 20260826;

    private const DECODE_ITERATIONS = 3000;

    private const MUTATION_ITERATIONS = 800;

    private static function randHex(int $minLen, int $maxLen): string
    {
        $len = mt_rand($minLen, $maxLen);
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= dechex(mt_rand(0, 15));
        }
        return $out;
    }

    private static function randBytes(int $minLen, int $maxLen): string
    {
        $len = mt_rand($minLen, $maxLen);
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(mt_rand(0, 255));
        }
        return $out;
    }

    // ─── 不变量 1：任意输入不逃逸非领域异常 ───────────────────────────────

    public function testDerSignatureHexDecoderSurvivesGarbage(): void
    {
        mt_srand(self::SEED);
        for ($i = 0; $i < self::DECODE_ITERATIONS; $i++) {
            $shape = mt_rand(0, 3);
            $input = match ($shape) {
                0 => self::randHex(0, 400),
                1 => '30' . self::randHex(0, 60),          // 像样的 SEQUENCE 开头
                2 => bin2hex(self::randBytes(1, 120)),      // 二进制噪声
                default => str_repeat('ff', mt_rand(1, 80)),
            };

            try {
                Asn1::decodeDerSignature($input);
            } catch (SmCryptoException) {
                // 预期路径：结构非法被域异常拒绝
            }
        }
        $this->addToAssertionCount(self::DECODE_ITERATIONS);
    }

    public function testDerSignatureBinaryDecoderSurvivesGarbage(): void
    {
        mt_srand(self::SEED + 1);
        for ($i = 0; $i < self::DECODE_ITERATIONS; $i++) {
            try {
                Asn1::decodeDerSignatureBinary(self::randBytes(0, 200));
            } catch (SmCryptoException) {
            }
        }
        $this->addToAssertionCount(self::DECODE_ITERATIONS);
    }

    public function testPemImportersSurviveArbitraryText(): void
    {
        mt_srand(self::SEED + 2);
        $labels = ['EC PRIVATE KEY', 'PRIVATE KEY', 'PUBLIC KEY', '', "X\nY"];

        for ($i = 0; $i < self::MUTATION_ITERATIONS; $i++) {
            $label = $labels[mt_rand(0, count($labels) - 1)];
            $body = self::randBytes(0, 90);

            if (mt_rand(0, 2) === 0) {
                // 混入合法 base64 字符提高结构命中率
                $body .= substr(base64_encode(self::randBytes(20, 60)), 0, mt_rand(1, 40));
            }

            $pem = "-----BEGIN {$label}-----\n"
                . chunkedBase64Noise(bin2hex($body))
                . "\n-----END {$label}-----";

            foreach ([static fn (): array => Pem::importPrivateKey($pem),
                static fn (): string => Pem::importPublicKey($pem)] as $fn) {
                try {
                    $fn();
                } catch (SmCryptoException) {
                }
            }
        }
        $this->addToAssertionCount(self::MUTATION_ITERATIONS * 2);
    }

    public function testDerImportersSurviveBitFlipsOfValidStructures(): void
    {
        mt_srand(self::SEED + 3);
        $kp = Sm2::generateKeyPairHex();

        $validPrivate = Pem::exportPrivateKeyDer($kp->getPrivateKey(), $kp->getPublicKey());
        $validPublic = Pem::exportPublicKeyDer($kp->getPublicKey());

        foreach ([$validPrivate, $validPublic] as $base) {
            for ($i = 0; $i < self::MUTATION_ITERATIONS; $i++) {
                $mutated = $base;
                $flips = mt_rand(1, 4);
                for ($f = 0; $f < $flips; $f++) {
                    $pos = mt_rand(0, strlen($mutated) - 1);
                    $mutated[$pos] = chr(ord($mutated[$pos]) ^ (1 << mt_rand(0, 7)));
                }

                $isPublic = $base === $validPublic;

                try {
                    if ($isPublic) {
                        Pem::importPublicKeyFromDer($mutated);
                    } else {
                        Pem::importPrivateKeyFromDer($mutated);
                    }
                    // 未命中语义字段时成功导入也是合法结果
                } catch (SmCryptoException) {
                    // 预期路径
                }
            }
        }
        $this->addToAssertionCount(self::MUTATION_ITERATIONS * 2);
    }

    // ─── 不变量 2：合法签名编解码往返恒等 ────────────────────────────────

    public function testSignatureDerRoundTripIdentityForRandomComponents(): void
    {
        mt_srand(self::SEED + 4);
        $n = gmp_init('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122', 16);

        for ($i = 0; $i < 500; $i++) {
            // r、s ∈ [1, n-1]
            $rHex = str_pad(gmp_strval(gmp_random_range(gmp_init(1), $n - 1), 16), 64, '0', STR_PAD_LEFT);
            $sHex = str_pad(gmp_strval(gmp_random_range(gmp_init(1), $n - 1), 16), 64, '0', STR_PAD_LEFT);

            $der = Asn1::encodeDerSignature($rHex, $sHex);
            [$backR, $backS] = Asn1::decodeDerSignature($der);

            self::assertSame(strtolower($rHex), strtolower($backR), "roundtrip r failed at #{$i}");
            self::assertSame(strtolower($sHex), strtolower($backS), "roundtrip s failed at #{$i}");
        }
    }

    // ─── 不变量 3：Hex 工具往返 ──────────────────────────────────────────

    public function testHexRoundTripForRandomBytes(): void
    {
        mt_srand(self::SEED + 5);
        for ($i = 0; $i < 1000; $i++) {
            $bin = self::randBytes(0, 128);
            self::assertSame($bin, Hex::fromHex(Hex::toHexString($bin)));
        }
    }
}

/**
 * 将十六进制噪声伪装成 PEM 常见的 64 列换行格式。
 */
function chunkedBase64Noise(string $hex): string
{
    $rawLines = max(1, (int) ceil(strlen($hex) / 64));
    $lines = [];
    for ($i = 0; $i < $rawLines; $i++) {
        $lines[] = substr($hex, $i * 64, 64);
    }
    return implode("\n", $lines);
}
