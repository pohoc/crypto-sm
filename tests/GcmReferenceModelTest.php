<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Gcm;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use PHPUnit\Framework\TestCase;

/**
 * GCM 差分验证测试：对照 NIST SP 800-38D 规范直译的独立参考模型。
 *
 * 背景：变异测试发现 GHASH 归约相关常量被篡改后既有测试全部通过——
 * GCM 此前只有自洽性检查。本文件提供两条独立正确性锚点：
 *
 * 1. RFC 8998 Appendix A.1 的 SM4-GCM 官方向量（外部权威）
 * 2. 规范直译的 GMP 整数版 GHASH/J0/CTR 参考模型（与库实现完全独立，
 *    已先用 AES-GCM + NIST 向量验证过模型本身的正确性）
 *
 * 库曾在差分验证中暴露真实缺陷：GHASH 的"字节位反射域"优化与归约多项式
 * 域不匹配，导致标签不符合 RFC 8998（密文正确）。修复后本文件全部通过。
 */
class GcmReferenceModelTest extends TestCase
{
    // ─── RFC 8998 A.1 官方向量 ────────────────────────────────────────────

    public function testRfc8998Sm4GcmVector(): void
    {
        $key = self::hexBytes('0123456789ABCDEFFEDCBA9876543210');
        $iv  = self::hexBytes('00001234567800000000ABCD');
        // 明文 8 块 ×8 字节：A B C D E F E A
        $pt  = self::hexBytes('AAAAAAAAAAAAAAAA'.'BBBBBBBBBBBBBBBB'
            . 'CCCCCCCCCCCCCCCC'.'DDDDDDDDDDDDDDDD'
            . 'EEEEEEEEEEEEEEEE'.'FFFFFFFFFFFFFFFF'
            . 'EEEEEEEEEEEEEEEE'.'AAAAAAAAAAAAAAAA');
        $aad = self::hexBytes('FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2');

        $r = Gcm::fromKey($key)->encrypt($pt, $iv, $aad, 16);

        $this->assertSame(
            strtolower('17F399F08C67D5EE19D0DC9969C4BB7D'
                . '5FD46FD3756489069157B282BB200735'
                . 'D82710CA5C22F0CCFA7CBF93D496AC15'
                . 'A56834CBCF98C397B4024A2691233B8D'),
            bin2hex($r['ciphertext']),
            'RFC 8998 A.1 ciphertext mismatch'
        );
        $this->assertSame(
            strtolower('83DE3541E4C2B58177E065A9BF7B62EC'),
            bin2hex($r['tag']),
            'RFC 8998 A.1 authentication tag mismatch'
        );

        // 解密往返
        $ptBack = Gcm::fromKey($key)->decrypt(
            $r['ciphertext'],
            $r['tag'],
            $iv,
            $aad,
            16
        );
        $this->assertSame(bin2hex($pt), bin2hex((string) $ptBack));
    }

    // ─── 独立参考模型（GMP 整数、规范直译）───────────────────────────────

    /** GF(2^128) 乘法，MSB-first，R = 0xE1 || 0^120 */
    private static function gmul(\GMP $x, \GMP $y): \GMP
    {
        $rPoly = gmp_init(0xE1) << 120;
        $mask  = (gmp_init(1) << 128) - 1;
        $z = gmp_init(0);
        $v = $y;
        for ($i = 127; $i >= 0; $i--) {
            if (gmp_testbit($x, $i)) {
                $z ^= $v;
            }
            $lsb = gmp_testbit($v, 0);
            $v >>= 1;
            if ($lsb) {
                $v ^= $rPoly;
            }
        }
        return $z & $mask;
    }

    private static function ecbBlock(string $keyBin, string $block): string
    {
        $opts = new Sm4Options();
        $opts->setMode(Sm4::MODE_ECB)->setPadding('none');
        $hex = Sm4::encrypt($block, bin2hex($keyBin), $opts);
        $bin = hex2bin($hex);
        self::assertIsString($bin);

        return $bin;
    }

    private static function padToBlock(string $data): string
    {
        $rem = strlen($data) % 16;

        return $rem === 0 ? $data : $data . str_repeat("\0", 16 - $rem);
    }

    /**
     * 参考模型加密：返回二进制 ['ciphertext', 'tag']。
     *
     * @return array{ciphertext: string, tag: string}
     */
    private static function referenceEncrypt(
        string $keyBin,
        string $iv,
        string $aad,
        string $plaintext,
        int $tagLength
    ): array {
        self::assertSame(16, strlen($keyBin));

        $toInt = static fn (string $b): \GMP => gmp_import($b);

        // H = E(K, 0^128)
        $hInt = $toInt(self::ecbBlock($keyBin, str_repeat("\0", 16)));

        // J0：96 位 IV 直接拼接；其余走 GHASH 公式（逐 16 字节块迭代）
        if (strlen($iv) === 12) {
            $j0 = $iv . "\0\0\0\x01";
        } else {
            $ghashIn = self::padToBlock($iv) . pack('J', strlen($iv) * 8);
            $y = gmp_init(0);
            for ($i = 0, $len = strlen($ghashIn); $i < $len; $i += 16) {
                $y = self::gmul($y ^ $toInt(substr($ghashIn, $i, 16)), $hInt);
            }
            $j0 = self::intToBytes($y);
        }

        // CTR：从 inc32(J0) 起，仅低 32 位大端递增
        $ciphertext = '';
        $unpackedCounter = unpack('N', substr($j0, 12, 4));
        self::assertIsArray($unpackedCounter);
        $counterLo = $unpackedCounter[1];
        for ($offset = 0, $n = 1; $offset < strlen($plaintext); $offset += 16, $n++) {
            $counter = substr($j0, 0, 12) . pack('N', ($counterLo + $n) & 0xFFFFFFFF);
            $ks = self::ecbBlock($keyBin, $counter);
            $chunk = substr($plaintext, $offset, 16);
            $ciphertext .= $chunk ^ substr($ks, 0, strlen($chunk));
        }

        // S = GHASH(pad(A) || pad(C) || [lenA]64 || [lenC]64)，位长；
        // 逐 16 字节块迭代（规范要求，不可整段导入）
        $ghashInput = self::padToBlock($aad) . self::padToBlock($ciphertext)
            . pack('J', strlen($aad) * 8) . pack('J', strlen($ciphertext) * 8);
        $y = gmp_init(0);
        for ($i = 0, $len = strlen($ghashInput); $i < $len; $i += 16) {
            $y = self::gmul($y ^ $toInt(substr($ghashInput, $i, 16)), $hInt);
        }
        $sBin = self::intToBytes($y);

        $fullTag = self::ecbBlock($keyBin, $j0) ^ $sBin;

        return ['ciphertext' => $ciphertext, 'tag' => substr($fullTag, 0, $tagLength)];
    }

    private static function intToBytes(\GMP $value): string
    {
        return (string) hex2bin(str_pad(gmp_strval($value, 16), 32, '0', STR_PAD_LEFT));
    }

    // ─── 差分比对 ────────────────────────────────────────────────────────

    /**
     * @return list<array{string,string,string,string,int}> [keyBin, iv, aad, plaintext, tagLength]
     */
    private static function fixedCases(): array
    {
        return [
            // 最小输入：空明文
            [self::hexBytes('0123456789abcdeffedcba9876543210'), str_repeat("\x33", 12), '', '', 16],
            // 单块明文 + AAD
            [self::hexBytes('0123456789abcdeffedcba9876543210'), str_repeat("\x33", 12), 'aad', str_repeat('A', 16), 16],
            // 多块非对齐明文（覆盖 CTR 尾块截断）
            [self::hexBytes('fedcba98765432100123456789abcdef'), str_repeat("\x00", 12), 'associated data', str_repeat('SM4-GCM ', 5), 16],
            // 非 96 位 IV：16 字节（J0 走 GHASH 分支）
            [self::hexBytes('0f0e0d0c0b0a09080706050403020100'), str_repeat("\x11", 16), '', 'non-standard iv length', 16],
            // 非 96 位 IV：8 字节 + 12 字节标签
            [self::hexBytes('ffeeddccbbaa99887766554433221100'), str_repeat("\xab", 8), 'x', 'eight byte iv', 12],
            // 短标签 4 字节
            [self::hexBytes('00112233445566778899aabbccddeeff'), str_repeat("\x77", 12), 'auth only', str_repeat('t', 24), 4],
        ];
    }

    public function testLibraryMatchesReferenceModelOnFixedCases(): void
    {
        foreach (self::fixedCases() as $idx => [$keyBin, $iv, $aad, $pt, $tagLen]) {
            $got = Gcm::fromKey($keyBin)->encrypt($pt, $iv, $aad, $tagLen);
            $want = self::referenceEncrypt($keyBin, $iv, $aad, $pt, $tagLen);

            $this->assertSame(bin2hex($want['ciphertext']), bin2hex($got['ciphertext']), "case #{$idx} ciphertext");
            $this->assertSame(bin2hex($want['tag']), bin2hex($got['tag']), "case #{$idx} tag");

            // 解密往返
            $back = Gcm::fromKey($keyBin)->decrypt($got['ciphertext'], $got['tag'], $iv, $aad, $tagLen);
            $this->assertSame(bin2hex($pt), bin2hex($back), "case #{$idx} roundtrip");
        }
    }

    public function testLibraryMatchesReferenceModelOnRandomInputs(): void
    {
        mt_srand(987654321); // 固定种子，保证可复现

        for ($i = 0; $i < 25; $i++) {
            $keyBin = self::randBytes(16);
            $iv = mt_rand(0, 1) === 0 ? self::randBytes(12) : self::randBytes(mt_rand(1, 32));
            $aad = self::randBytes(mt_rand(0, 40));
            $pt = self::randBytes(mt_rand(0, 100));
            $tagLen = [4, 8, 12, 13, 14, 15, 16][mt_rand(0, 6)];

            $got = Gcm::fromKey($keyBin)->encrypt($pt, $iv, $aad, $tagLen);
            $want = self::referenceEncrypt($keyBin, $iv, $aad, $pt, $tagLen);

            $this->assertSame(bin2hex($want['ciphertext']), bin2hex($got['ciphertext']), "case #{$i} ciphertext");
            $this->assertSame(bin2hex($want['tag']), bin2hex($got['tag']), "case #{$i} tag");
        }
    }

    public function testTagVerificationRejectsTamperingAgainstReference(): void
    {
        $keyBin = self::randBytes16();
        $iv = self::randBytes(12);
        $aad = 'header';
        $pt = 'payload';

        $r = Gcm::fromKey($keyBin)->encrypt($pt, $iv, $aad, 16);
        $want = self::referenceEncrypt($keyBin, $iv, $aad, $pt, 16);

        // 正确标签可通过验证
        $this->assertSame($pt, Gcm::fromKey($keyBin)->decrypt($r['ciphertext'], $r['tag'], $iv, $aad, 16));

        // 与参考模型一致的标签必然一致（交叉确认）
        $this->assertTrue(hash_equals($want['tag'], $r['tag']));

        // 篡改任一字节必须失败
        $bad = $r['tag'];
        $bad[0] = $bad[0] === "\x00" ? "\x01" : "\x00";
        $this->expectException(\CryptoSm\Exception\CryptoException::class);
        Gcm::fromKey($keyBin)->decrypt($r['ciphertext'], $bad, $iv, $aad, 16);
    }

    private static function hexBytes(string $hex): string
    {
        $bin = hex2bin($hex);
        self::assertIsString($bin);

        return $bin;
    }

    private static function randBytes16(): string
    {
        return self::randBytes(16);
    }

    private static function randBytes(int $len): string
    {
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(mt_rand(0, 255));
        }
        return $out;
    }
}
