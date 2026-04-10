<?php

declare(strict_types=1);

namespace CryptoSm\SM3;

use CryptoSm\Interfaces\HashInterface;

/**
 * SM3 cryptographic hash algorithm implementation (GM/T 0004-2012).
 */
class Sm3 implements HashInterface
{
    private const IV = [
        0x7380166f,
        0x4914b2b9,
        0x172442d7,
        0xda8a0600,
        0xa96f30bc,
        0x163138aa,
        0xe38dee4d,
        0xb0fb0e4e,
    ];

    /**
     * Compute SM3 hash of the given data.
     *
     * @param  string $data Input data
     * @return string 64-character hex string (256-bit hash)
     */
    public static function sm3(string $data): string
    {
        return self::computeHash($data);
    }

    /**
     * Alias for sm3() — static hash computation (HashInterface naming convention).
     *
     * @param  string $data Input data
     * @return string 64-character hex string
     */
    public static function hashStatic(string $data): string
    {
        return self::sm3($data);
    }

    /**
     * Instance method for hash computation (HashInterface).
     *
     * @param  string $data Input data
     * @return string 64-character hex string
     */
    public function hash(string $data): string
    {
        return self::sm3($data);
    }

    /** @var bool|null Cached availability of OpenSSL SM3 support */
    private static ?bool $openSslSm3Available = null;

    private static function computeHash(string $msg): string
    {
        // P0: 优先使用 OpenSSL 原生 SM3（OpenSSL 1.1.1+ 支持，C 实现比纯 PHP 快 100-300 倍）
        if (self::$openSslSm3Available === null) {
            self::$openSslSm3Available = function_exists('openssl_digest')
                && in_array('sm3', openssl_get_md_methods(), true);
        }
        if (self::$openSslSm3Available) {
            $result = openssl_digest($msg, 'sm3');
            if ($result !== false) {
                return $result;
            }
        }

        return self::computeHashPure($msg);
    }

    /**
     * Pure PHP SM3 implementation (fallback when OpenSSL SM3 is unavailable).
     *
     * Optimizations applied:
     * - Inline helper functions as closures to reduce method call overhead (~640 calls/block)
     * - Cache repeated sub-expressions (rol($a, 12))
     * - Remove unnecessary p32() on XOR results (XOR of 32-bit values stays within 32 bits)
     * - Unroll the j < 16 / j >= 16 branch outside the inner loop
     */
    private static function computeHashPure(string $msg): string
    {
        $blocks = self::pad($msg);
        $v = self::IV;

        // Inline helpers as closures — significantly faster than self::method() calls
        $rol = static fn (int $x, int $n): int => (($x << ($n & 31)) | ($x >> (32 - ($n & 31)))) & 0xFFFFFFFF;
        $p0 = static fn (int $x): int => ($x ^ $rol($x, 9) ^ $rol($x, 17)) & 0xFFFFFFFF;
        $p1 = static fn (int $x): int => ($x ^ $rol($x, 15) ^ $rol($x, 23)) & 0xFFFFFFFF;

        foreach ($blocks as $block) {
            [$w, $wPrime] = self::expandWith($block, $rol, $p1);

            [$a, $b, $c, $d, $e, $f, $g, $h] = $v;

            // Unroll j < 16 and j >= 16 phases to avoid per-iteration branch
            for ($j = 0; $j < 16; $j++) {
                $rolA12 = $rol($a, 12);
                $ss1 = $rol(($rolA12 + $e + $rol(0x79cc4519, $j % 32)) & 0xFFFFFFFF, 7);
                $ss2 = $ss1 ^ $rolA12;
                $ff = $a ^ $b ^ $c;
                $gg = $e ^ $f ^ $g;
                $tt1 = ($ff + $d + $ss2 + $wPrime[$j]) & 0xFFFFFFFF;
                $tt2 = ($gg + $h + $ss1 + $w[$j]) & 0xFFFFFFFF;

                $d = $c;
                $c = $rol($b, 9);
                $b = $a;
                $a = $tt1;
                $h = $g;
                $g = $rol($f, 19);
                $f = $e;
                $e = $p0($tt2);
            }

            for ($j = 16; $j < 64; $j++) {
                $rolA12 = $rol($a, 12);
                $ss1 = $rol(($rolA12 + $e + $rol(0x7a879d8a, $j % 32)) & 0xFFFFFFFF, 7);
                $ss2 = $ss1 ^ $rolA12;
                $ff = ($a & $b) | ($a & $c) | ($b & $c);
                $gg = ($e & $f) | ((~$e) & $g);
                $tt1 = ($ff + $d + $ss2 + $wPrime[$j]) & 0xFFFFFFFF;
                $tt2 = ($gg + $h + $ss1 + $w[$j]) & 0xFFFFFFFF;

                $d = $c;
                $c = $rol($b, 9);
                $b = $a;
                $a = $tt1;
                $h = $g;
                $g = $rol($f, 19);
                $f = $e;
                $e = $p0($tt2);
            }

            // XOR of 32-bit values stays within 32 bits — no p32() needed
            $v = [
                $v[0] ^ $a,
                $v[1] ^ $b,
                $v[2] ^ $c,
                $v[3] ^ $d,
                $v[4] ^ $e,
                $v[5] ^ $f,
                $v[6] ^ $g,
                $v[7] ^ $h,
            ];
        }

        return sprintf(
            '%08x%08x%08x%08x%08x%08x%08x%08x',
            ...$v
        );
    }

    /**
     * @param callable(int, int): int $rol
     * @param callable(int): int      $p1
     *
     * @return array<int,array<int,int>>
     */
    private static function expandWith(string $block, callable $rol, callable $p1): array
    {
        $unpacked = unpack('N16', $block);
        $w = $unpacked === false ? [] : array_values($unpacked);
        for ($j = 16; $j < 68; $j++) {
            $w[$j] = $p1($w[$j - 16] ^ $w[$j - 9] ^ $rol($w[$j - 3], 15))
                ^ $rol($w[$j - 13], 7) ^ $w[$j - 6];
        }

        $wPrime = [];
        for ($j = 0; $j < 64; $j++) {
            $wPrime[$j] = ($w[$j] ^ $w[$j + 4]) & 0xFFFFFFFF;
        }

        return [$w, $wPrime];
    }

    /** @return array<int,string> */
    private static function pad(string $msg): array
    {
        $len = strlen($msg);
        $bitLen = $len * 8;

        $msg .= chr(0x80);
        $padLen = (56 - (($len + 1) % 64) + 64) % 64;
        if ($padLen) {
            $msg .= str_repeat(chr(0x00), $padLen);
        }
        $msg .= pack('N2', $bitLen >> 32, $bitLen & 0xFFFFFFFF);

        return str_split($msg, 64);
    }
}
