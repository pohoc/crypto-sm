<?php

declare(strict_types=1);

namespace CryptoSm\SM3;

/**
 * SM3 cryptographic hash function implementation.
 *
 * Chinese national standard GM/T 0004-2012.
 */
class Sm3
{
    private static array $iv = [
        0x7380166f,
        0x4914b2b9,
        0xdc45292a,
        0x980a225e,
        0xa08e44e4,
        0xf05fc1d2,
        0x1c1ff3f8,
        0xd2536f93
    ];

    private static function ror32(int $x, int $n): int
    {
        return (($x >> $n) | ($x << (32 - $n))) & 0xFFFFFFFF;
    }

    private static function mod32(int $x): int
    {
        return $x & 0xFFFFFFFF;
    }

    private static function pad(string $msg): string
    {
        $msgLen = strlen($msg);
        $bitLen = $msgLen * 8;

        $msg .= chr(0x80);

        $remainder = strlen($msg) % 64;
        if ($remainder > 56) {
            $msg .= str_repeat(chr(0), 64 - $remainder + 56);
        } else {
            $msg .= str_repeat(chr(0), 56 - $remainder);
        }

        $msg .= pack('N', 0);
        $msg .= pack('N', $bitLen);

        return $msg;
    }

    /**
     * Computes SM3 hash of the input data.
     *
     * @param string $data The input data to hash
     * @return string The hash in hexadecimal format
     */
    public static function sm3(string $data): string
    {
        return self::hash($data);
    }

    private static function hash(string $msg): string
    {
        $msg = self::pad($msg);
        $n = strlen($msg) / 64;

        $v = self::$iv;

        for ($i = 0; $i < $n; $i++) {
            $block = substr($msg, $i * 64, 64);
            $w = self::expand($block);
            $w1 = array_slice($w, 16);

            $a = $v[0];
            $b = $v[1];
            $c = $v[2];
            $d = $v[3];
            $e = $v[4];
            $f = $v[5];
            $g = $v[6];
            $h = $v[7];

            for ($j = 0; $j < 64; $j++) {
                $ss1 = self::ror32(self::mod32(self::mod32(self::ror32($a, 12) + $e + self::t($j)) + 7), 7);
                $ss2 = self::mod32($ss1 ^ self::ror32($a, 12));

                if ($j < 16) {
                    $tt1 = self::mod32(self::mod32(self::mod32($a ^ $b ^ $c) + $e) + $ss2 + self::mod32($w1[$j] ^ $w[$j]));
                    $tt2 = self::mod32(self::mod32(self::mod32($e ^ $f ^ $g) + $d) + $ss1 + $w[$j]);
                } else {
                    $aa = ($a & $b) | ($a & $c) | ($b & $c);
                    $bb = ($e & $f) | ((~$e) & $g);
                    $tt1 = self::mod32(self::mod32($aa + $e + $ss2 + self::mod32($w1[$j - 16] ^ $w[$j])));
                    $tt2 = self::mod32(self::mod32($bb + $d + $ss1 + $w[$j]));
                }

                $d = $c;
                $c = self::ror32($b, 9);
                $b = $a;
                $a = $tt1;
                $h = $g;
                $g = self::ror32($f, 19);
                $f = $e;
                $e = self::p0($tt2);
            }

            $v[0] = self::mod32($v[0] ^ $a);
            $v[1] = self::mod32($v[1] ^ $b);
            $v[2] = self::mod32($v[2] ^ $c);
            $v[3] = self::mod32($v[3] ^ $d);
            $v[4] = self::mod32($v[4] ^ $e);
            $v[5] = self::mod32($v[5] ^ $f);
            $v[6] = self::mod32($v[6] ^ $g);
            $v[7] = self::mod32($v[7] ^ $h);
        }

        $result = '';
        foreach ($v as $word) {
            $result .= sprintf('%08x', $word);
        }

        return $result;
    }

    private static function expand(string $block): array
    {
        $w = [];
        $words = unpack('N16', $block);

        for ($j = 0; $j < 16; $j++) {
            $w[$j] = $words[$j + 1];
        }

        for ($j = 16; $j < 68; $j++) {
            $w[$j] = self::mod32(
                self::p1($w[$j - 16] ^ $w[$j - 9] ^ self::ror32($w[$j - 13], 15)) ^
                    self::ror32($w[$j - 9], 7) ^
                    $w[$j - 3]
            );
        }

        for ($j = 0; $j < 64; $j++) {
            $w[$j] = self::mod32($w[$j] ^ $w[$j + 4]);
        }

        return $w;
    }

    private static function t(int $j): int
    {
        return $j < 16 ? 0x79cc4519 : 0x7a879d8a;
    }

    private static function p0(int $x): int
    {
        return self::mod32($x ^ self::ror32($x, 9) ^ self::ror32($x, 17));
    }

    private static function p1(int $x): int
    {
        return self::mod32($x ^ self::ror32($x, 15) ^ self::ror32($x, 23));
    }
}
