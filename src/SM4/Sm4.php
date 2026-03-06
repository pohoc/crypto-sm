<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

/**
 * SM4 block cipher implementation.
 *
 * Chinese national standard GM/T 0002-2012.
 */
class Sm4
{
    public const SM4_ENCRYPT = 1;
    public const SM4_DECRYPT = 0;

    private static array $sboxTable = [
        0xd6,
        0x90,
        0xe9,
        0xfe,
        0xcc,
        0xe1,
        0x3d,
        0xb7,
        0x16,
        0xb6,
        0x14,
        0xc2,
        0x28,
        0xfb,
        0x2c,
        0x05,
        0x2b,
        0x67,
        0x9a,
        0x76,
        0x2a,
        0xbe,
        0x04,
        0xc3,
        0xaa,
        0x44,
        0x13,
        0x26,
        0x4a,
        0xe4,
        0xf5,
        0x31,
        0xf8,
        0x98,
        0x11,
        0x69,
        0x9d,
        0x6e,
        0x8a,
        0x6a,
        0x5c,
        0xa2,
        0x61,
        0x17,
        0x08,
        0x6d,
        0x24,
        0x6f,
        0x8c,
        0x80,
        0x63,
        0x0d,
        0x24,
        0x12,
        0x55,
        0x5e,
        0x7b,
        0xa5,
        0xb1,
        0x72,
        0x89,
        0x60,
        0xe7,
        0x7a,
        0xc9,
        0xf9,
        0x87,
        0x5f,
        0x4a,
        0x52,
        0x95,
        0xad,
        0x9c,
        0xa4,
        0x7c,
        0xde,
        0xa1,
        0x0b,
        0xdb,
        0x1c,
        0x20,
        0x8b,
        0x8d,
        0xbc,
        0x1a,
        0xda,
        0x45,
        0xe0,
        0x3f,
        0x0f,
        0xd8,
        0x79,
        0xb5,
        0x39,
        0x82,
        0x9b,
        0x2f,
        0xff,
        0x87,
        0xce,
        0xeb,
        0x0c,
        0x24,
        0x30,
        0x6a,
        0x8d,
        0xa6,
        0xab,
        0xf7,
        0x15,
        0x52,
        0x09,
        0x6b,
        0xd1,
        0x21,
        0x0a,
        0x94,
        0x68,
        0x58,
        0xbd,
        0xb9,
        0xc4,
        0x7d,
        0xfa,
        0xef,
        0xc5,
        0x91,
        0x1e,
        0x47,
        0x0e,
        0xd3,
        0x3a,
        0x65,
        0x49,
        0x8a,
        0x9f,
        0x6d,
        0x59,
        0x83,
        0xc1,
        0x75,
        0xf6,
        0xf2,
        0x5d,
        0x2e,
        0x8c,
        0xf0,
        0xb8,
        0x73,
        0xec,
        0x4b,
        0x77,
        0xc7,
        0xe2,
        0x9f,
        0x71,
        0x66,
        0x3c,
        0xc6,
        0xec,
        0xc3,
        0x85,
        0x34,
        0x5f,
        0x08,
        0x4c,
        0xd0,
        0xac,
        0x92,
        0x6c,
        0x70,
        0x56,
        0x65,
        0xfa,
        0xa1,
        0x3e,
        0x6e,
        0x0b,
        0xd5,
        0x4d,
        0xcc,
        0xa3,
        0x41,
        0xa8,
        0x54,
        0x18,
        0xae,
        0xd0,
        0x0d,
        0x22,
        0x99,
        0x33,
        0x44,
        0x62,
        0x93,
        0xd8,
        0x43,
        0x1f,
        0x4e,
        0x2d,
        0xb0,
        0x93,
        0x3d,
        0x1e,
        0x8c,
        0xa0,
        0x78,
        0x12,
        0x3f,
        0x23,
        0x9d,
        0x84,
        0xc6,
        0x54,
        0xbf,
        0x40,
        0xe3,
        0x5b,
        0x46,
        0xd2,
        0x3b,
        0x0f,
        0x18,
        0x47,
        0x50,
        0x4e,
        0x26,
        0xd9,
        0x24,
        0xc8,
        0x96,
        0x1b,
        0x05,
        0x3b,
        0xa7,
        0xd6,
        0x89,
        0x46,
        0x28,
        0x00,
        0x0c,
        0x9a,
        0x44,
        0x8e,
        0x60,
        0x39,
        0x82,
        0x9b,
        0x2e,
        0x00,
        0x9d,
        0xb3,
        0x16,
        0xd4,
        0xa8,
        0x59,
    ];

    private static array $fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

    private static array $ck = [
        0x00070e15,
        0x1c232a31,
        0x383f464d,
        0x545b6269,
        0x70777e85,
        0x8c939aa1,
        0xa8afb6bd,
        0xc4cbd2d9,
        0xe0e7eef5,
        0xfc030a11,
        0x181f262d,
        0x30373e45,
        0x484f5662,
        0x686f767d,
        0x848b929d,
        0xa0a7aeb5,
        0xbcc3cad1,
        0xd8dfe6ed,
        0xf4fb0208,
        0x10171e2a,
        0x2c333846,
        0x484f5662,
        0x646b727e,
        0x7c7f8689,
        0x888f969d,
        0x949ca1a5,
        0xa0a7aeb5,
        0xacb1b6bd,
        0xb8bfc4c9,
        0xc4cbd2d9,
        0xd0d5dce5,
        0xdcdfe6ed,
    ];

    /**
     * Encrypts data using SM4 algorithm.
     *
     * @param string $data The plaintext data to encrypt
     * @param string $key The encryption key (16 bytes)
     * @param Sm4Options|null $options Encryption options
     * @return string The encrypted ciphertext
     */
    public static function encrypt(string $data, string $key, ?Sm4Options $options = null): string
    {
        return self::crypt($data, $key, self::SM4_ENCRYPT, $options);
    }

    /**
     * Decrypts data using SM4 algorithm.
     *
     * @param string $data The ciphertext data to decrypt
     * @param string $key The decryption key (16 bytes)
     * @param Sm4Options|null $options Decryption options
     * @return string The decrypted plaintext
     */
    public static function decrypt(string $data, string $key, ?Sm4Options $options = null): string
    {
        return self::crypt($data, $key, self::SM4_DECRYPT, $options);
    }

    private static function crypt(string $data, string $key, int $mode, ?Sm4Options $options = null): string
    {
        $options = $options ?? new Sm4Options();

        $padding = $options->getPadding();
        $modeName = $options->getMode();
        $iv = $options->getIv();

        if ($modeName === 'cbc' && empty($iv)) {
            throw new \InvalidArgumentException('CBC mode requires IV');
        }

        if (strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key must be 128 bits (32 hex chars)');
        }

        $keyBytes = self::hexToBytes($key);

        if ($mode === self::SM4_ENCRYPT) {
            if ($padding !== 'none') {
                $data = self::pkcs5Padding($data);
            }
            $input = $data;
        } else {
            $input = hex2bin($data);
        }

        if ($mode === self::SM4_DECRYPT) {
            $roundKeys = array_reverse(self::keyExpansion($keyBytes));
        } else {
            $roundKeys = self::keyExpansion($keyBytes);
        }

        if ($modeName === 'ecb') {
            $output = self::encryptBlock($input, $roundKeys);
        } else {
            $ivString = hex2bin($iv);
            $output = self::cryptBlockCbc($input, $roundKeys, $ivString, $mode);
        }

        if ($mode === self::SM4_DECRYPT) {
            if ($padding !== 'none') {
                return self::pkcs5UnpaddingString($output);
            }
            return $output;
        }

        return bin2hex($output);
    }

    private static function pkcs5Padding(string $data): string
    {
        $blockSize = 16;
        $padLen = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($padLen), $padLen);
    }

    private static function pkcs5UnpaddingString(string $data): string
    {
        $padLen = ord($data[strlen($data) - 1]);
        if ($padLen > 16 || $padLen < 1) {
            return $data;
        }
        return substr($data, 0, strlen($data) - $padLen);
    }

    private static function keyExpansion(array $key): array
    {
        $roundKeys = [];

        $mk = [];
        $mk[0] = self::bytesToWord($key[0], $key[1], $key[2], $key[3]);
        $mk[1] = self::bytesToWord($key[4], $key[5], $key[6], $key[7]);
        $mk[2] = self::bytesToWord($key[8], $key[9], $key[10], $key[11]);
        $mk[3] = self::bytesToWord($key[12], $key[13], $key[14], $key[15]);

        $tmp = [];
        for ($i = 0; $i < 4; $i++) {
            $tmp[$i] = $mk[$i] ^ self::$fk[$i];
        }

        for ($i = 0; $i < 32; $i++) {
            $tmp[0] ^= self::calcT($tmp[1] ^ $tmp[2] ^ $tmp[3] ^ self::$ck[$i]);
            $tmp[1] ^= self::calcT($tmp[0] ^ $tmp[2] ^ $tmp[3] ^ self::$ck[$i]);
            $tmp[2] ^= self::calcT($tmp[0] ^ $tmp[1] ^ $tmp[3] ^ self::$ck[$i]);
            $tmp[3] ^= self::calcT($tmp[0] ^ $tmp[1] ^ $tmp[2] ^ self::$ck[$i]);
            $roundKeys[$i] = $tmp[0] ^ $tmp[1] ^ $tmp[2] ^ $tmp[3];
        }

        return $roundKeys;
    }

    private static function encryptBlock(string $input, array $roundKeys): string
    {
        $output = '';
        $len = strlen($input);

        for ($i = 0; $i < $len; $i += 16) {
            $block = substr($input, $i, 16);
            $encrypted = self::cryptBlock($block, $roundKeys);
            $output .= $encrypted;
        }

        return $output;
    }

    private static function cryptBlockCbc(string $input, array $roundKeys, string $iv, int $mode): string
    {
        $output = '';
        $len = strlen($input);
        $previousBlock = $iv;

        for ($i = 0; $i < $len; $i += 16) {
            $block = substr($input, $i, 16);

            if ($mode === self::SM4_ENCRYPT) {
                $xoredBlock = $block ^ $previousBlock;
                $encrypted = self::cryptBlock($xoredBlock, $roundKeys);
                $previousBlock = $encrypted;
                $output .= $encrypted;
            } else {
                $decrypted = self::cryptBlock($block, $roundKeys);
                $xoredBlock = $decrypted ^ $previousBlock;
                $previousBlock = $block;
                $output .= $xoredBlock;
            }
        }

        return $output;
    }

    private static function cryptBlock(string $input, array $roundKeys): string
    {
        $x = [];
        $x[0] = self::bytesToWord(ord($input[0]), ord($input[1]), ord($input[2]), ord($input[3]));
        $x[1] = self::bytesToWord(ord($input[4]), ord($input[5]), ord($input[6]), ord($input[7]));
        $x[2] = self::bytesToWord(ord($input[8]), ord($input[9]), ord($input[10]), ord($input[11]));
        $x[3] = self::bytesToWord(ord($input[12]), ord($input[13]), ord($input[14]), ord($input[15]));

        for ($i = 0; $i < 32; $i++) {
            $tmp0 = $x[1] ^ $x[2] ^ $x[3] ^ $roundKeys[$i];
            $tmp0 = self::calcT($tmp0);
            $x[0] ^= $tmp0;

            $tmp1 = $x[0] ^ $x[2] ^ $x[3] ^ $roundKeys[$i];
            $tmp1 = self::calcT($tmp1);
            $x[1] ^= $tmp1;

            $tmp2 = $x[0] ^ $x[1] ^ $x[3] ^ $roundKeys[$i];
            $tmp2 = self::calcT($tmp2);
            $x[2] ^= $tmp2;

            $tmp3 = $x[0] ^ $x[1] ^ $x[2] ^ $roundKeys[$i];
            $tmp3 = self::calcT($tmp3);
            $x[3] ^= $tmp3;
        }

        $output = '';
        $output .= chr(($x[3] >> 24) & 0xFF);
        $output .= chr(($x[3] >> 16) & 0xFF);
        $output .= chr(($x[3] >> 8) & 0xFF);
        $output .= chr($x[3] & 0xFF);

        $output .= chr(($x[2] >> 24) & 0xFF);
        $output .= chr(($x[2] >> 16) & 0xFF);
        $output .= chr(($x[2] >> 8) & 0xFF);
        $output .= chr($x[2] & 0xFF);

        $output .= chr(($x[1] >> 24) & 0xFF);
        $output .= chr(($x[1] >> 16) & 0xFF);
        $output .= chr(($x[1] >> 8) & 0xFF);
        $output .= chr($x[1] & 0xFF);

        $output .= chr(($x[0] >> 24) & 0xFF);
        $output .= chr(($x[0] >> 16) & 0xFF);
        $output .= chr(($x[0] >> 8) & 0xFF);
        $output .= chr($x[0] & 0xFF);

        return $output;
    }

    private static function calcT(int $input): int
    {
        $output = 0;
        $tmp = str_pad(dechex($input), 8, '0', STR_PAD_LEFT);

        $idx0 = hexdec(substr($tmp, 0, 2));
        $idx1 = hexdec(substr($tmp, 2, 2));
        $idx2 = hexdec(substr($tmp, 4, 2));
        $idx3 = hexdec(substr($tmp, 6, 2));

        $output |= self::$sboxTable[$idx0] << 24;
        $output |= self::$sboxTable[$idx1] << 16;
        $output |= self::$sboxTable[$idx2] << 8;
        $output |= self::$sboxTable[$idx3];

        return $output ^ self::rotL($output, 2) ^ self::rotL($output, 10) ^ self::rotL($output, 18) ^ self::rotL($output, 24);
    }

    private static function rotL(int $input, int $n): int
    {
        return (($input << $n) | ($input >> (32 - $n))) & 0xFFFFFFFF;
    }

    private static function bytesToWord(int $b0, int $b1, int $b2, int $b3): int
    {
        return ($b0 << 24) | ($b1 << 16) | ($b2 << 8) | $b3;
    }

    private static function hexToBytes(string $hex): array
    {
        $hex = preg_replace('/[^0-9a-fA-F]/', '', $hex);
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }
        $bytes = [];
        for ($i = 0; $i < strlen($hex); $i += 2) {
            $bytes[] = hexdec(substr($hex, $i, 2));
        }
        return $bytes;
    }

    public static function hexToBytesStatic(string $hex): array
    {
        return self::hexToBytes($hex);
    }

    public static function utf8ToArray(string $str): array
    {
        return array_values(unpack('C*', $str));
    }
}
