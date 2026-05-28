<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

use CryptoSm\Exception\CryptoException;

/**
 * Pure PHP SM4 block cipher implementation (GM/T 0002-2012).
 *
 * Used as fallback when the OpenSSL extension does not provide SM4 support.
 * Implements the block primitive used by ECB directly and by CBC, CFB,
 * OFB, CTR, and GCM fallback composition in Sm4/Gcm.
 */
final class Sm4PurePhp
{
    /**
     * SM4 S-box (8x8 substitution, 256 entries).
     * Defined in GM/T 0002-2012 Appendix A.
     */
    private const SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
    ];

    /** FK constants for key expansion (GM/T 0002-2012 Section 5.2) */
    private const FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];

    /** CK constants for key expansion (GM/T 0002-2012 Section 5.2) */
    private const CK = [
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
    ];

    /** @var array<int,int> 32 round keys */
    private array $roundKeys;

    /** @var bool Whether keys are initialized */
    private bool $keyInitialized = false;

    /**
     * Encrypt a single 16-byte block.
     *
     * @param  string          $block 16-byte plaintext block
     * @return string          16-byte ciphertext block
     * @throws CryptoException If block size is invalid
     */
    public function encryptBlock(string $block): string
    {
        if (strlen($block) !== 16) {
            throw new CryptoException('SM4 block must be 16 bytes');
        }
        $this->ensureKey();

        return $this->processBlock($block, $this->roundKeys);
    }

    /**
     * Decrypt a single 16-byte block.
     *
     * @param  string          $block 16-byte ciphertext block
     * @return string          16-byte plaintext block
     * @throws CryptoException If block size is invalid
     */
    public function decryptBlock(string $block): string
    {
        if (strlen($block) !== 16) {
            throw new CryptoException('SM4 block must be 16 bytes');
        }
        $this->ensureKey();

        // Decryption uses round keys in reverse order
        return $this->processBlock($block, array_reverse($this->roundKeys));
    }

    /**
     * Initialize with a 128-bit (16-byte) key.
     *
     * @param string $keyBin 16-byte binary key
     */
    public function setKey(string $keyBin): void
    {
        if (strlen($keyBin) !== 16) {
            throw new CryptoException('SM4 key must be 16 bytes');
        }
        $this->roundKeys = self::keyExpansion($keyBin);
        $this->keyInitialized = true;
    }

    /**
     * Check if this platform can use OpenSSL SM4.
     */
    public static function openSslSm4Available(): bool
    {
        return function_exists('openssl_encrypt')
            && in_array('SM4-ECB', openssl_get_cipher_methods(), true);
    }

    // ─── Internal Implementation ─────────────────────────────────────────

    private function ensureKey(): void
    {
        if (!$this->keyInitialized) {
            throw new CryptoException('SM4 key not set — call setKey() first');
        }
    }

    /**
     * Process one block with given round keys (32 rounds).
     */
    /**
     * @param array<int,int> $rk
     */
    private function processBlock(string $block, array $rk): string
    {
        $words = unpack('N4', $block);
        if ($words === false) {
            throw new CryptoException('SM4 block unpack failed');
        }
        $x = array_values($words);

        for ($i = 0; $i < 32; $i++) {
            $tmp = $x[$i + 1] ^ $x[$i + 2] ^ $x[$i + 3] ^ $rk[$i];
            $t = self::tau($tmp);
            $x[$i + 4] = $x[$i] ^ self::l($t);
        }

        // Reverse order for output: X35, X34, X33, X32
        return pack('N4', $x[35], $x[34], $x[33], $x[32]);
    }

    /**
     * SM4 key expansion: generates 32 round keys from a 128-bit key.
     *
     * @param  string         $keyBin 16-byte binary key
     * @return array<int,int> 32 round keys (32-bit integers)
     */
    private static function keyExpansion(string $keyBin): array
    {
        $words = unpack('N4', $keyBin);
        if ($words === false) {
            throw new CryptoException('SM4 key unpack failed');
        }
        $mk = array_values($words);

        // K[0..3] = MK[i] ^ FK[i]
        $k = [];
        for ($i = 0; $i < 4; $i++) {
            $k[$i] = $mk[$i] ^ self::FK[$i];
        }

        // Generate 32 round keys: rk[i] = K[i+4] = K[i] ^ T'(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])
        $rk = [];
        for ($i = 0; $i < 32; $i++) {
            $tmp = $k[$i + 1] ^ $k[$i + 2] ^ $k[$i + 3] ^ self::CK[$i];
            $t = self::tau($tmp);
            $k[$i + 4] = $k[$i] ^ self::lPrime($t);
            $rk[$i] = $k[$i + 4];
        }

        return $rk;
    }

    /**
     * Non-linear transformation tau: applies S-box to each byte.
     *
     * @param  int $a 32-bit input
     * @return int 32-bit output after S-box substitution
     */
    private static function tau(int $a): int
    {
        return (self::SBOX[($a >> 24) & 0xFF] << 24)
            | (self::SBOX[($a >> 16) & 0xFF] << 16)
            | (self::SBOX[($a >> 8) & 0xFF] << 8)
            | (self::SBOX[$a & 0xFF]);
    }

    /**
     * Linear transformation L for encryption rounds.
     * L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)
     *
     * @param  int $b 32-bit input
     * @return int 32-bit output
     */
    private static function l(int $b): int
    {
        return ($b ^ self::rotl($b, 2) ^ self::rotl($b, 10)
            ^ self::rotl($b, 18) ^ self::rotl($b, 24)) & 0xFFFFFFFF;
    }

    /**
     * Simplified linear transformation L' for key expansion.
     * L'(B) = B ^ (B <<< 13) ^ (B <<< 23)
     *
     * @param  int $b 32-bit input
     * @return int 32-bit output
     */
    private static function lPrime(int $b): int
    {
        return ($b ^ self::rotl($b, 13) ^ self::rotl($b, 23)) & 0xFFFFFFFF;
    }

    /**
     * Rotate left by n bits (32-bit word).
     */
    private static function rotl(int $x, int $n): int
    {
        return (($x << $n) | (($x >> (32 - $n)) & ((1 << $n) - 1))) & 0xFFFFFFFF;
    }
}
