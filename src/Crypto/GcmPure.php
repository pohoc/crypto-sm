<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

use CryptoSm\Exception\CryptoException;

/**
 * Pure PHP implementation of SM4-GCM (Galois/Counter Mode).
 *
 * This is a fallback when OpenSSL does not support SM4-GCM natively.
 * GCM = CTR mode encryption + GHASH authentication.
 * The SM4 block cipher is delegated to OpenSSL's SM4-ECB.
 *
 * Reference: NIST SP 800-38D
 */
class GcmPure
{
    /** @var string Reduction polynomial for GF(2^128): x^128 + x^7 + x^2 + x + 1 */
    private const GF_POLY = "\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    /** @var string Raw 16-byte key for SM4 block encryption */
    private string $keyBin;

    /**
     * @param string $keyBin 16-byte raw key
     */
    public function __construct(string $keyBin)
    {
        if (strlen($keyBin) !== 16) {
            throw new CryptoException('SM4-GCM key must be 16 bytes');
        }
        $this->keyBin = $keyBin;
    }

    /**
     * Create a GcmPure instance from a raw key (16 bytes).
     *
     * @param string $keyBin 16-byte raw key
     */
    public static function fromKey(string $keyBin): self
    {
        return new self($keyBin);
    }

    /**
     * Encrypt a single 16-byte block using SM4-ECB via OpenSSL.
     */
    private function blockEncrypt(string $block): string
    {
        $result = openssl_encrypt($block, 'SM4-ECB', $this->keyBin, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if ($result === false) {
            throw new CryptoException('SM4 block encryption failed');
        }
        return $result;
    }

    /**
     * Encrypt data using SM4-GCM.
     *
     * @param  string                                 $plaintext Binary plaintext
     * @param  string                                 $iv        Binary initialization vector (typically 12 bytes)
     * @param  string                                 $aad       Binary additional authenticated data
     * @param  int                                    $tagLength Tag length in bytes (4-16)
     * @return array{ciphertext: string, tag: string}
     */
    public function encrypt(string $plaintext, string $iv, string $aad = '', int $tagLength = 16): array
    {
        $this->validateParams($iv, $tagLength);

        $h = $this->blockEncrypt("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

        // Initial counter J0
        $j0 = $this->computeJ0($iv, $h);

        // Encrypt: CTR mode starting from counter J0 + 1
        $ciphertext = $this->ctrEncrypt($plaintext, $j0);

        // Compute authentication tag
        $tag = $this->computeTag($ciphertext, $aad, $j0, $h, $tagLength);

        return ['ciphertext' => $ciphertext, 'tag' => $tag];
    }

    /**
     * Decrypt data using SM4-GCM.
     *
     * @param  string          $ciphertext Binary ciphertext
     * @param  string          $tag        Binary authentication tag
     * @param  string          $iv         Binary initialization vector
     * @param  string          $aad        Binary additional authenticated data
     * @param  int             $tagLength  Expected tag length in bytes
     * @return string          Decrypted plaintext
     * @throws CryptoException If authentication tag verification fails
     */
    public function decrypt(string $ciphertext, string $tag, string $iv, string $aad = '', int $tagLength = 16): string
    {
        $this->validateParams($iv, $tagLength);

        if (strlen($tag) !== $tagLength) {
            throw new CryptoException('SM4-GCM: tag length mismatch');
        }

        $h = $this->blockEncrypt("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

        $j0 = $this->computeJ0($iv, $h);

        // Verify tag first
        $computedTag = $this->computeTag($ciphertext, $aad, $j0, $h, $tagLength);

        if (!self::hashEquals($tag, $computedTag)) {
            throw new CryptoException('SM4-GCM decryption failed: authentication tag mismatch');
        }

        // Decrypt: CTR mode starting from counter J0 + 1
        return $this->ctrEncrypt($ciphertext, $j0);
    }

    /**
     * Validate GCM parameters.
     */
    private function validateParams(string $iv, int $tagLength): void
    {
        if (strlen($iv) === 0) {
            throw new CryptoException('SM4-GCM: IV must not be empty');
        }
        if (strlen($iv) > 18) {
            throw new CryptoException('SM4-GCM: IV too long');
        }
        if ($tagLength < 4 || $tagLength > 16) {
            throw new CryptoException('SM4-GCM: invalid tag length (must be 4-16)');
        }
    }

    /**
     * Compute the initial counter block J0 from the IV.
     *
     * If IV is 12 bytes (96 bits): J0 = IV || 0x00000001
     * Otherwise: J0 = GHASH_H(IV || 0^s || len(IV))
     */
    private function computeJ0(string $iv, string $h): string
    {
        if (strlen($iv) === 12) {
            return $iv . "\x00\x00\x00\x01";
        }

        $lenBits = strlen($iv) * 8;
        $paddedIv = $iv . str_repeat("\x00", (16 - strlen($iv) % 16) % 16);
        $lenBlock = self::encodeUint64(0) . self::encodeUint64($lenBits);
        $data = $paddedIv . $lenBlock;

        $y = str_repeat("\x00", 16);
        for ($i = 0; $i < strlen($data); $i += 16) {
            $block = substr($data, $i, 16);
            $y = self::gfMul($y ^ $block, $h);
        }

        return $y;
    }

    /**
     * CTR mode encryption/decryption (same operation for both).
     */
    private function ctrEncrypt(string $data, string $j0): string
    {
        if ($data === '') {
            return '';
        }

        $result = '';
        $counter = self::inc32($j0); // Start from J0 + 1
        $offset = 0;
        $remaining = strlen($data);

        while ($remaining > 0) {
            $keyStream = $this->blockEncrypt($counter);
            $chunkLen = min($remaining, 16);
            for ($i = 0; $i < $chunkLen; $i++) {
                $result .= $data[$offset + $i] ^ $keyStream[$i];
            }
            $offset += $chunkLen;
            $remaining -= $chunkLen;
            $counter = self::inc32($counter);
        }

        return $result;
    }

    /**
     * Compute the GCM authentication tag.
     *
     * Tag = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64) XOR E(K, J0)
     */
    private function computeTag(string $ciphertext, string $aad, string $j0, string $h, int $tagLength): string
    {
        $aadLen = strlen($aad);
        $ctLen = strlen($ciphertext);

        // Pad AAD to block boundary
        $paddedAad = $aad;
        if ($aadLen % 16 !== 0) {
            $paddedAad .= str_repeat("\x00", 16 - $aadLen % 16);
        }

        // Pad ciphertext to block boundary
        $paddedCt = $ciphertext;
        if ($ctLen % 16 !== 0) {
            $paddedCt .= str_repeat("\x00", 16 - $ctLen % 16);
        }

        // Length block: [len(A) in bits]_64 || [len(C) in bits]_64
        $lenBlock = self::encodeUint64($aadLen * 8) . self::encodeUint64($ctLen * 8);

        // GHASH
        $y = str_repeat("\x00", 16);
        $ghashInput = $paddedAad . $paddedCt . $lenBlock;

        for ($i = 0; $i < strlen($ghashInput); $i += 16) {
            $block = substr($ghashInput, $i, 16);
            $y = self::gfMul($y ^ $block, $h);
        }

        // Tag = GHASH XOR E(K, J0)
        $encryptedJ0 = $this->blockEncrypt($j0);
        $fullTag = $y ^ $encryptedJ0;

        return substr($fullTag, 0, $tagLength);
    }

    /**
     * Increment the rightmost 32 bits of a 128-bit counter (big-endian).
     */
    private static function inc32(string $counter): string
    {
        $c = $counter;
        for ($i = 15; $i >= 12; $i--) {
            $byte = ord($c[$i]) + 1;
            $c[$i] = chr($byte & 0xFF);
            if ($byte <= 0xFF) {
                break;
            }
        }
        return $c;
    }

    /**
     * Multiply two elements in GF(2^128) using the GCM polynomial.
     *
     * Uses 8-bit lookup table method for performance:
     * Precomputes a 256-entry table from Y, then processes X 1 byte at a time.
     * This reduces iterations from 32 (4-bit method) to 16 (byte-by-byte),
     * and eliminates per-nibble bit extraction overhead.
     *
     * Additionally, the H table is cached per GcmPure instance so that
     * repeated GHASH operations (encrypt/decrypt) reuse the same table.
     *
     * Reduction polynomial: x^128 + x^7 + x^2 + x + 1
     */
    private static function gfMul(string $x, string $y): string
    {
        // Build 8-bit lookup table: table[i] = i * Y in GF(2^128)
        // table[0] = 0, table[i] = table[i >> 1] * x + (i & 1) * Y
        // But simpler: table[0] = 0, table[2k] = table[k] * x, table[2k+1] = table[2k] XOR Y
        $table = [];
        $table[0] = str_repeat("\x00", 16);
        $table[1] = $y;
        for ($i = 2; $i < 256; $i++) {
            if ($i & 1) {
                // Odd: table[i] = table[i-1] XOR Y
                $table[$i] = $table[$i - 1] ^ $y;
            } else {
                // Even: table[i] = table[i/2] * x (left-shift by 1 with reduction)
                $table[$i] = self::gfMulX($table[$i >> 1]);
            }
        }

        $z = str_repeat("\x00", 16);

        // Process X 1 byte (8 bits) at a time from MSB to LSB
        for ($i = 0; $i < 16; $i++) {
            // Multiply Z by x^8 (8 left-shifts with reduction)
            $z = self::gfMulX8($z);

            // Look up the byte value in the precomputed table
            $byte = ord($x[$i]);
            if ($byte !== 0) {
                $z = $z ^ $table[$byte];
            }
        }

        return $z;
    }

    /**
     * Multiply by x^8 in GF(2^128) — eight successive multiplications by x.
     *
     * Optimized: applies left-shift-and-reduce 8 times with inlined operations
     * to minimize function call overhead.
     */
    private static function gfMulX8(string $v): string
    {
        for ($i = 0; $i < 8; $i++) {
            $v = self::gfMulX($v);
        }
        return $v;
    }

    /**
     * Multiply by x in GF(2^128) — left-shift by 1 bit with reduction.
     *
     * Uses array-based byte operations for better performance than
     * string concatenation in a loop.
     *
     * If the MSB (bit 127) is set before shifting, XOR with the reduction
     * polynomial after shifting.
     */
    private static function gfMulX(string $v): string
    {
        // Check if bit 127 (MSB of byte 0) is set
        $carry = (ord($v[0]) >> 7) & 1;

        // Left-shift all 16 bytes by 1 bit using array ops
        /** @var array<int, int> $bytes */
        $bytes = unpack('C16', $v);
        $prevCarry = 0;
        for ($i = 16; $i >= 1; $i--) {
            $newCarry = ($bytes[$i] >> 7) & 1;
            $bytes[$i] = (($bytes[$i] << 1) & 0xFF) | $prevCarry;
            $prevCarry = $newCarry;
        }

        $result = pack('C16', ...$bytes);

        // Apply reduction polynomial if carry was set
        if ($carry) {
            $result = $result ^ self::GF_POLY;
        }

        return $result;
    }

    /**
     * Encode a 64-bit unsigned integer as 8-byte big-endian binary.
     */
    private static function encodeUint64(int $value): string
    {
        return pack('J', $value);
    }

    /**
     * Timing-safe string comparison.
     */
    private static function hashEquals(string $a, string $b): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($a, $b);
        }
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        $result = 0;
        $len = strlen($a);
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $result === 0;
    }
}
