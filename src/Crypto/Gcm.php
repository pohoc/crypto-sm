<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

use CryptoSm\Exception\CryptoException;

/**
 * GCM (Galois/Counter Mode) implementation for SM4.
 *
 * Uses GMP for GF(2^128) multiplication with optimized lookup tables.
 * The SM4 block cipher is delegated to OpenSSL's SM4-ECB (this class
 * is NOT a pure-PHP implementation — it requires the OpenSSL extension
 * with SM4 support for the underlying block encryption).
 *
 * Performance optimizations:
 * - 8-bit (256-entry) lookup table for GHASH multiplication
 * - Precomputed x^8 shifted table to eliminate runtime gfMulX8 calls
 * - Fast gfMulX8 using reduction table (1 lookup vs 8 shift-mask-XOR iterations)
 * - String XOR for block mixing before GMP conversion
 * - gmp_import for fast bytes→GMP conversion
 * - gmp_strval(hex) for fast GMP→bytes conversion
 * - warmup() method for first-call latency elimination
 *
 * Reference: NIST SP 800-38D / GM/T 0002-2012
 */
class Gcm
{
    private const GF_POLY_HEX = '0xe1000000000000000000000000000000';

    private string $keyBin;

    private ?\GMP $hGmp = null;

    /** @var array<int, \GMP>|null Cached 8-bit lookup table: table[i] = i*H in GF(2^128) */
    private ?array $hTable = null;

    /** @var array<int, array<int, \GMP>>|null 16-layer shifted table: layerTable[k][i] = table[i] * x^{8*k} */
    private ?array $layerTable = null;

    private static ?\GMP $gfPolyGmp = null;

    private static ?\GMP $mask128 = null;

    /** @var array<int, \GMP>|null Reduction table for fast x^8 multiplication: reduceTable[b] = reduction for high byte b */
    private static ?array $reduceTable = null;

    private static function initGmpConstants(): void
    {
        if (self::$mask128 === null) {
            self::$mask128 = (gmp_init(1) << 128) - 1;
            self::$gfPolyGmp = gmp_init(self::GF_POLY_HEX);
        }
    }

    public function __construct(string $keyBin)
    {
        if (strlen($keyBin) !== 16) {
            throw new CryptoException('SM4-GCM key must be 16 bytes');
        }
        $this->keyBin = $keyBin;
    }

    public static function fromKey(string $keyBin): self
    {
        return new self($keyBin);
    }

    public function warmup(): void
    {
        self::initGmpConstants();
        self::getReduceTable();
        $this->getLayerTable();
    }

    public static function warmupStatic(): void
    {
        self::initGmpConstants();
        self::getReduceTable();
    }

    private function blockEncrypt(string $block): string
    {
        $result = openssl_encrypt($block, 'SM4-ECB', $this->keyBin, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if ($result === false) {
            throw new CryptoException('SM4 block encryption failed');
        }
        return $result;
    }

    private function getHashSubkey(): \GMP
    {
        if ($this->hGmp === null) {
            $h = $this->blockEncrypt("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
            $this->hGmp = self::bytesToGmp($h);
        }
        return $this->hGmp;
    }

    /**
     * @return array{ciphertext: string, tag: string}
     */
    public function encrypt(string $plaintext, string $iv, string $aad = '', int $tagLength = 16): array
    {
        $this->validateParams($iv, $tagLength);

        $hGmp = $this->getHashSubkey();

        $j0 = $this->computeJ0($iv, $hGmp);

        $ciphertext = $this->ctrEncrypt($plaintext, $j0);

        $tag = $this->computeTag($ciphertext, $aad, $j0, $hGmp, $tagLength);

        return ['ciphertext' => $ciphertext, 'tag' => $tag];
    }

    public function decrypt(string $ciphertext, string $tag, string $iv, string $aad = '', int $tagLength = 16): string
    {
        $this->validateParams($iv, $tagLength);

        if (strlen($tag) !== $tagLength) {
            throw new CryptoException('SM4-GCM: tag length mismatch');
        }

        $hGmp = $this->getHashSubkey();

        $j0 = $this->computeJ0($iv, $hGmp);

        $computedTag = $this->computeTag($ciphertext, $aad, $j0, $hGmp, $tagLength);

        if (!hash_equals($tag, $computedTag)) {
            throw new CryptoException('SM4-GCM decryption failed: authentication tag mismatch');
        }

        return $this->ctrEncrypt($ciphertext, $j0);
    }

    private function validateParams(string $iv, int $tagLength): void
    {
        if (strlen($iv) === 0) {
            throw new CryptoException('SM4-GCM: IV must not be empty');
        }
        if ($tagLength < 4 || $tagLength > 16) {
            throw new CryptoException('SM4-GCM: invalid tag length (must be 4-16)');
        }
    }

    private function computeJ0(string $iv, \GMP $hGmp): string
    {
        if (strlen($iv) === 12) {
            return $iv . "\x00\x00\x00\x01";
        }

        $lenBits = strlen($iv) * 8;
        $paddedIv = $iv . str_repeat("\x00", (16 - strlen($iv) % 16) % 16);
        $lenBlock = self::encodeUint64(0) . self::encodeUint64($lenBits);
        $data = $paddedIv . $lenBlock;

        $yGmp = $this->ghash($data, $hGmp);

        return self::gmpToBytes($yGmp);
    }

    private function ctrEncrypt(string $data, string $j0): string
    {
        if ($data === '') {
            return '';
        }

        $result = '';
        $counter = self::inc32($j0);
        $offset = 0;
        $remaining = strlen($data);

        while ($remaining > 0) {
            $keyStream = $this->blockEncrypt($counter);
            $chunkLen = min($remaining, 16);
            $chunk = substr($data, $offset, $chunkLen);
            if ($chunkLen === 16) {
                $result .= $chunk ^ $keyStream;
            } else {
                $result .= $chunk ^ substr($keyStream, 0, $chunkLen);
            }
            $offset += $chunkLen;
            $remaining -= $chunkLen;
            $counter = self::inc32($counter);
        }

        return $result;
    }

    private function computeTag(string $ciphertext, string $aad, string $j0, \GMP $hGmp, int $tagLength): string
    {
        $aadLen = strlen($aad);
        $ctLen = strlen($ciphertext);

        $paddedAad = $aad;
        if ($aadLen % 16 !== 0) {
            $paddedAad .= str_repeat("\x00", 16 - $aadLen % 16);
        }

        $paddedCt = $ciphertext;
        if ($ctLen % 16 !== 0) {
            $paddedCt .= str_repeat("\x00", 16 - $ctLen % 16);
        }

        $lenBlock = self::encodeUint64($aadLen * 8) . self::encodeUint64($ctLen * 8);

        $ghashInput = $paddedAad . $paddedCt . $lenBlock;
        $yGmp = $this->ghash($ghashInput, $hGmp);

        $encryptedJ0 = $this->blockEncrypt($j0);
        $fullTag = self::gmpToBytes($yGmp) ^ $encryptedJ0;

        return substr($fullTag, 0, $tagLength);
    }

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

    // ─── GF(2^128) Arithmetic ─────────────────────────────────────────────

    /**
     * Get the cached 8-bit lookup table for H.
     *
     * @return array<int, \GMP>
     */
    private function getHTable(): array
    {
        if ($this->hTable === null) {
            $hGmp = $this->getHashSubkey();
            $this->hTable = self::buildHTable($hGmp);
        }
        return $this->hTable;
    }

    /**
     * Get the 16-layer shifted table.
     *
     * layerTable[k][i] = table[i] * x^{8*k} in GF(2^128)
     *
     * This allows GHASH to be computed as a pure XOR sum:
     *   result = ⊕_{j=0}^{15} layerTable[15-j][byte_j]
     *
     * No runtime gfMulX8 calls needed at all.
     *
     * @return array<int, array<int, \GMP>>
     */
    private function getLayerTable(): array
    {
        if ($this->layerTable === null) {
            $table = $this->getHTable();
            $this->layerTable = self::buildLayerTable($table);
        }
        return $this->layerTable;
    }

    /**
     * Build an 8-bit (256-entry) lookup table for GHASH multiplication.
     *
     * @return array<int, \GMP>
     */
    private static function buildHTable(\GMP $h): array
    {
        self::initGmpConstants();

        $table = [];
        $table[0] = gmp_init(0);
        $table[1] = $h;

        for ($i = 2; $i < 256; $i++) {
            if ($i & 1) {
                $table[$i] = $table[$i - 1] ^ $h;
            } else {
                $table[$i] = self::gfMulXGmp($table[$i >> 1]);
            }
        }
        return $table;
    }

    /**
     * Build the 16-layer shifted table from the H table.
     *
     * layerTable[0][i] = table[i]                (x^0 shift, i.e. no shift)
     * layerTable[k][i] = table[i] * x^{8*k}      (shifted by k bytes)
     *
     * Each layer is built by applying gfMulX8 to the previous layer.
     * Total: 16 * 256 = 4096 GMP objects, ~128KB memory.
     *
     * @param  array<int, \GMP>             $table The 8-bit H table
     * @return array<int, array<int, \GMP>>
     */
    private static function buildLayerTable(array $table): array
    {
        self::initGmpConstants();

        $layers = [];
        $layers[0] = $table;

        for ($k = 1; $k < 16; $k++) {
            $prev = $layers[$k - 1];
            $current = [];
            for ($i = 0; $i < 256; $i++) {
                $current[$i] = self::gfMulX8Gmp($prev[$i]);
            }
            $layers[$k] = $current;
        }
        return $layers;
    }

    private static function gfMulXGmp(\GMP $v): \GMP
    {
        self::initGmpConstants();
        assert(self::$mask128 !== null && self::$gfPolyGmp !== null);

        $carry = gmp_testbit($v, 127);
        $result = ($v << 1) & self::$mask128;
        if ($carry) {
            $result ^= self::$gfPolyGmp;
        }
        return $result;
    }

    /**
     * @return array<int, \GMP>
     */
    private static function getReduceTable(): array
    {
        if (self::$reduceTable !== null) {
            return self::$reduceTable;
        }

        self::initGmpConstants();

        $basis = [];
        for ($bit = 0; $bit < 8; $bit++) {
            $v = gmp_init(1) << (120 + $bit);
            for ($j = 0; $j < 8; $j++) {
                $v = self::gfMulXGmp($v);
            }
            $basis[$bit] = $v;
        }

        $table = [];
        $table[0] = gmp_init(0);
        for ($i = 1; $i < 256; $i++) {
            $lowestBit = $i & (-$i);
            $bitPos = 0;
            $tmp = $lowestBit;
            while ($tmp > 1) {
                $tmp >>= 1;
                $bitPos++;
            }
            $table[$i] = $table[$i ^ $lowestBit] ^ $basis[$bitPos];
        }

        self::$reduceTable = $table;
        return $table;
    }

    private static function gfMulX8Gmp(\GMP $v): \GMP
    {
        self::initGmpConstants();
        assert(self::$mask128 !== null);

        $highByte = gmp_intval($v >> 120);
        $result = ($v << 8) & self::$mask128;
        if ($highByte !== 0) {
            $result = $result ^ self::getReduceTable()[$highByte];
        }
        return $result;
    }

    /**
     * GHASH: Compute GHASH_H(data) using precomputed layer tables.
     *
     * Optimized algorithm using 16-layer shifted table:
     * The GHASH multiplication Y*H can be decomposed as:
     *   Y*H = ⊕_{j=0}^{15} (byte_j * H) * x^{8*(15-j)}
     *       = ⊕_{j=0}^{15} layerTable[15-j][byte_j]
     *
     * This eliminates ALL runtime gfMulX8 calls — the inner loop
     * becomes pure GMP XOR operations (16 per block).
     *
     * Additionally:
     * - XOR Y with input block using fast string XOR (avoids GMP XOR)
     * - gmp_import for fast bytes→GMP conversion
     * - gmp_strval(hex) for fast GMP→bytes conversion
     */
    private function ghash(string $data, \GMP $hGmp): \GMP
    {
        $layerTable = $this->getLayerTable();
        self::initGmpConstants();

        $yBytes = str_repeat("\x00", 16);
        $dataLen = strlen($data);

        for ($i = 0; $i < $dataLen; $i += 16) {
            $block = substr($data, $i, 16);

            $yBytes = $yBytes ^ $block;

            $z = gmp_init(0);
            for ($j = 0; $j < 16; $j++) {
                $byte = ord($yBytes[$j]);
                if ($byte !== 0) {
                    $z = $z ^ $layerTable[15 - $j][$byte];
                }
            }

            $yBytes = self::gmpToBytes($z);
        }

        return self::bytesToGmp($yBytes);
    }

    private static function bytesToGmp(string $bytes): \GMP
    {
        $reflected = str_repeat("\x00", 16);
        for ($i = 0; $i < 16; $i++) {
            $reflected[$i] = chr(self::reverseByte(ord($bytes[$i])) & 0xFF);
        }
        return gmp_import($reflected, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }

    private static function gmpToBytes(\GMP $value): string
    {
        $hex = str_pad(gmp_strval($value, 16), 32, '0', STR_PAD_LEFT);
        $raw = hex2bin($hex);
        if ($raw === false) {
            return str_repeat("\x00", 16);
        }
        if (strlen($raw) > 16) {
            $raw = substr($raw, -16);
        } elseif (strlen($raw) < 16) {
            $raw = str_repeat("\x00", 16 - strlen($raw)) . $raw;
        }
        $result = str_repeat("\x00", 16);
        for ($i = 0; $i < 16; $i++) {
            $result[$i] = chr(self::reverseByte(ord($raw[$i])) & 0xFF);
        }
        return $result;
    }

    /**
     * @param  int<0, 255> $byte
     * @return int<0, 255>
     */
    private static function reverseByte(int $byte): int
    {
        static $table = null;
        if ($table === null) {
            $table = [
                0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
                0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
                0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
                0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
                0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
                0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
                0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
                0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
                0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
                0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
                0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
                0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
                0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
                0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
                0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
                0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF,
            ];
        }
        return $table[$byte & 0xFF];
    }

    private static function encodeUint64(int $value): string
    {
        return pack('J', $value);
    }
}
