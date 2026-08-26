<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

use CryptoSm\Exception\CryptoException;
use CryptoSm\SM4\Sm4PurePhp;

/**
 * GCM (Galois/Counter Mode) implementation for SM4.
 *
 * Uses GMP for GF(2^128) multiplication with optimized lookup tables.
 * The SM4 block cipher uses OpenSSL's SM4-ECB when available and falls
 * back to the library's pure-PHP SM4 block implementation otherwise.
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
    /**
     * Valid authentication tag lengths in bytes (NIST SP 800-38D Section 5.2.1.2
     * recommends this discrete set for interoperability).
     */
    public const VALID_TAG_LENGTHS = [4, 8, 12, 13, 14, 15, 16];

    private string $keyBin;

    private ?Sm4PurePhp $purePhpEngine = null;

    private ?\GMP $hGmp = null;

    /** GF(2^128) 归约多项式 R = 0xE1 || 0^120（MSB-first 规范域） */
    private static ?\GMP $rPoly = null;

    private static ?\GMP $mask128 = null;

    private static function initGmpConstants(): void
    {
        if (self::$mask128 === null) {
            self::$mask128 = (gmp_init(1) << 128) - 1;
            self::$rPoly = gmp_init(0xE1) << 120;
        }
    }

    /**
     * GF(2^128) 乘法：NIST SP 800-38D Algorithm 1 的规范直译。
     *
     * 此前基于"字节位反射域 + 多层查表"的优化实现存在域混用缺陷，导致
     * 认证标签与 NIST / RFC 8998 官方向量不一致（密文正确、标签错误，
     * 由变异测试触发、差分验证定位）。现回归逐位规范实现；如未来重新
     * 引入查表优化，必须先通过 GcmReferenceModelTest 与 RFC 8998 向量
     * 的双重验证后再合入。
     */
    private static function gmul(\GMP $x, \GMP $y): \GMP
    {
        self::initGmpConstants();
        assert(self::$rPoly !== null && self::$mask128 !== null);

        $z = gmp_init(0);
        $v = $y;
        for ($i = 127; $i >= 0; $i--) {
            if (gmp_testbit($x, $i)) {
                $z ^= $v;
            }
            $lsb = gmp_testbit($v, 0);
            $v >>= 1;
            if ($lsb) {
                $v ^= self::$rPoly;
            }
        }
        return $z & self::$mask128;
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
        // 重构后无建表开销，仅预热域常量（保留 API 兼容）
        self::initGmpConstants();
    }

    public static function warmupStatic(): void
    {
        self::initGmpConstants();
    }

    private function blockEncrypt(string $block): string
    {
        if (Sm4PurePhp::openSslSm4Available()) {
            $result = openssl_encrypt($block, 'SM4-ECB', $this->keyBin, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($result !== false) {
                return $result;
            }
        }

        if ($this->purePhpEngine === null) {
            $this->purePhpEngine = new Sm4PurePhp();
            $this->purePhpEngine->setKey($this->keyBin);
        }
        return $this->purePhpEngine->encryptBlock($block);
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
        if (!in_array($tagLength, self::VALID_TAG_LENGTHS, true)) {
            throw new CryptoException('SM4-GCM: invalid tag length (must be one of ' . implode(', ', self::VALID_TAG_LENGTHS) . ' bytes)');
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

    // ─── GHASH ────────────────────────────────────────────────────────────

    /**
     * GHASH_H(data)：规范直译实现（NIST SP 800-38D Algorithm 2）。
     *
     * 调用方保证 $data 为 16 字节的整数倍（computeJ0/computeTag 均已填充）。
     */
    private function ghash(string $data, \GMP $hGmp): \GMP
    {
        $dataLen = strlen($data);
        $y = gmp_init(0);

        for ($i = 0; $i < $dataLen; $i += 16) {
            $blockInt = gmp_import(substr($data, $i, 16));
            $y = self::gmul($y ^ $blockInt, $hGmp);
        }

        return $y;
    }

    private static function bytesToGmp(string $bytes): \GMP
    {
        // 规范域（MSB-first）直接导入，不做字节内位反射：
        // 反射域必须配套反射版归约多项式，此前混用导致 GHASH 与
        // NIST SP 800-38D / RFC 8998 不一致（密文正确、标签错误）
        return gmp_import($bytes, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
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
        return $raw;
    }

    private static function encodeUint64(int $value): string
    {
        return pack('J', $value);
    }
}
