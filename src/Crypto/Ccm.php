<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

use CryptoSm\Exception\CryptoException;
use CryptoSm\SM4\Sm4PurePhp;

use function is_array;

/**
 * SM4-CCM authenticated encryption (NIST SP 800-38C / RFC 3610 construction).
 *
 * CCM = Counter mode encryption + CBC-MAC authentication.
 * This implementation follows the RFC 3610 block formatting with SM4
 * as the 128-bit block cipher and SM3-style tag truncation rules
 * (valid M values per NIST: {4, 6, 8, 10, 12, 14, 16}).
 */
final class Ccm
{
    /** @var array<int, true> Valid MAC tag lengths in bytes per NIST SP 800-38C */
    private const VALID_TAG_LENGTHS = [4 => true, 6 => true, 8 => true, 10 => true, 12 => true, 14 => true, 16 => true];

    private string $keyBin;

    private ?Sm4PurePhp $engine = null;

    public function __construct(string $keyBin)
    {
        if (strlen($keyBin) !== 16) {
            throw new CryptoException('SM4-CCM key must be 16 bytes');
        }
        $this->keyBin = $keyBin;
    }

    public static function fromKey(string $keyBin): self
    {
        return new self($keyBin);
    }

    /**
     * Encrypt and authenticate.
     *
     * @param  string                                 $plaintext Data to encrypt
     * @param  string                                 $nonce     7–13 byte nonce (unique per message under the same key)
     * @param  string                                 $aad       Additional authenticated data (not encrypted)
     * @param  int                                    $tagLength Tag length in bytes (4, 6, 8, 10, 12, 14, or 16)
     * @return array{ciphertext: string, tag: string} Binary strings
     */
    public function encrypt(string $plaintext, string $nonce, string $aad = '', int $tagLength = 16): array
    {
        self::validateParams($nonce, $tagLength, strlen($aad), strlen($plaintext));

        // Format B0 block: flags || nonce || message length
        $q = 15 - strlen($nonce); // length-field width in bytes
        $flagsB0 = self::formatFlags($tagLength, strlen($aad) > 0, $q);
        $b0 = chr($flagsB0) . $nonce . str_pad(self::encodeLengthField(strlen($plaintext), $q), $q, "\0", STR_PAD_LEFT);

        // CBC-MAC over B0, AAD blocks, plaintext blocks
        $macInput = $b0 . self::formatAad($aad) . $plaintext . str_repeat("\0", ((16 - strlen($plaintext) % 16) % 16));
        $macTag = self::cbcMac($macInput);

        // CTR encryption: A0 for tag encryption, A1..An for plaintext
        $ctrStart = $this->buildCounterBlock(false, $nonce, $q, 1);
        $keystream = $this->ctrKeystream($plaintext, $ctrStart);
        $ciphertext = $plaintext ^ $keystream;

        $a0 = $this->buildCounterBlock(false, $nonce, $q, 0);
        $encTag = $macTag ^ substr($this->blockEncrypt($a0), 0, $tagLength);

        return ['ciphertext' => $ciphertext, 'tag' => substr($encTag, 0, $tagLength)];
    }

    /**
     * Decrypt and verify.
     *
     * @return string Plaintext
     *
     * @throws CryptoException If authentication fails
     */
    public function decrypt(string $ciphertext, string $tag, string $nonce, string $aad = '', int $tagLength = 16): string
    {
        if (strlen($tag) !== $tagLength) {
            throw new CryptoException('SM4-CCM: tag length mismatch');
        }
        self::validateParams($nonce, $tagLength, strlen($aad), strlen($ciphertext));

        $q = 15 - strlen($nonce);
        $a0 = $this->buildCounterBlock(false, $nonce, $q, 0);
        $mask = substr($this->blockEncrypt($a0), 0, $tagLength);
        $decryptedTag = $tag ^ $mask;

        $ctrStart = $this->buildCounterBlock(false, $nonce, $q, 1);
        $keystream = $this->ctrKeystream($ciphertext, $ctrStart);
        $plaintext = $ciphertext ^ $keystream;

        // Verify CBC-MAC over decrypted data
        $flagsB0 = self::formatFlags($tagLength, strlen($aad) > 0, $q);
        $b0 = chr($flagsB0) . $nonce . str_pad(self::encodeLengthField(strlen($plaintext), $q), $q, "\0", STR_PAD_LEFT);
        $macInput = $b0 . self::formatAad($aad) . $plaintext . str_repeat("\0", ((16 - strlen($plaintext) % 16) % 16));
        $expectedTag = self::cbcMac($macInput);

        if (!hash_equals(substr($expectedTag, 0, $tagLength), $decryptedTag)) {
            throw new CryptoException('SM4-CCM: authentication failed');
        }

        return $plaintext;
    }

    // ─── Internal ─────────────────────────────────────────────────────────

    private static function validateParams(string $nonce, int $tagLength, int $aadLen, int $dataLen): void
    {
        if (strlen($nonce) < 7 || strlen($nonce) > 13) {
            throw new CryptoException('SM4-CCM nonce must be 7–13 bytes');
        }
        if (!isset(self::VALID_TAG_LENGTHS[$tagLength])) {
            throw new CryptoException('SM4-CCM invalid tag length (must be one of 4,6,8,10,12,14,16)');
        }
        $q = 15 - strlen($nonce);
        // q*8 可达 64 位，PHP int 在 64 位系统上最大 shift 为 62
        $maxShift = min($q * 8, PHP_INT_SIZE * 8 - 2);
        if ($dataLen >= (1 << $maxShift)) {
            throw new CryptoException('SM4-CCM message too long for nonce size');
        }
        // RFC 3610：AAD 长度上限受限于 4 字节扩展前缀编码容量
        // [不可达守卫] 硬上限超出任何实际内存可构造输入
        if ($aadLen >= (1 << 32)) {
            throw new CryptoException('SM4-CCM AAD exceeds supported maximum');
        }
        // [/不可达守卫]
    }

    private static function formatFlags(int $tagLength, bool $hasAad, int $q): int
    {
        $t = ($tagLength - 2) >> 1; // (M-2)/2, stored in 3 bits
        $flags = ($t << 3);          // T' field [bits 6..3]
        if ($hasAad) {
            $flags |= 0x40;          // Adata flag bit 6
        }
        $flags |= ($q - 1) & 0x07;   // Q' field [bits 2..0]
        return $flags;
    }

    private static function encodeLengthField(int $value, int $bytes): string
    {
        $out = '';
        for ($i = $bytes - 1; $i >= 0; $i--) {
            $out .= chr(($value >> ($i * 8)) & 0xFF);
        }
        return $out;
    }

    /**
     * Format AAD length prefix + AAD padded to 16-byte boundary per RFC 3610.
     */
    private static function formatAad(string $aad): string
    {
        $aadLen = strlen($aad);
        if ($aadLen === 0) {
            return '';
        }
        if ($aadLen < 65280) {
            if ($aadLen < 256) {
                $prefix = pack('C', $aadLen);
            } else {
                $prefix = "\xFF\xFE" . pack('n', $aadLen);
            }
        } else {
            $prefix = "\xFF\xFF" . pack('N', $aadLen);
        }
        $result = $prefix . $aad;
        $padLen = (16 - strlen($result) % 16) % 16;
        return $result . str_repeat("\0", $padLen);
    }

    /**
     * Build a counter/generator block: flags || nonce || counter.
     */
    private function buildCounterBlock(bool $isMac, string $nonce, int $q, int $counter): string
    {
        $flags = ($q - 1) & 0x07; // L' field only (no Adata, no M fields)
        return chr($flags) . $nonce . str_pad(self::encodeLengthField($counter, $q), $q, "\0", STR_PAD_LEFT);
    }

    /**
     * Generate keystream for data using CTR mode starting from the given block.
     */
    private function ctrKeystream(string $data, string $startCounter): string
    {
        $blocks = (int) ceil(strlen($data) / 16);
        $ks = '';
        $unpackedLo = unpack('N', substr($startCounter, 12, 4));
        if (!is_array($unpackedLo) || !isset($unpackedLo[1])) {
            throw new \LogicException('unpack failed');
        }
        $lo = $unpackedLo[1];
        $prefix = substr($startCounter, 0, 12);

        for ($i = 1; $i <= $blocks; $i++) {
            $ctr = $prefix . pack('N', ($lo + $i) & 0xFFFFFFFF);
            $ks .= $this->blockEncrypt($ctr);
        }
        return $ks;
    }

    /**
     * Compute raw CBC-MAC over pre-padded input.
     */
    private function cbcMac(string $padded): string
    {
        $y = str_repeat("\0", 16);
        for ($i = 0, $len = strlen($padded); $i < $len; $i += 16) {
            $block = substr($padded, $i, 16);
            $y = $this->blockEncrypt($y ^ $block);
        }
        return $y;
    }

    private function blockEncrypt(string $block): string
    {
        if ($this->engine === null) {
            $this->engine = new Sm4PurePhp();
            $this->engine->setKey($this->keyBin);
        }
        return $this->engine->encryptBlock($block);
    }
}
