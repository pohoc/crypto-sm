<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Interfaces\CcmBlockUsageTrackerInterface;
use CryptoSm\Interfaces\CcmNonceTrackerInterface;
use CryptoSm\Interfaces\CcmTagLengthTrackerInterface;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4PurePhp;
use CryptoSm\Utils\SensitiveContext;

/**
 * SM4-CCM authenticated encryption (NIST SP 800-38C / RFC 3610 construction).
 *
 * CCM = Counter mode encryption + CBC-MAC authentication.
 * This implementation follows the RFC 3610 block formatting with SM4
 * as the 128-bit block cipher and SM3-style tag truncation rules
 * (valid M values per NIST: {4, 6, 8, 10, 12, 14, 16}). NIST requires
 * the selected tag length to stay fixed for every invocation under one key.
 */
final class Ccm
{
    use SensitiveContext;
    /** @var array<int, true> Valid MAC tag lengths in bytes per NIST SP 800-38C */
    private const VALID_TAG_LENGTHS = [4 => true, 6 => true, 8 => true, 10 => true, 12 => true, 14 => true, 16 => true];

    private const MAX_TRACKED_NONCES = 65536;
    private const MAX_TRACKED_TAG_PROFILES = 65536;
    private const MAX_TRACKED_BLOCK_USAGE_KEYS = 65536;
    private const MAX_BLOCK_CIPHER_INVOCATIONS_PER_KEY = '2305843009213693952'; // 2^61

    /** @var \WeakMap<object, string>|null */
    private static ?\WeakMap $keys = null;

    /** @var array<string, true> */
    private static array $usedNonces = [];

    /** @var array<string, int> */
    private static array $tagLengthByKey = [];

    /** @var array<string, array{tagLength: int, pending: int}> */
    private static array $pendingTagLengthByKey = [];

    /** @var array<string, \GMP> Process-local count of CCM block-cipher calls by key */
    private static array $blockInvocationsByKey = [];

    private static ?CcmNonceTrackerInterface $nonceTracker = null;

    private static ?CcmTagLengthTrackerInterface $tagLengthTracker = null;

    private static ?CcmBlockUsageTrackerInterface $blockUsageTracker = null;

    private static bool $trackerConfigurationLocked = false;

    private static bool $blockUsageTrackingLocked = false;

    private \stdClass $keyHandle;

    private ?Sm4PurePhp $engine = null;

    public function __construct(string $keyBin)
    {
        if (strlen($keyBin) !== 16) {
            throw new CryptoException('SM4-CCM key must be 16 bytes');
        }
        $this->keyHandle = new \stdClass();
        self::keyStore()[$this->keyHandle] = $keyBin;
    }

    public static function fromKey(string $keyBin): self
    {
        return new self($keyBin);
    }

    /**
     * Configure an atomic application-wide nonce tracker before the first CCM encryption.
     * The tracker must persist claims across every process sharing the same encryption key.
     */
    public static function setNonceTracker(?CcmNonceTrackerInterface $tracker): void
    {
        if (self::$trackerConfigurationLocked) {
            throw new \LogicException('CCM nonce tracker cannot be changed after CCM processing has started');
        }

        self::$nonceTracker = $tracker;
    }

    /**
     * Configure an atomic application-wide fixed tag-length profile before
     * the first CCM encryption. Multi-process decryptors should use the same
     * tracker as encryptors so the key profile cannot vary across workers.
     */
    public static function setTagLengthTracker(?CcmTagLengthTrackerInterface $tracker): void
    {
        if (self::$trackerConfigurationLocked) {
            throw new \LogicException('CCM tag length tracker cannot be changed after CCM processing has started');
        }

        self::$tagLengthTracker = $tracker;
    }

    /**
     * Configure an atomic, durable CCM block-usage tracker before any CCM
     * block-cipher operation. Required alongside the nonce tracker when a key
     * is shared across workers or process restarts.
     */
    public static function setBlockUsageTracker(?CcmBlockUsageTrackerInterface $tracker): void
    {
        if (self::$blockUsageTrackingLocked) {
            throw new \LogicException('CCM block-usage tracker cannot be changed after CCM processing has started');
        }

        self::$blockUsageTracker = $tracker;
    }

    public function __clone()
    {
        $key = self::keyStore()[$this->keyHandle] ?? null;
        if (!is_string($key)) {
            throw new \LogicException('SM4-CCM key context is unavailable');
        }

        $this->keyHandle = new \stdClass();
        self::keyStore()[$this->keyHandle] = $key;
        $this->engine = $this->engine === null ? null : clone $this->engine;
    }

    /** @return \WeakMap<object, string> */
    private static function keyStore(): \WeakMap
    {
        return self::$keys ??= new \WeakMap();
    }

    private static function reserveTagLength(string $keyId, int $tagLength): bool
    {
        // When configured, the shared tracker is authoritative. Avoid keeping
        // a duplicate process-local profile that can exhaust its bounded map.
        if (self::$tagLengthTracker !== null) {
            return false;
        }

        $configured = self::$tagLengthByKey[$keyId] ?? null;
        if ($configured !== null) {
            if ($configured !== $tagLength) {
                throw new CryptoException('SM4-CCM tag length must remain fixed for each key within this process');
            }
            return false;
        }

        $pending = self::$pendingTagLengthByKey[$keyId] ?? null;
        if ($pending !== null) {
            if ($pending['tagLength'] !== $tagLength) {
                throw new CryptoException('SM4-CCM tag length must remain fixed for each key within this process');
            }
            self::$pendingTagLengthByKey[$keyId]['pending']++;
            return true;
        }

        if (count(self::$tagLengthByKey) + count(self::$pendingTagLengthByKey) >= self::MAX_TRACKED_TAG_PROFILES) {
            throw new CryptoException(
                'SM4-CCM tag profile tracker capacity reached; configure a shared CcmTagLengthTrackerInterface during bootstrap and restart this process'
            );
        }

        self::$pendingTagLengthByKey[$keyId] = ['tagLength' => $tagLength, 'pending' => 1];
        return true;
    }

    private static function finishTagLengthReservation(string $keyId, int $tagLength, bool $reserved, bool $commit): void
    {
        if (!$reserved) {
            return;
        }

        if ($commit) {
            self::$tagLengthByKey[$keyId] = $tagLength;
        }

        $pending = self::$pendingTagLengthByKey[$keyId] ?? null;
        if ($pending === null || $pending['tagLength'] !== $tagLength || $pending['pending'] < 1) {
            throw new \LogicException('SM4-CCM tag length reservation is unavailable');
        }
        if ($pending['pending'] === 1) {
            unset(self::$pendingTagLengthByKey[$keyId]);
            return;
        }
        self::$pendingTagLengthByKey[$keyId]['pending']--;
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
        $key = self::keyStore()[$this->keyHandle] ?? null;
        if (!is_string($key)) {
            throw new \LogicException('SM4-CCM key context is unavailable');
        }
        Sm4::claimEncryptionModeForKey($key, Sm4::MODE_CCM);
        $blockInvocations = self::estimateBlockInvocations(strlen($aad), strlen($plaintext));
        $this->claimNonce($nonce, $tagLength, $blockInvocations);

        // Format B0 block: flags || nonce || message length
        $q = 15 - strlen($nonce); // length-field width in bytes
        $flagsB0 = self::formatFlags($tagLength, strlen($aad) > 0, $q);
        $b0 = chr($flagsB0) . $nonce . str_pad(self::encodeLengthField(strlen($plaintext), $q), $q, "\0", STR_PAD_LEFT);

        // Process MAC input and CTR keystream a block at a time. Building a
        // concatenated MAC input and a full-size keystream would multiply peak
        // memory use for large caller-controlled payloads.
        $aadPrefix = self::aadLengthPrefix(strlen($aad));
        $aadPadding = str_repeat("\0", (16 - (strlen($aadPrefix) + strlen($aad)) % 16) % 16);
        $dataPadding = str_repeat("\0", (16 - strlen($plaintext) % 16) % 16);
        $macTag = $this->cbcMacParts([$b0, $aadPrefix, $aad, $aadPadding, $plaintext, $dataPadding]);

        // CTR encryption: A0 for tag encryption, A1..An for plaintext
        $ctrStart = $this->buildCounterBlock(false, $nonce, $q, 1);
        $ciphertext = $this->ctrXor($plaintext, $ctrStart);

        $a0 = $this->buildCounterBlock(false, $nonce, $q, 0);
        $encTag = $macTag ^ substr($this->blockEncrypt($a0), 0, $tagLength);

        return ['ciphertext' => $ciphertext, 'tag' => substr($encTag, 0, $tagLength)];
    }

    private function claimNonce(string $nonce, int $tagLength, int $blockInvocations): void
    {
        $key = self::keyStore()[$this->keyHandle] ?? null;
        if (!is_string($key)) {
            throw new \LogicException('SM4-CCM key context is unavailable');
        }

        $keyId = hash('sha256', $key);
        $tagLengthReserved = self::reserveTagLength($keyId, $tagLength);
        $tagLengthCommitted = false;
        try {
            self::$trackerConfigurationLocked = true;
            // Lock before invoking the nonce tracker: its callback is external
            // code and must not be able to replace the usage counter policy.
            self::$blockUsageTrackingLocked = true;
            if (self::$nonceTracker !== null) {
                if (!self::$nonceTracker->claim($key, $nonce)) {
                    throw new CryptoException('SM4-CCM nonce reuse detected for this key');
                }
            } else {
                $id = hash('sha256', $key . $nonce, true);
                if (isset(self::$usedNonces[$id])) {
                    throw new CryptoException('SM4-CCM nonce reuse detected for this key');
                }
                if (count(self::$usedNonces) >= self::MAX_TRACKED_NONCES) {
                    throw new CryptoException(
                        'SM4-CCM nonce tracker capacity reached; configure a shared CcmNonceTrackerInterface during bootstrap and restart this process'
                    );
                }

                self::$usedNonces[$id] = true;
            }

            self::claimBlockInvocations($key, $keyId, $blockInvocations, false);

            // Do not let a rejected/reused nonce initialize the shared tag
            // profile. The nonce is reserved first; if the profile then rejects
            // this length, burning that nonce is safe, while poisoning the
            // profile on a failed nonce claim can deny later valid encryptions.
            if (self::$tagLengthTracker !== null && !self::$tagLengthTracker->claimTagLength($key, $tagLength)) {
                throw new CryptoException('SM4-CCM tag length must remain fixed for each key');
            }

            self::finishTagLengthReservation($keyId, $tagLength, $tagLengthReserved, true);
            $tagLengthCommitted = true;
        } finally {
            if (!$tagLengthCommitted) {
                self::finishTagLengthReservation($keyId, $tagLength, $tagLengthReserved, false);
            }
        }
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

        $key = self::keyStore()[$this->keyHandle] ?? null;
        if (!is_string($key)) {
            throw new \LogicException('SM4-CCM key context is unavailable');
        }
        $keyId = hash('sha256', $key);
        $configuredTagLength = self::$tagLengthByKey[$keyId] ?? null;
        if ($configuredTagLength !== null && $configuredTagLength !== $tagLength) {
            throw new CryptoException('SM4-CCM: authentication failed');
        }

        // Authentication work below consumes CCM block inputs even if it fails.
        Sm4::assertDecryptionModeForKey($key, Sm4::MODE_CCM);

        $blockInvocations = self::estimateBlockInvocations(strlen($aad), strlen($ciphertext));
        self::claimBlockInvocations($key, $keyId, $blockInvocations, true);

        $q = 15 - strlen($nonce);
        $a0 = $this->buildCounterBlock(false, $nonce, $q, 0);
        $mask = substr($this->blockEncrypt($a0), 0, $tagLength);
        $decryptedTag = $tag ^ $mask;

        $ctrStart = $this->buildCounterBlock(false, $nonce, $q, 1);
        $plaintext = $this->ctrXor($ciphertext, $ctrStart);

        // Verify CBC-MAC over decrypted data
        $flagsB0 = self::formatFlags($tagLength, strlen($aad) > 0, $q);
        $b0 = chr($flagsB0) . $nonce . str_pad(self::encodeLengthField(strlen($plaintext), $q), $q, "\0", STR_PAD_LEFT);
        $aadPrefix = self::aadLengthPrefix(strlen($aad));
        $aadPadding = str_repeat("\0", (16 - (strlen($aadPrefix) + strlen($aad)) % 16) % 16);
        $dataPadding = str_repeat("\0", (16 - strlen($plaintext) % 16) % 16);
        $expectedTag = $this->cbcMacParts([$b0, $aadPrefix, $aad, $aadPadding, $plaintext, $dataPadding]);

        if (!hash_equals(substr($expectedTag, 0, $tagLength), $decryptedTag)) {
            throw new CryptoException('SM4-CCM: authentication failed');
        }

        self::$trackerConfigurationLocked = true;
        $tagLengthReserved = self::reserveTagLength($keyId, $tagLength);
        $tagLengthCommitted = false;
        try {
            if (self::$tagLengthTracker !== null && !self::$tagLengthTracker->claimTagLength($key, $tagLength)) {
                throw new CryptoException('SM4-CCM: authentication failed');
            }

            self::finishTagLengthReservation($keyId, $tagLength, $tagLengthReserved, true);
            $tagLengthCommitted = true;
        } finally {
            if (!$tagLengthCommitted) {
                self::finishTagLengthReservation($keyId, $tagLength, $tagLengthReserved, false);
            }
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
        // Only form 2^(8q) when it fits in a positive PHP integer. Otherwise
        // every representable string length already fits in the q-byte field.
        $lengthBits = $q * 8;
        if ($lengthBits < PHP_INT_SIZE * 8 - 1 && $dataLen >= (1 << $lengthBits)) {
            throw new CryptoException('SM4-CCM message too long for nonce size');
        }
    }

    /**
     * Count all SM4 calls for CCM: CBC-MAC blocks plus CTR payload blocks and
     * the counter block used to mask the authentication tag.
     */
    private static function estimateBlockInvocations(int $aadLen, int $dataLen): int
    {
        $aadPrefixLength = strlen(self::aadLengthPrefix($aadLen));
        $aadRemainder = ($aadLen % 16) + $aadPrefixLength;
        $aadBlocks = intdiv($aadLen, 16)
            + intdiv($aadRemainder, 16)
            + ($aadRemainder % 16 === 0 ? 0 : 1);
        $payloadBlocks = intdiv($dataLen, 16) + ($dataLen % 16 === 0 ? 0 : 1);

        return 2 + $aadBlocks + 2 * $payloadBlocks;
    }

    /** Reserve CCM's per-key SP 800-38C block-cipher usage before doing work. */
    private static function claimBlockInvocations(string $key, string $keyId, int $count, bool $decryption): void
    {
        self::$blockUsageTrackingLocked = true;
        $tracker = self::$blockUsageTracker;
        if ($tracker !== null) {
            if (!$tracker->claimBlockInvocations($key, $count)) {
                throw new CryptoException($decryption
                    ? 'SM4-CCM: authentication failed'
                    : 'SM4-CCM per-key block-cipher usage limit reached; rotate the key');
            }
            return;
        }

        $current = self::$blockInvocationsByKey[$keyId] ?? gmp_init(0);
        $next = gmp_add($current, $count);
        if (gmp_cmp($next, gmp_init(self::MAX_BLOCK_CIPHER_INVOCATIONS_PER_KEY)) > 0) {
            throw new CryptoException($decryption
                ? 'SM4-CCM: authentication failed'
                : 'SM4-CCM per-key block-cipher usage limit reached; rotate the key');
        }
        if (!isset(self::$blockInvocationsByKey[$keyId])
            && count(self::$blockInvocationsByKey) >= self::MAX_TRACKED_BLOCK_USAGE_KEYS) {
            throw new CryptoException(
                'SM4-CCM block-usage tracker capacity reached; configure a shared CcmBlockUsageTrackerInterface during bootstrap and restart this process'
            );
        }

        self::$blockInvocationsByKey[$keyId] = $next;
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

    private static function aadLengthPrefix(int $aadLen): string
    {
        if ($aadLen === 0) {
            return '';
        }
        if ($aadLen < 65280) {
            return pack('n', $aadLen);
        }
        if ($aadLen < 4294967296) {
            return "\xFF\xFE" . pack('N', $aadLen);
        }
        return "\xFF\xFF" . pack('J', $aadLen);
    }

    /**
     * Build a counter/generator block: flags || nonce || counter.
     */
    private function buildCounterBlock(bool $isMac, string $nonce, int $q, int $counter): string
    {
        $flags = ($q - 1) & 0x07; // L' field only (no Adata, no M fields)
        return chr($flags) . $nonce . str_pad(self::encodeLengthField($counter, $q), $q, "\0", STR_PAD_LEFT);
    }

    /** XOR data with CTR keystream, retaining only one block of keystream at a time. */
    private function ctrXor(string $data, string $startCounter): string
    {
        $length = strlen($data);
        $output = str_repeat("\0", $length);
        $counter = $startCounter;

        for ($offset = 0; $offset < $length; $offset += 16) {
            $chunkLength = min(16, $length - $offset);
            $keystream = $this->blockEncrypt($counter);
            for ($i = 0; $i < $chunkLength; $i++) {
                $output[$offset + $i] = $data[$offset + $i] ^ $keystream[$i];
            }
            $counter = self::incrementCounterField($counter);
        }
        return $output;
    }

    private static function incrementCounterField(string $counter): string
    {
        for ($i = 15; $i >= 16 - (ord($counter[0]) % 8 + 1); $i--) {
            $byte = ord($counter[$i]) + 1;
            $counter[$i] = chr($byte & 0xff);
            if ($byte <= 0xff) {
                break;
            }
        }

        return $counter;
    }

    /**
     * Compute raw CBC-MAC over pre-padded segments without concatenating them.
     *
     * @param list<string> $parts
     */
    private function cbcMacParts(array $parts): string
    {
        $y = str_repeat("\0", 16);
        $buffer = '';
        foreach ($parts as $part) {
            for ($offset = 0, $length = strlen($part); $offset < $length;) {
                $needed = 16 - strlen($buffer);
                $take = min($needed, $length - $offset);
                $buffer .= substr($part, $offset, $take);
                $offset += $take;
                if (strlen($buffer) === 16) {
                    $y = $this->blockEncrypt($y ^ $buffer);
                    $buffer = '';
                }
            }
        }
        assert($buffer === '');
        return $y;
    }

    private function blockEncrypt(string $block): string
    {
        $key = self::keyStore()[$this->keyHandle] ?? null;
        if (!is_string($key)) {
            throw new \LogicException('SM4-CCM key context is unavailable');
        }

        if (Sm4PurePhp::openSslSm4Available()) {
            $result = openssl_encrypt($block, 'SM4-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($result !== false) {
                return $result;
            }
        }

        if ($this->engine === null) {
            $this->engine = new Sm4PurePhp();
            $this->engine->setKeyForMode($key, Sm4::MODE_CCM);
        }
        return $this->engine->encryptBlock($block);
    }
}
