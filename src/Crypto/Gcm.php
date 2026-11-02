<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Interfaces\GcmIvTrackerInterface;
use CryptoSm\Interfaces\GcmTagLengthTrackerInterface;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use CryptoSm\SM4\Sm4PurePhp;
use CryptoSm\Utils\SensitiveContext;

/**
 * GCM (Galois/Counter Mode) implementation for SM4.
 *
 * Uses GMP for the direct bit-by-bit GF(2^128) multiplication described by
 * NIST SP 800-38D Algorithm 1.
 * The SM4 block cipher uses OpenSSL's SM4-ECB when available and falls
 * back to the library's pure-PHP SM4 block implementation otherwise.
 *
 * The direct multiplication keeps the field representation explicit and is
 * checked against the RFC 8998 vectors and an independent reference model.
 * SM4 block encryption prefers OpenSSL and falls back to the PHP implementation.
 *
 * Reference: NIST SP 800-38D / GM/T 0002-2012
 */
class Gcm
{
    use SensitiveContext;
    private const OPENSSL_GCM_CIPHER = 'sm4-gcm';
    private const INTERNAL_RANDOM_IV_PREFIX = 'SM4R';

    /** Whether PHP/OpenSSL can actually execute SM4-GCM in this process. */
    private static ?bool $openSslGcmAvailable = null;

    /** Maximum plaintext size from NIST SP 800-38D, Section 5.2.1.1. */
    public const MAX_PLAINTEXT_LENGTH_BYTES = 68719476704; // 2^36 - 32

    /** NIST SP 800-38D §8.3 per-key invocation limit for this IV policy. */
    private const MAX_INVOCATIONS_PER_KEY = PHP_INT_SIZE >= 8 ? 4294967296 : PHP_INT_MAX;

    /** Bound process-local per-key counters when no shared tracker is configured. */
    private const MAX_TRACKED_KEYS = 65536;

    /** Bound process-local GCM tag profiles by key. */
    private const MAX_TRACKED_TAG_PROFILES = 65536;

    /** Bound process-local key/IV pair history when no shared tracker is configured. */
    private const MAX_TRACKED_IV_PAIRS = 65536;

    /** @var array<string, int> Fallback process-local counts keyed by SHA-256 when no shared tracker is set */
    private static array $invocationCounts = [];

    /** @var array<string, int> */
    private static array $tagLengthByKey = [];

    /** @var array<string, array{tagLength: int, pending: int}> */
    private static array $pendingTagLengthByKey = [];

    /** @var array<string, true> */
    private static array $usedIvPairs = [];

    private static ?GcmIvTrackerInterface $ivTracker = null;

    private static bool $ivTrackingLocked = false;

    private static ?GcmTagLengthTrackerInterface $tagLengthTracker = null;

    private static bool $tagLengthTrackingLocked = false;

    /**
     * General-purpose tag lengths in bytes. NIST SP 800-38D permits 32- and
     * 64-bit tags only with Appendix C packet-size and key-lifetime limits;
     * this library cannot enforce those protocol-wide limits, so it restricts
     * support to the general-purpose 96- through 128-bit profile.
     */
    public const VALID_TAG_LENGTHS = [12, 13, 14, 15, 16];

    /** @var \WeakMap<object, array{key: string, h: ?\GMP}>|null */
    private static ?\WeakMap $secretStates = null;

    private object $secretHandle;

    private ?Sm4PurePhp $purePhpEngine = null;

    /** @return \WeakMap<object, array{key: string, h: ?\GMP}> */
    private static function secretStates(): \WeakMap
    {
        return self::$secretStates ??= new \WeakMap();
    }

    /** @return array{key: string, h: ?\GMP} */
    private function secretState(): array
    {
        $state = self::secretStates()[$this->secretHandle] ?? null;
        if ($state === null) {
            throw new \LogicException('GCM context is unavailable');
        }
        return $state;
    }

    private static function reserveTagLength(string $keyId, int $tagLength): bool
    {
        // A shared tracker is the authoritative per-key profile store. Keeping
        // a duplicate process-local entry would still fill the bounded cache
        // even when applications have configured durable shared state.
        if (self::$tagLengthTracker !== null) {
            return false;
        }

        $configured = self::$tagLengthByKey[$keyId] ?? null;
        if ($configured !== null) {
            if ($configured !== $tagLength) {
                throw new CryptoException('SM4-GCM tag length must remain fixed for each key within this process');
            }
            return false;
        }

        $pending = self::$pendingTagLengthByKey[$keyId] ?? null;
        if ($pending !== null) {
            if ($pending['tagLength'] !== $tagLength) {
                throw new CryptoException('SM4-GCM tag length must remain fixed for each key within this process');
            }
            self::$pendingTagLengthByKey[$keyId]['pending']++;
            return true;
        }

        if (count(self::$tagLengthByKey) + count(self::$pendingTagLengthByKey) >= self::MAX_TRACKED_TAG_PROFILES) {
            throw new CryptoException(
                'SM4-GCM tag profile tracker capacity reached; configure a shared GcmTagLengthTrackerInterface during bootstrap and restart this process'
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
            throw new \LogicException('SM4-GCM tag length reservation is unavailable');
        }
        if ($pending['pending'] === 1) {
            unset(self::$pendingTagLengthByKey[$keyId]);
            return;
        }
        self::$pendingTagLengthByKey[$keyId]['pending']--;
    }

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
        $this->secretHandle = new \stdClass();
        self::secretStates()[$this->secretHandle] = ['key' => $keyBin, 'h' => null];
    }

    public function __clone()
    {
        $state = $this->secretState();
        $this->secretHandle = new \stdClass();
        self::secretStates()[$this->secretHandle] = $state;
        if ($this->purePhpEngine !== null) {
            $this->purePhpEngine = clone $this->purePhpEngine;
        }
    }

    public static function fromKey(string $keyBin): self
    {
        return new self($keyBin);
    }

    /**
     * Configure shared IV uniqueness and per-key invocation tracking before
     * the first GCM encryption performed by this implementation.
     */
    public static function setIvTracker(?GcmIvTrackerInterface $tracker): void
    {
        if (self::$ivTrackingLocked && $tracker !== self::$ivTracker) {
            throw new CryptoException('GCM IV tracker cannot be changed after encryption has started');
        }
        self::$ivTracker = $tracker;
    }

    /**
     * Configure a shared fixed tag-length profile tracker before GCM has
     * accepted an encryption or authenticated a decryption for any key.
     */
    public static function setTagLengthTracker(?GcmTagLengthTrackerInterface $tracker): void
    {
        if ((self::$tagLengthTrackingLocked || self::$ivTrackingLocked) && $tracker !== self::$tagLengthTracker) {
            throw new CryptoException('GCM tag-length tracker cannot be changed after GCM processing has started');
        }

        self::$tagLengthTracker = $tracker;
    }

    /** @internal Keep the Sm4 facade's process-local IV guard enabled. */
    public static function configureFacadeIvTracking(bool $enabled): void
    {
        if (!$enabled) {
            throw new CryptoException('GCM IV reuse tracking cannot be disabled');
        }
    }

    /** @internal The facade's process-local explicit-IV guard is always enabled. */
    public static function isFacadeIvTrackingEnabled(): bool
    {
        return true;
    }

    /** @internal Reset process-local key/IV history before the first GCM encryption. */
    public static function resetFacadeIvTracking(): void
    {
        if (self::$ivTrackingLocked) {
            throw new CryptoException('GCM IV tracking history cannot be reset after encryption has started');
        }
        self::$usedIvPairs = [];
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
        $key = $this->secretState()['key'];
        if (Sm4PurePhp::openSslSm4Available()) {
            $result = openssl_encrypt($block, 'SM4-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($result !== false) {
                return $result;
            }
        }

        if ($this->purePhpEngine === null) {
            $this->purePhpEngine = new Sm4PurePhp();
            $this->purePhpEngine->setKeyForMode($key, Sm4::MODE_GCM);
        }
        return $this->purePhpEngine->encryptBlock($block);
    }

    private function getHashSubkey(): \GMP
    {
        $state = $this->secretState();
        if ($state['h'] === null) {
            $h = $this->blockEncrypt("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
            $state['h'] = self::bytesToGmp($h);
            self::secretStates()[$this->secretHandle] = $state;
        }
        return $state['h'];
    }

    /**
     * Encrypt with GCM. By default this low-level class detects duplicate key/IV
     * pairs in a bounded process-local table. Configure a shared tracker to
     * coordinate across processes and restarts.
     *
     * @return array{ciphertext: string, tag: string}
     * @throws CryptoException                        If parameters are invalid, the tracker rejects the IV, or the per-key limit is reached
     */
    public function encrypt(string $plaintext, string $iv, string $aad = '', int $tagLength = 16): array
    {
        self::rejectReservedRandomIv($iv);
        return $this->encryptInternal($plaintext, $iv, $aad, $tagLength, true);
    }

    /**
     * Encrypt a caller-materialized IV for the SM4 facade.
     *
     * @internal
     * @return array{ciphertext: string, tag: string}
     */
    public function encryptFromFacade(string $plaintext, string $iv, string $aad = '', int $tagLength = 16): array
    {
        self::rejectReservedRandomIv($iv);
        // This public bridge must not let callers disable duplicate-IV checks.
        return $this->encryptInternal($plaintext, $iv, $aad, $tagLength, true);
    }

    /**
     * Encrypt a random IV materialized by Sm4Options.
     *
     * @internal
     * @return array{ciphertext: string, tag: string}
     */
    public function encryptWithMaterializedRandomIvFromFacade(
        string $plaintext,
        Sm4Options $options,
        string $aad = '',
        int $tagLength = 16
    ): array {
        // This path skips the local explicit-IV table because the base options
        // class owns the generated nonce. A subclass could override the public
        // nonce accessors and supply a chosen IV, so only accept the class whose
        // generation and provenance checks are implemented here.
        if ($options::class !== Sm4Options::class) {
            throw new CryptoException('Generated GCM IVs require the built-in SM4 options class');
        }

        $iv = $options->consumeGeneratedGcmIvForEncryption();
        return $this->encryptInternal($plaintext, $iv, $aad, $tagLength, false);
    }

    /**
     * Encrypt using an IV generated inside the GCM implementation.
     *
     * The random IV is returned with the ciphertext so the facade can serialize
     * it. Random IVs are excluded from the explicit-IV reuse table to keep its
     * size bounded. A configured shared tracker still receives every generated
     * IV claim.
     *
     * @internal
     * @return array{iv: string, ciphertext: string, tag: string}
     */
    public function encryptWithRandomIvFromFacade(string $plaintext, string $aad = '', int $tagLength = 16): array
    {
        // Reserve a recognizable 128-bit IV namespace: four fixed bytes plus
        // 96 CSPRNG bits. Caller-supplied encryption APIs reject this namespace,
        // so returning the IV cannot create a cross-entry-point reuse bypass.
        $iv = self::INTERNAL_RANDOM_IV_PREFIX . random_bytes(12);
        $result = $this->encryptInternal($plaintext, $iv, $aad, $tagLength, false);
        return ['iv' => $iv, 'ciphertext' => $result['ciphertext'], 'tag' => $result['tag']];
    }

    private static function rejectReservedRandomIv(string $iv): void
    {
        if (self::isReservedRandomIv($iv)) {
            throw new CryptoException('GCM IV uses the reserved internally generated IV namespace');
        }
    }

    private static function isReservedRandomIv(string $iv): bool
    {
        return strlen($iv) === 16 && str_starts_with($iv, self::INTERNAL_RANDOM_IV_PREFIX);
    }

    /** @return array{ciphertext: string, tag: string} */
    private function encryptInternal(string $plaintext, string $iv, string $aad, int $tagLength, bool $trackLocalIv): array
    {
        $this->validateParams(strlen($iv), $tagLength, strlen($plaintext), strlen($aad));

        $key = $this->secretState()['key'];
        Sm4::claimEncryptionModeForKey($key, Sm4::MODE_GCM);
        $keyId = hash('sha256', $key);
        $tagLengthReserved = self::reserveTagLength($keyId, $tagLength);
        $tagLengthCommitted = false;
        try {
            $tracker = self::$ivTracker;
            if ($tracker === null) {
                if ($trackLocalIv) {
                    $pairId = hash('sha256', $key . $iv);
                    if (isset(self::$usedIvPairs[$pairId])) {
                        throw new CryptoException(
                            'GCM IV reuse detected: the same IV was used twice with the same key. Generate a fresh IV for each encryption.'
                        );
                    }
                    if (count(self::$usedIvPairs) >= self::MAX_TRACKED_IV_PAIRS) {
                        throw new CryptoException(
                            'GCM process-local IV tracking table is full (' . self::MAX_TRACKED_IV_PAIRS
                            . ' entries): configure a shared GcmIvTrackerInterface during bootstrap and restart this process'
                        );
                    }
                }

                $count = self::$invocationCounts[$keyId] ?? 0;
                if ($count >= self::MAX_INVOCATIONS_PER_KEY) {
                    throw new CryptoException(
                        'SM4-GCM per-key encryption limit reached (' . self::MAX_INVOCATIONS_PER_KEY
                        . '): rotate the key before encrypting more data'
                    );
                }

                if (!isset(self::$invocationCounts[$keyId]) && count(self::$invocationCounts) >= self::MAX_TRACKED_KEYS) {
                    throw new CryptoException(
                        'SM4-GCM process-local key tracking table is full (' . self::MAX_TRACKED_KEYS
                        . ' keys): configure a shared GcmIvTrackerInterface during bootstrap and restart this process'
                    );
                }
                // No callback occurs between the check and reservation, so a
                // cooperative fiber cannot race this process-local count.
                self::$ivTrackingLocked = true;
                self::$invocationCounts[$keyId] = $count + 1;
                if ($trackLocalIv) {
                    self::$usedIvPairs[$pairId] = true;
                }
            } else {
                // Lock the tracker configuration even when it rejects this claim:
                // replacing the tracker afterward could discard shared IV history.
                self::$ivTrackingLocked = true;
                // The shared IV tracker is external and may re-enter this API.
                self::$tagLengthTrackingLocked = true;
                if (!$tracker->claim($key, $iv)) {
                    throw new CryptoException(
                        'GCM IV reuse detected or per-key invocation limit reached: tracker rejected the claim.'
                    );
                }
            }

            // A local IV rejection leaves both tracker configurations open.
            // Once a nonce is reserved, lock before the external tag callback
            // so reentrant code cannot replace the tag-profile policy.
            self::$tagLengthTrackingLocked = true;

            // Claim a shared tag profile only after the IV claim succeeds.
            // Otherwise a reused IV could pin a profile despite failed encryption.
            if (self::$tagLengthTracker !== null && !self::$tagLengthTracker->claimTagLength($key, $tagLength)) {
                throw new CryptoException('SM4-GCM tag length must remain fixed for each key');
            }

            self::finishTagLengthReservation($keyId, $tagLength, $tagLengthReserved, true);
            $tagLengthCommitted = true;
        } finally {
            if (!$tagLengthCommitted) {
                self::finishTagLengthReservation($keyId, $tagLength, $tagLengthReserved, false);
            }
        }

        if (self::openSslGcmAvailable()) {
            $tag = '';
            $ciphertext = @openssl_encrypt(
                $plaintext,
                self::OPENSSL_GCM_CIPHER,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                $aad,
                $tagLength
            );
            $tagBytes = (string) $tag;
            if (!is_string($ciphertext) || strlen($tagBytes) !== $tagLength) {
                throw new CryptoException('SM4-GCM OpenSSL encryption failed');
            }

            return ['ciphertext' => $ciphertext, 'tag' => $tagBytes];
        }

        $hGmp = $this->getHashSubkey();

        $j0 = $this->computeJ0($iv, $hGmp);

        $ciphertext = $this->ctrEncrypt($plaintext, $j0);

        $tag = $this->computeTag($ciphertext, $aad, $j0, $hGmp, $tagLength);

        return ['ciphertext' => $ciphertext, 'tag' => $tag];
    }

    public function decrypt(string $ciphertext, string $tag, string $iv, string $aad = '', int $tagLength = 16): string
    {
        $this->validateParams(strlen($iv), $tagLength, strlen($ciphertext), strlen($aad));

        $keyId = hash('sha256', $this->secretState()['key']);
        $configuredTagLength = self::$tagLengthByKey[$keyId] ?? null;
        $tagLengthMatchesKeyProfile = $configuredTagLength === null || $configuredTagLength === $tagLength;

        if (strlen($tag) !== $tagLength) {
            throw new CryptoException('SM4-GCM: tag length mismatch');
        }
        if (!$tagLengthMatchesKeyProfile) {
            throw new CryptoException('SM4-GCM decryption failed: authentication tag mismatch');
        }

        // Authentication failure still consumes GCM block inputs (including
        // E_K(0) for GHASH), so reserve the key's mode before any cipher work.
        Sm4::assertDecryptionModeForKey($this->secretState()['key'], Sm4::MODE_GCM);

        if (self::openSslGcmAvailable()) {
            $key = $this->secretState()['key'];
            $plaintext = @openssl_decrypt(
                $ciphertext,
                self::OPENSSL_GCM_CIPHER,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                $aad
            );
            if (!is_string($plaintext)) {
                throw new CryptoException('SM4-GCM decryption failed: authentication tag mismatch');
            }

            $this->commitTagLengthProfile($keyId, $tagLength);
            return $plaintext;
        }

        $hGmp = $this->getHashSubkey();

        $j0 = $this->computeJ0($iv, $hGmp);

        $computedTag = $this->computeTag($ciphertext, $aad, $j0, $hGmp, $tagLength);
        $tagMatches = hash_equals($tag, $computedTag);

        if (!$tagMatches) {
            throw new CryptoException('SM4-GCM decryption failed: authentication tag mismatch');
        }

        $this->commitTagLengthProfile($keyId, $tagLength);
        return $this->ctrEncrypt($ciphertext, $j0);
    }

    /** Fix the local tag profile after a successful authenticated decryption. */
    private function commitTagLengthProfile(string $keyId, int $tagLength): void
    {
        self::$tagLengthTrackingLocked = true;
        $reserved = self::reserveTagLength($keyId, $tagLength);
        $committed = false;
        try {
            $key = $this->secretState()['key'];
            if (self::$tagLengthTracker !== null && !self::$tagLengthTracker->claimTagLength($key, $tagLength)) {
                throw new CryptoException('SM4-GCM decryption failed: authentication tag mismatch');
            }
            self::finishTagLengthReservation($keyId, $tagLength, $reserved, true);
            $committed = true;
        } finally {
            if (!$committed) {
                self::finishTagLengthReservation($keyId, $tagLength, $reserved, false);
            }
        }
    }

    /**
     * Probe the operation itself rather than trusting openssl_get_cipher_methods(),
     * which can list aliases that the active provider cannot execute.
     */
    private static function openSslGcmAvailable(): bool
    {
        if (self::$openSslGcmAvailable !== null) {
            return self::$openSslGcmAvailable;
        }
        if (!function_exists('openssl_encrypt')) {
            return self::$openSslGcmAvailable = false;
        }

        $tag = '';
        $probe = @openssl_encrypt(
            '',
            self::OPENSSL_GCM_CIPHER,
            str_repeat("\0", 16),
            OPENSSL_RAW_DATA,
            str_repeat("\0", 12),
            $tag,
            '',
            16
        );

        return self::$openSslGcmAvailable = is_string($probe);
    }

    private function validateParams(int $ivLength, int $tagLength, int $dataLength, int $aadLength): void
    {
        if ($ivLength === 0) {
            throw new CryptoException('SM4-GCM: IV must not be empty');
        }
        if ($ivLength > intdiv(PHP_INT_MAX, 8)) {
            throw new CryptoException('SM4-GCM: IV exceeds the supported bit-length range');
        }
        if ($dataLength > intdiv(PHP_INT_MAX, 8)) {
            throw new CryptoException('SM4-GCM: plaintext/ciphertext exceeds the supported bit-length range');
        }
        if ($dataLength > self::MAX_PLAINTEXT_LENGTH_BYTES) {
            throw new CryptoException('SM4-GCM: plaintext/ciphertext exceeds the NIST maximum length');
        }
        if ($aadLength > intdiv(PHP_INT_MAX, 8)) {
            throw new CryptoException('SM4-GCM: AAD exceeds the supported bit-length range');
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
        $ivPadding = str_repeat("\x00", (16 - strlen($iv) % 16) % 16);
        $lenBlock = self::encodeUint64(0) . self::encodeUint64($lenBits);
        $yGmp = $this->ghashParts([$iv, $ivPadding, $lenBlock], $hGmp);

        return self::gmpToBytes($yGmp);
    }

    private function ctrEncrypt(string $data, string $j0): string
    {
        if ($data === '') {
            return '';
        }

        $dataLen = strlen($data);
        $result = str_repeat("\0", $dataLen);
        $counter = self::inc32($j0);
        for ($offset = 0; $offset < $dataLen; $offset += 16) {
            $chunkLen = min(16, $dataLen - $offset);
            $keyStream = $this->blockEncrypt($counter);
            for ($i = 0; $i < $chunkLen; $i++) {
                $result[$offset + $i] = $data[$offset + $i] ^ $keyStream[$i];
            }
            $counter = self::inc32($counter);
        }

        return $result;
    }

    private function computeTag(string $ciphertext, string $aad, string $j0, \GMP $hGmp, int $tagLength): string
    {
        $aadLen = strlen($aad);
        $ctLen = strlen($ciphertext);

        $aadPadding = str_repeat("\x00", (16 - $aadLen % 16) % 16);
        $ctPadding = str_repeat("\x00", (16 - $ctLen % 16) % 16);

        $lenBlock = self::encodeUint64($aadLen * 8) . self::encodeUint64($ctLen * 8);
        $yGmp = $this->ghashParts([$aad, $aadPadding, $ciphertext, $ctPadding, $lenBlock], $hGmp);

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
     * GHASH_H over block-aligned input segments, without concatenating them.
     * Callers provide padding so the final block buffer is empty.
     *
     * @param list<string> $parts
     */
    private function ghashParts(array $parts, \GMP $hGmp): \GMP
    {
        $y = gmp_init(0);
        $buffer = '';

        foreach ($parts as $part) {
            for ($offset = 0, $partLen = strlen($part); $offset < $partLen;) {
                $take = min(16 - strlen($buffer), $partLen - $offset);
                $buffer .= substr($part, $offset, $take);
                $offset += $take;
                if (strlen($buffer) === 16) {
                    $blockInt = gmp_import($buffer);
                    $y = self::gmul($y ^ $blockInt, $hGmp);
                    $buffer = '';
                }
            }
        }

        assert($buffer === '');
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
        // str_pad 至 32 个 hex 字符后 hex2bin 恒成功且恰为 16 字节
        $raw = (string) hex2bin($hex);
        if (strlen($raw) > 16) {
            $raw = substr($raw, -16);
        } elseif (strlen($raw) < 16) {
            $raw = str_repeat("\x00", 16 - strlen($raw)) . $raw;
        }
        return $raw;
    }

    private static function encodeUint64(int $value): string
    {
        if (PHP_INT_SIZE < 8) {
            // 64-bit pack formats are unavailable on 32-bit PHP builds. Every
            // representable non-negative length fits in the low word there.
            return pack('N2', 0, $value);
        }

        return pack('N2', intdiv($value, 0x100000000), $value & 0xFFFFFFFF);
    }
}
