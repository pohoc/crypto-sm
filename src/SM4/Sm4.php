<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

use CryptoSm\Crypto\Gcm;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Interfaces\CipherInterface;
use CryptoSm\Interfaces\GcmIvTrackerInterface;
use CryptoSm\Interfaces\GcmTagLengthTrackerInterface;
use CryptoSm\Interfaces\Sm4CtrCounterTrackerInterface;
use CryptoSm\Interfaces\Sm4FeedbackIvTrackerInterface;
use CryptoSm\Interfaces\Sm4KeyModeTrackerInterface;
use CryptoSm\Interfaces\Sm4StreamBlockTrackerInterface;

/**
 * SM4 block cipher implementation (GM/T 0002-2012).
 *
 * Supports ECB, CBC, CFB, OFB, CTR, and GCM modes with configurable padding.
 * GCM is the default mode and provides authenticated encryption (AEAD).
 * CBC remains available for compatibility and does not authenticate ciphertext.
 */
class Sm4 implements CipherInterface
{
    private const SELF_CONTAINED_GCM_MARKER_V1 = '534d3447434d31'; // "SM4GCM1", legacy 12-byte IV
    private const SELF_CONTAINED_GCM_MARKER_V2 = '534d3447434d32'; // "SM4GCM2", reserved 16-byte IV
    /**
     * @var string Electronic Codebook mode
     * @deprecated ECB mode does not provide data confidentiality for repeated patterns. Use CBC or GCM instead.
     */
    public const MODE_ECB = 'ecb';

    /** @var string Cipher Block Chaining compatibility mode (not the default; no integrity protection) */
    public const MODE_CBC = 'cbc';

    /** @var string Cipher Feedback mode (stream-like, no padding needed) */
    public const MODE_CFB = 'cfb';

    /** @var string Output Feedback mode (stream-like, no padding needed) */
    public const MODE_OFB = 'ofb';

    /** @var string Counter mode (stream-like, no padding needed) */
    public const MODE_CTR = 'ctr';

    /** @var string Galois/Counter mode (authenticated encryption) */
    public const MODE_GCM = 'gcm';

    /** @internal CCM is implemented by a separate authenticated-encryption construction. */
    public const MODE_CCM = 'ccm';

    /** @var array<int,string> Modes that don't require padding (stream-like) */
    private const STREAM_MODES = [self::MODE_CFB, self::MODE_OFB, self::MODE_CTR, self::MODE_GCM];

    private const MAX_TRACKED_STREAM_BLOCK_RANGES = 65536;

    private const MAX_TRACKED_CBC_IV_PAIRS = 65536;

    private const MAX_TRACKED_CIPHER_MODE_KEYS = 65536;

    /** @var array<string, int> AVL tree roots keyed by the SM4 key fingerprint */
    private static array $ctrCounterRangeRoots = [];

    /** @var array<int, array{start: string, end: string, left: int|null, right: int|null, height: int}> */
    private static array $ctrCounterRangeNodes = [];

    private static int $trackedCtrCounterRangeCount = 0;

    private static ?Sm4CtrCounterTrackerInterface $ctrCounterTracker = null;

    private static bool $ctrCounterTrackingLocked = false;

    private static ?Sm4FeedbackIvTrackerInterface $feedbackIvTracker = null;

    private static bool $feedbackIvTrackingLocked = false;

    /** @var array<string, true> CBC key/IV pairs used in this process. */
    private static array $usedCbcIvPairs = [];

    private static ?Sm4StreamBlockTrackerInterface $streamBlockTracker = null;

    private static bool $streamBlockTrackingLocked = false;

    /** @var array<string, string> One cipher mode per key within this process. */
    private static array $cipherModeByKey = [];

    /** @var array<string, array{mode: string, pending: int}> */
    private static array $pendingCipherModeByKey = [];

    private static ?Sm4KeyModeTrackerInterface $keyModeTracker = null;

    private static bool $keyModeTrackingLocked = false;

    /**
     * Encrypt data using SM4.
     *
     * @param  string              $data    Plaintext data to encrypt
     * @param  string              $key     32-character hex string (128-bit key)
     * @param  mixed               $options Sm4Options instance or null for defaults
     * @return string              Hex-encoded ciphertext; when options are null, returns a self-contained authenticated GCM payload
     * @throws InvalidKeyException If key or options are invalid
     * @throws CryptoException     If encryption fails
     */
    public static function encrypt(string $data, string $key, mixed $options = null): string
    {
        if ($options !== null && !$options instanceof Sm4Options) {
            throw new InvalidKeyException('SM4 options must be an instance of Sm4Options');
        }
        return self::crypt($data, $key, true, $options, $options === null);
    }

    /**
     * Decrypt data using SM4.
     *
     * @param  string              $data    Hex-encoded ciphertext; when options are null, expects a self-contained authenticated GCM payload
     * @param  string              $key     32-character hex string (128-bit key)
     * @param  mixed               $options Sm4Options instance or null for defaults
     * @return string              Decrypted plaintext
     * @throws InvalidKeyException If key, ciphertext, or options are invalid
     * @throws CryptoException     If decryption fails
     */
    public static function decrypt(string $data, string $key, mixed $options = null): string
    {
        if ($options !== null && !$options instanceof Sm4Options) {
            throw new InvalidKeyException('SM4 options must be an instance of Sm4Options');
        }
        return self::crypt($data, $key, false, $options, $options === null);
    }

    /** Decrypt the legacy IV || CBC ciphertext format. This format is unauthenticated. */
    public static function decryptLegacyCbc(string $data, string $key): string
    {
        if (!preg_match('/\A[0-9a-fA-F]+\z/', $data) || strlen($data) < 64 || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid self-contained CBC ciphertext');
        }
        $options = (new Sm4Options())->setMode(self::MODE_CBC)->setIv(substr($data, 0, 32));
        return self::decrypt(substr($data, 32), $key, $options);
    }

    /**
     * Encrypt data into a structured self-contained payload.
     *
     * This API always generates a fresh IV for IV-based modes and stores the
     * IV/tag metadata beside the ciphertext, preventing the common mistake of
     * losing or reusing IVs when using explicit Sm4Options.
     *
     * @return array{version: int, algorithm: string, mode: string, ciphertext: string, padding?: string, iv?: string, aad?: string, tagLength?: int, tag?: string}
     */
    public static function encryptPayload(string $data, string $key, ?Sm4Options $options = null): array
    {
        // The structured API is the safe default for new callers: use AEAD
        // unless a mode is explicitly selected for compatibility.
        $options = $options === null
            ? (new Sm4Options())->setMode(self::MODE_GCM)
            : clone $options;
        $mode = strtolower($options->getMode());

        if ($mode !== self::MODE_ECB) {
            $options->resetIv();
        }

        $payload = [
            'version' => 1,
            'algorithm' => 'SM4',
            'mode' => $mode,
        ];

        if ($mode === self::MODE_GCM) {
            $encrypted = self::encrypt($data, $key, $options);
            $tagLength = $options->getTagLength();
            $tagHexLength = $tagLength * 2;

            $payload['iv'] = $options->getIv();
            $payload['aad'] = bin2hex($options->getAad());
            $payload['tagLength'] = $tagLength;
            $payload['ciphertext'] = substr($encrypted, 0, -$tagHexLength);
            $payload['tag'] = substr($encrypted, -$tagHexLength);

            return $payload;
        }

        $padding = strtolower($options->getPadding());
        if ($padding === 'zero') {
            throw new InvalidKeyException('Zero padding is ambiguous and is not supported by encryptPayload(); use pkcs5/pkcs7 or the legacy encrypt() API');
        }

        if ($mode !== self::MODE_ECB) {
            $payload['iv'] = $options->getIv();
        }
        $payload['padding'] = $padding;
        $payload['ciphertext'] = self::encrypt($data, $key, $options);

        return $payload;
    }

    /**
     * Decrypt a structured SM4 payload produced by encryptPayload().
     * The expected mode must come from trusted application configuration, not the payload.
     *
     * @param array<string, mixed> $payload
     * @param string               $expectedPadding Trusted padding policy for non-GCM payloads
     */
    public static function decryptPayload(array $payload, string $key, string $expectedMode = self::MODE_GCM, int $expectedTagLength = 16, string $expectedAad = '', string $expectedPadding = 'pkcs5'): string
    {
        $version = self::payloadInt($payload, 'version');
        $algorithm = self::payloadString($payload, 'algorithm');
        $mode = strtolower(self::payloadString($payload, 'mode'));

        if ($version !== 1 || strtoupper($algorithm) !== 'SM4') {
            throw new InvalidKeyException('Unsupported SM4 payload');
        }

        // Reject unknown payload modes without triggering mode-specific
        // configuration side effects such as deprecation notices for ECB.
        $validModes = [self::MODE_ECB, self::MODE_CBC, self::MODE_CFB, self::MODE_OFB, self::MODE_CTR, self::MODE_GCM];
        if (!in_array($mode, $validModes, true)) {
            throw new InvalidKeyException('Unsupported SM4 payload mode: ' . $mode);
        }

        if ($mode !== strtolower($expectedMode)) {
            throw new InvalidKeyException('SM4 payload mode does not match expected mode');
        }

        $options = (new Sm4Options())->setMode($mode);

        if ($mode === self::MODE_GCM) {
            $iv = self::payloadString($payload, 'iv');
            self::validatePayloadHex($iv, 'IV', false);
            $options->setIv($iv);

            $tagLength = self::payloadInt($payload, 'tagLength');
            if ($tagLength !== $expectedTagLength) {
                throw new InvalidKeyException('SM4 payload tag length does not match expected length');
            }
            $options->setTagLength($tagLength);

            $aadHex = self::payloadString($payload, 'aad');
            self::validatePayloadHex($aadHex, 'AAD', true);
            $aad = $aadHex === '' ? '' : hex2bin($aadHex);
            if ($aad === false) {
                throw new InvalidKeyException('Invalid SM4 payload AAD hex');
            }
            if (!hash_equals($expectedAad, $aad)) {
                throw new InvalidKeyException('SM4 payload AAD does not match expected context');
            }
            $options->setAad($aad);

            $ciphertext = self::payloadString($payload, 'ciphertext');
            $tag = self::payloadString($payload, 'tag');
            self::validatePayloadHex($ciphertext, 'ciphertext', true);
            self::validatePayloadHex($tag, 'tag', false);
            if (strlen($tag) !== $tagLength * 2) {
                throw new InvalidKeyException('SM4 payload tag length mismatch');
            }

            return self::decrypt($ciphertext . $tag, $key, $options);
        }

        if ($mode !== self::MODE_ECB) {
            $iv = self::payloadString($payload, 'iv');
            self::validatePayloadHex($iv, 'IV', false);
            $options->setIv($iv);
        }

        $padding = strtolower(self::payloadString($payload, 'padding'));
        if ($padding === 'zero') {
            throw new InvalidKeyException('Zero padding is ambiguous and is not supported by decryptPayload()');
        }
        if ($padding === 'iso10126') {
            throw new InvalidKeyException('ISO 10126 padding is unverifiable and is not supported by decryptPayload()');
        }
        if ($padding !== strtolower($expectedPadding)) {
            throw new InvalidKeyException('SM4 payload padding does not match expected padding');
        }
        $options->setPadding($expectedPadding);

        $ciphertext = self::payloadString($payload, 'ciphertext');
        self::validatePayloadHex($ciphertext, 'ciphertext', true);

        return self::decrypt($ciphertext, $key, $options);
    }

    /**
     * Check whether the OpenSSL extension provides SM4 cipher support.
     * Result is cached per process (see Sm4PurePhp::openSslSm4Available()).
     */
    public static function openSslSm4Available(): bool
    {
        return Sm4PurePhp::openSslSm4Available();
    }

    private static function crypt(string $data, string $key, bool $encrypt, ?Sm4Options $options = null, bool $selfContainedDefault = false): string
    {
        $options ??= new Sm4Options();

        if ($selfContainedDefault && !$encrypt) {
            $markerLength = strlen(self::SELF_CONTAINED_GCM_MARKER_V2);
            if (strncasecmp($data, self::SELF_CONTAINED_GCM_MARKER_V2, $markerLength) === 0) {
                $ivHexLength = 32;
            } elseif (strncasecmp($data, self::SELF_CONTAINED_GCM_MARKER_V1, $markerLength) === 0) {
                $ivHexLength = 24;
            } else {
                $ivHexLength = 0;
            }
            $headerLength = $markerLength + $ivHexLength;
            if ($ivHexLength === 0 || strlen($data) < $headerLength + 32 || strlen($data) % 2 !== 0) {
                throw new InvalidKeyException('Invalid self-contained GCM ciphertext');
            }
            $options->setMode(self::MODE_GCM);
            $options->setIv(substr($data, $markerLength, $ivHexLength));
            $data = substr($data, $headerLength);
        }

        $mode = strtolower($options->getMode());
        $padding = strtolower($options->getPadding());

        self::validateHexKey($key);

        // Decryption requires a concrete IV: lazily generating a random one here
        // would silently produce garbage plaintext, so reject missing IVs instead.
        // Self-contained formats extract their IV before reaching this guard.
        if (!$encrypt && $mode !== self::MODE_ECB && !$options->hasIv()
            && !$selfContainedDefault) {
            throw new InvalidKeyException(
                'IV is required for SM4 ' . strtoupper($mode)
                . ' decryption: pass the same IV used during encryption via Sm4Options::setIv(),'
                . ' or omit options to use the self-contained iv+ciphertext format'
            );
        }

        if ($mode === self::MODE_GCM) {
            if ($encrypt && !$options->hasExplicitIv()) {
                // Keep an IV materialized by getIv() for the first operation,
                // then refresh it when a generated options object is reused.
                $options->prepareIvForEncryption();
            }
            $result = self::cryptGcm($data, $key, $encrypt, $options);
            if ($selfContainedDefault && $encrypt) {
                return self::SELF_CONTAINED_GCM_MARKER_V2 . $options->getIv() . $result;
            }
            return $result;
        }

        // Validate mode
        $validModes = [self::MODE_ECB, self::MODE_CBC, self::MODE_CFB, self::MODE_OFB, self::MODE_CTR];
        if (!in_array($mode, $validModes, true)) {
            throw new InvalidKeyException('Unsupported SM4 mode: ' . $mode);
        }

        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }

        if ($encrypt && $mode !== self::MODE_ECB) {
            $options->prepareIvForEncryption();
            $options->markIvUsedForEncryption();
        }

        if ($mode !== self::MODE_ECB) {
            self::validateHexKey($options->getIv(), 'IV');
        }

        if (!$encrypt && $data !== '') {
            self::validateCiphertextFormat($data, in_array($mode, [self::MODE_ECB, self::MODE_CBC], true));
        }

        if ($mode === self::MODE_CTR) {
            $iv = $options->getIv();
            $ivBin = hex2bin($iv);
            if ($ivBin === false) {
                throw new InvalidKeyException('Invalid IV hex');
            }

            $inputLength = $encrypt ? strlen($data) : intdiv(strlen($data), 2);
            self::validateCtrCounterRange($ivBin, $inputLength);
            if ($encrypt) {
                $blockCount = self::ctrCounterBlockCount($inputLength);
                if ($blockCount > 0) {
                    self::claimStreamBlockRange($keyBin, $ivBin, $blockCount, self::MODE_CTR);
                }
            }
        }

        if ($encrypt && strlen($data) > 0 && in_array($mode, [self::MODE_CFB, self::MODE_OFB], true)) {
            $ivBin = hex2bin($options->getIv());
            if ($ivBin === false) {
                throw new InvalidKeyException('Invalid IV hex');
            }
            self::claimFeedbackBlockInputs($keyBin, $ivBin, $data, $mode);
        }

        if ($encrypt && in_array($mode, [self::MODE_ECB, self::MODE_CBC], true)
            && ($padding !== 'none' || ($data !== '' && strlen($data) % 16 === 0))) {
            self::claimEncryptionModeForKey($keyBin, $mode);
        }

        if ($encrypt && $mode === self::MODE_CBC
            && ($padding !== 'none' || ($data !== '' && strlen($data) % 16 === 0))) {
            $ivBin = hex2bin($options->getIv());
            if ($ivBin === false) {
                throw new InvalidKeyException('Invalid IV hex');
            }
            self::claimCbcIv($keyBin, $ivBin);
        }

        if (!$encrypt && $data !== '') {
            self::assertDecryptionModeForKey($keyBin, $mode);
        }

        // Probe the selected mode itself: providers can expose SM4-ECB while
        // omitting or disabling CBC/CFB/OFB/CTR.
        if (self::openSslModeAvailable($mode)) {
            $result = self::cryptOpenSsl($data, $keyBin, $encrypt, $mode, $padding, $options);
        } else {
            $result = self::cryptPurePhp($data, $keyBin, $encrypt, $mode, $padding, $options);
        }

        return $result;
    }

    private static function openSslModeAvailable(string $mode): bool
    {
        if (isset(self::$openSslModeAvailability[$mode])) {
            return self::$openSslModeAvailability[$mode];
        }
        if (!self::openSslSm4Available()) {
            return self::$openSslModeAvailability[$mode] = false;
        }

        $cipher = self::getOpenSSLMethodName($mode);
        $plaintext = str_repeat("\0", 16);
        $key = str_repeat("\0", 16);
        $iv = $mode === self::MODE_ECB ? '' : str_repeat("\0", 16);
        $ciphertext = @openssl_encrypt(
            $plaintext,
            $cipher,
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        if (!is_string($ciphertext) || strlen($ciphertext) !== 16) {
            return self::$openSslModeAvailability[$mode] = false;
        }

        $roundTrip = @openssl_decrypt(
            $ciphertext,
            $cipher,
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        return self::$openSslModeAvailability[$mode] = is_string($roundTrip)
            && hash_equals($plaintext, $roundTrip);
    }

    /**
     * Encrypt/decrypt using OpenSSL.
     */
    /** 平台分支：需要原生 OpenSSL SM4-ECB；不可用时走纯 PHP 回退。 */
    private static function cryptOpenSsl(string $data, string $keyBin, bool $encrypt, string $mode, string $padding, Sm4Options $options): string
    {
        $opensslCipher = self::getOpenSSLMethodName($mode);
        $isStreamMode = in_array($mode, self::STREAM_MODES, true);
        $needsIv = $mode !== self::MODE_ECB;

        $ivBin = '';
        if ($needsIv) {
            $iv = $options->getIv();
            self::validateHexKey($iv, 'IV');
            $ivBin = hex2bin($iv);
            if ($ivBin === false) {
                throw new InvalidKeyException('Invalid IV hex');
            }
        }

        if ($encrypt) {
            $input = $isStreamMode ? $data : self::maybePad($data, $padding);
            $cipher = openssl_encrypt(
                $input,
                $opensslCipher,
                $keyBin,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $needsIv ? $ivBin : ''
            );
            if ($cipher === false) {
                throw new CryptoException('SM4 encryption failed: ' . openssl_error_string());
            }
            return bin2hex($cipher);
        }

        // Decrypt
        if (($data !== '' && !preg_match('/\A[0-9a-fA-F]+\z/', $data)) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = $data === '' ? '' : hex2bin($data);
        if ($cipher === false) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        if (!$isStreamMode && strlen($cipher) % 16 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length not multiple of block size');
        }

        $plain = openssl_decrypt(
            $cipher,
            $opensslCipher,
            $keyBin,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $needsIv ? $ivBin : ''
        );
        if ($plain === false) {
            throw new CryptoException('SM4 decryption failed: ' . openssl_error_string());
        }

        return $isStreamMode ? $plain : self::maybeUnpad($plain, $padding);
    }

    /**
     * Encrypt/decrypt ECB using the pure PHP SM4 block engine.
     */
    private static function cryptEcbPurePhp(string $data, string $keyBin, bool $encrypt, string $padding): string
    {
        $engine = new Sm4PurePhp();
        $engine->setKeyForMode($keyBin, self::MODE_ECB);

        if ($encrypt) {
            $input = self::maybePad($data, $padding);
            $result = '';
            for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
                $result .= $engine->encryptBlock(substr($input, $i, 16));
            }
            return bin2hex($result);
        }

        // Decrypt
        if (($data !== '' && !preg_match('/\A[0-9a-fA-F]+\z/', $data)) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = $data === '' ? '' : hex2bin($data);
        if ($cipher === false) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        if (strlen($cipher) % 16 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length not multiple of block size');
        }

        $result = '';
        for ($i = 0, $len = strlen($cipher); $i < $len; $i += 16) {
            $result .= $engine->decryptBlock(substr($cipher, $i, 16));
        }

        return self::maybeUnpad($result, $padding);
    }

    private static function cryptPurePhp(string $data, string $keyBin, bool $encrypt, string $mode, string $padding, Sm4Options $options): string
    {
        if ($mode === self::MODE_ECB) {
            return self::cryptEcbPurePhp($data, $keyBin, $encrypt, $padding);
        }

        $iv = $options->getIv();
        self::validateHexKey($iv, 'IV');
        $ivBin = hex2bin($iv);
        if ($ivBin === false) {
            throw new InvalidKeyException('Invalid IV hex');
        }

        $engine = new Sm4PurePhp();
        $engine->setKeyForMode($keyBin, $mode);

        return match ($mode) {
            self::MODE_CBC => self::cryptCbcPurePhp($engine, $data, $encrypt, $padding, $ivBin),
            self::MODE_CFB => self::cryptCfbPurePhp($engine, $data, $encrypt, $ivBin),
            self::MODE_OFB => self::cryptOfbPurePhp($engine, $data, $encrypt, $ivBin),
            self::MODE_CTR => self::cryptCtrPurePhp($engine, $data, $encrypt, $ivBin),
            default => throw new InvalidKeyException('Unsupported SM4 mode: ' . $mode),
        };
    }

    private static function cryptCbcPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $padding, string $ivBin): string
    {
        if ($encrypt) {
            $input = self::maybePad($data, $padding);
            $result = '';
            $previous = $ivBin;
            for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
                $block = substr($input, $i, 16) ^ $previous;
                $previous = $engine->encryptBlock($block);
                $result .= $previous;
            }
            return bin2hex($result);
        }

        $cipher = self::decodeBlockCiphertext($data);
        $result = '';
        $previous = $ivBin;
        for ($i = 0, $len = strlen($cipher); $i < $len; $i += 16) {
            $block = substr($cipher, $i, 16);
            $result .= $engine->decryptBlock($block) ^ $previous;
            $previous = $block;
        }

        return self::maybeUnpad($result, $padding);
    }

    private static function cryptCfbPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $ivBin): string
    {
        $input = $encrypt ? $data : self::decodeStreamCiphertext($data);
        $result = '';
        $feedback = $ivBin;
        for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
            $chunk = substr($input, $i, 16);
            $keyStream = $engine->encryptBlock($feedback);
            $out = $chunk ^ substr($keyStream, 0, strlen($chunk));
            $result .= $out;
            $feedback = $encrypt
                ? str_pad($out, 16, "\0")
                : str_pad($chunk, 16, "\0");
        }

        return $encrypt ? bin2hex($result) : $result;
    }

    private static function cryptOfbPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $ivBin): string
    {
        $input = $encrypt ? $data : self::decodeStreamCiphertext($data);
        $result = '';
        $feedback = $ivBin;
        for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
            $feedback = $engine->encryptBlock($feedback);
            $chunk = substr($input, $i, 16);
            $result .= $chunk ^ substr($feedback, 0, strlen($chunk));
        }

        return $encrypt ? bin2hex($result) : $result;
    }

    private static function cryptCtrPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $ivBin): string
    {
        $input = $encrypt ? $data : self::decodeStreamCiphertext($data);
        $result = '';
        $counter = $ivBin;
        for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
            $keyStream = $engine->encryptBlock($counter);
            $chunk = substr($input, $i, 16);
            $result .= $chunk ^ substr($keyStream, 0, strlen($chunk));
            $counter = self::incrementCounter($counter);
        }

        return $encrypt ? bin2hex($result) : $result;
    }

    private static function validateCiphertextFormat(string $data, bool $requiresBlockAlignment): void
    {
        if (!preg_match('/\A[0-9a-fA-F]+\z/', $data) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        if ($requiresBlockAlignment && strlen($data) % 32 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length not multiple of block size');
        }
    }

    private static function decodeBlockCiphertext(string $data): string
    {
        $cipher = self::decodeStreamCiphertext($data);
        if (strlen($cipher) % 16 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length not multiple of block size');
        }
        return $cipher;
    }

    private static function decodeStreamCiphertext(string $data): string
    {
        if ($data === '') {
            return '';
        }
        if (!preg_match('/\A[0-9a-fA-F]+\z/', $data) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = hex2bin($data);
        if ($cipher === false) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        return $cipher;
    }

    private static function incrementCounter(string $counter): string
    {
        $c = $counter;
        for ($i = 15; $i >= 0; $i--) {
            $byte = ord($c[$i]) + 1;
            $c[$i] = chr($byte & 0xFF);
            if ($byte <= 0xFF) {
                break;
            }
        }
        return $c;
    }

    private static function validateCtrCounterRange(string $counter, int $dataLength): void
    {
        $blocks = self::ctrCounterBlockCount($dataLength);
        $increments = $blocks - 1;

        for ($i = 15; $i >= 0 && $increments > 0; --$i) {
            $sum = ord($counter[$i]) + ($increments & 0xff);
            $increments = intdiv($increments, 256) + ($sum >> 8);
        }

        if ($increments > 0) {
            throw new InvalidKeyException('SM4-CTR counter would wrap for this data length');
        }
    }

    private static function ctrCounterBlockCount(int $dataLength): int
    {
        return intdiv($dataLength, 16) + ($dataLength % 16 === 0 ? 0 : 1);
    }

    /**
     * Configure a shared atomic tracker before the first CTR encryption.
     * The tracker must reject intersecting counter ranges across processes and
     * restarts for each SM4 key.
     */
    public static function setCtrCounterTracker(?Sm4CtrCounterTrackerInterface $tracker): void
    {
        if (self::$ctrCounterTrackingLocked && $tracker !== self::$ctrCounterTracker) {
            throw new CryptoException('SM4-CTR counter tracker cannot be changed after encryption has started');
        }

        self::$ctrCounterTracker = $tracker;
    }

    /**
     * Configure a shared atomic IV tracker for CBC, CFB, and OFB encryption.
     * The tracker must persist each key/IV claim across workers and restarts.
     */
    public static function setFeedbackIvTracker(?Sm4FeedbackIvTrackerInterface $tracker): void
    {
        if (self::$feedbackIvTrackingLocked && $tracker !== self::$feedbackIvTracker) {
            throw new CryptoException('SM4 CBC/CFB/OFB IV tracker cannot be changed after encryption has started');
        }

        self::$feedbackIvTracker = $tracker;
    }

    /** Claim a CBC key/IV pair before encryption. */
    private static function claimCbcIv(string $key, string $iv): void
    {
        self::$feedbackIvTrackingLocked = true;
        $tracker = self::$feedbackIvTracker;
        if ($tracker !== null) {
            if (!$tracker->claim($key, $iv)) {
                throw new CryptoException('SM4-CBC IV reuse detected or tracker rejected the claim');
            }
            return;
        }

        $pairId = hash('sha256', $key . $iv);
        if (isset(self::$usedCbcIvPairs[$pairId])) {
            throw new CryptoException('SM4-CBC IV reuse detected for this key');
        }
        if (count(self::$usedCbcIvPairs) >= self::MAX_TRACKED_CBC_IV_PAIRS) {
            throw new CryptoException(
                'SM4-CBC process-local IV tracking table is full (' . self::MAX_TRACKED_CBC_IV_PAIRS
                . ' entries); configure a shared Sm4FeedbackIvTrackerInterface during bootstrap and restart this process'
            );
        }
        self::$usedCbcIvPairs[$pairId] = true;
    }

    /**
     * Configure one shared atomic tracker for CTR, CFB, and OFB block inputs.
     * This is required to prevent cross-mode block-input reuse across workers
     * or process restarts. It supersedes the mode-specific shared trackers.
     */
    public static function setStreamBlockTracker(?Sm4StreamBlockTrackerInterface $tracker): void
    {
        if (self::$streamBlockTrackingLocked && $tracker !== self::$streamBlockTracker) {
            throw new CryptoException('SM4 stream-block tracker cannot be changed after encryption has started');
        }

        self::$streamBlockTracker = $tracker;
    }

    /**
     * Configure a shared atomic key-to-mode registry before any SM4 operation.
     * This is required to enforce mode separation across workers and restarts.
     */
    public static function setKeyModeTracker(?Sm4KeyModeTrackerInterface $tracker): void
    {
        if (self::$keyModeTrackingLocked && $tracker !== self::$keyModeTracker) {
            throw new CryptoException('SM4 key-mode tracker cannot be changed after cipher operations have started');
        }

        self::$keyModeTracker = $tracker;
    }

    /**
     * Register a key's mode from trusted key-provisioning code.
     *
     * Decryption never creates a shared key-mode record. Keys that are only
     * used to decrypt existing data must be registered before the first
     * decryption attempt.
     */
    public static function registerKeyMode(string $keyHex, string $mode): void
    {
        if (!preg_match('/\A[0-9a-fA-F]{32}\z/', $keyHex)) {
            throw new InvalidKeyException('SM4 key must be 32 hexadecimal characters');
        }
        if (!in_array(
            $mode,
            [self::MODE_ECB, self::MODE_CBC, self::MODE_GCM, self::MODE_CTR, self::MODE_CFB, self::MODE_OFB, self::MODE_CCM, 'raw-block'],
            true
        )) {
            throw new InvalidKeyException('Unsupported SM4 key mode: ' . $mode);
        }
        if (self::$keyModeTracker === null) {
            throw new CryptoException('Configure a shared SM4 key-mode tracker before registering keys');
        }

        $key = hex2bin($keyHex);
        if ($key === false) {
            throw new InvalidKeyException('Invalid SM4 key hex');
        }
        self::$keyModeTrackingLocked = true;
        if (!self::$keyModeTracker->claimMode(hash('sha256', $key, true), $mode)) {
            throw new CryptoException('SM4 key-mode tracker rejected this key and mode');
        }
    }

    private static function claimStreamBlockRange(
        string $key,
        string $initialBlock,
        int $blockCount,
        string $mode,
        bool $claimLegacyFeedbackIv = true
    ): void {
        self::$streamBlockTrackingLocked = true;
        self::$ctrCounterTrackingLocked = true;
        self::$feedbackIvTrackingLocked = true;
        self::claimEncryptionModeForKey($key, $mode);
        $keyId = hash('sha256', $key);
        $tracker = self::$streamBlockTracker;
        if ($tracker !== null) {
            if (!$tracker->claimRange($key, $initialBlock, $blockCount)) {
                throw new CryptoException('SM4 stream block input reuse detected or tracker rejected the claim');
            }
            return;
        }

        if ($mode === self::MODE_CTR && self::$ctrCounterTracker !== null) {
            if (!self::$ctrCounterTracker->claimRange($key, $initialBlock, $blockCount)) {
                throw new CryptoException('SM4-CTR counter range reuse detected or tracker rejected the claim');
            }
            // The dedicated tracker owns CTR range history across processes
            // and restarts. Retaining the same ranges locally would still hit
            // the bounded fallback table and reject valid claims eventually.
            return;
        } elseif ($claimLegacyFeedbackIv
            && in_array($mode, [self::MODE_CFB, self::MODE_OFB], true)
            && self::$feedbackIvTracker !== null) {
            if (!self::$feedbackIvTracker->claim($key, $initialBlock)) {
                throw new CryptoException('SM4-CFB/OFB IV reuse detected or tracker rejected the claim');
            }
        }

        $start = bin2hex($initialBlock);
        $end = str_pad(
            gmp_strval(gmp_add(gmp_init($start, 16), gmp_init($blockCount - 1)), 16),
            32,
            '0',
            STR_PAD_LEFT
        );
        $root = self::$ctrCounterRangeRoots[$keyId] ?? null;
        try {
            self::assertCtrCounterRangeIsDisjoint($root, $start, $end);
        } catch (CryptoException $exception) {
            throw new CryptoException(
                $mode === self::MODE_CTR
                    ? 'SM4-CTR counter range reuse detected for this key'
                    : 'SM4-CFB/OFB IV reuse detected for this key',
                0,
                $exception
            );
        }
        self::$ctrCounterRangeRoots[$keyId] = self::insertCtrCounterRange($root, $start, $end);
    }

    /**
     * Reserve every block-cipher input used by an encryption in CFB/OFB.
     * NIST SP 800-38A warns that reusing any OFB feedback input as another
     * message's IV can compromise confidentiality; tracking only the initial
     * IV misses that overlap. CFB inputs after the first block are ciphertext
     * feedback and are reserved for the same reason.
     */
    private static function claimFeedbackBlockInputs(string $key, string $iv, string $plaintext, string $mode): void
    {
        $engine = null;
        $encryptBlock = static function (string $block) use ($key, $mode, &$engine): string {
            if (self::openSslSm4Available()) {
                $result = @openssl_encrypt(
                    $block,
                    'SM4-ECB',
                    $key,
                    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
                );
                if (is_string($result) && strlen($result) === 16) {
                    return $result;
                }
            }

            if ($engine === null) {
                $engine = new Sm4PurePhp();
                $engine->setKeyForMode($key, $mode);
            }
            return $engine->encryptBlock($block);
        };
        $feedback = $iv;
        $length = strlen($plaintext);

        for ($offset = 0; $offset < $length; $offset += 16) {
            self::claimStreamBlockRange($key, $feedback, 1, $mode, $offset === 0);
            $keystream = $encryptBlock($feedback);
            if ($mode === self::MODE_OFB) {
                $feedback = $keystream;
                continue;
            }

            $chunk = substr($plaintext, $offset, 16);
            $ciphertextBlock = $chunk ^ substr($keystream, 0, strlen($chunk));
            if ($offset + 16 < $length) {
                $feedback = str_pad($ciphertextBlock, 16, "\0");
            }
        }
    }

    /** @internal Enforce encryption-mode key separation for SM4 block-cipher constructions. */
    public static function claimEncryptionModeForKey(string $key, string $mode): void
    {
        if (!in_array(
            $mode,
            [self::MODE_ECB, self::MODE_CBC, self::MODE_GCM, self::MODE_CTR, self::MODE_CFB, self::MODE_OFB, self::MODE_CCM, 'raw-block'],
            true
        )) {
            throw new \LogicException('Unsupported SM4 encryption mode reservation');
        }

        $keyId = hash('sha256', $key);
        self::$keyModeTrackingLocked = true;
        if (self::$keyModeTracker !== null) {
            if (!self::$keyModeTracker->claimMode(hash('sha256', $key, true), $mode)) {
                throw new CryptoException('SM4 key-mode tracker rejected this key and mode; use a distinct key for each mode');
            }
            return;
        }

        self::reserveCipherMode($keyId, $mode);
        self::finishCipherModeReservation($keyId, $mode, true);
    }

    /** @internal Check mode before decryption without mutating a shared registry. */
    public static function assertDecryptionModeForKey(string $key, string $mode): void
    {
        if (!in_array(
            $mode,
            [self::MODE_ECB, self::MODE_CBC, self::MODE_GCM, self::MODE_CTR, self::MODE_CFB, self::MODE_OFB, self::MODE_CCM, 'raw-block'],
            true
        )) {
            throw new \LogicException('Unsupported SM4 decryption mode reservation');
        }

        if (self::$keyModeTracker !== null) {
            if (!self::$keyModeTracker->isModeAllowed(hash('sha256', $key, true), $mode)) {
                throw new CryptoException('SM4 key is not registered for this decryption mode');
            }
            return;
        }

        // Decryption input is untrusted and may fail authentication (or have no
        // authentication at all). Check an existing local mode claim without
        // creating one, so a forged ciphertext cannot pin the key to a mode and
        // deny later legitimate encryption with that key.
        $keyId = hash('sha256', $key);
        $configured = self::$cipherModeByKey[$keyId] ?? null;
        $pending = self::$pendingCipherModeByKey[$keyId] ?? null;
        if (($configured !== null && $configured !== $mode)
            || ($pending !== null && $pending['mode'] !== $mode)) {
            throw new CryptoException('SM4 key is not registered for this decryption mode');
        }
    }

    private static function reserveCipherMode(string $keyId, string $mode): void
    {
        $configured = self::$cipherModeByKey[$keyId] ?? null;
        if ($configured !== null && $configured !== $mode) {
            throw new CryptoException('SM4 modes must use separate keys to prevent cross-mode block input reuse');
        }

        $pending = self::$pendingCipherModeByKey[$keyId] ?? null;
        if ($pending !== null && $pending['mode'] !== $mode) {
            throw new CryptoException('SM4 modes must use separate keys to prevent cross-mode block input reuse');
        }

        if ($pending === null) {
            if (count(self::$cipherModeByKey) + count(self::$pendingCipherModeByKey) >= self::MAX_TRACKED_CIPHER_MODE_KEYS) {
                throw new CryptoException(
                    'SM4 mode key tracker capacity reached (' . self::MAX_TRACKED_CIPHER_MODE_KEYS
                    . ' keys); use a bounded set of mode-specific keys'
                );
            }
            self::$pendingCipherModeByKey[$keyId] = ['mode' => $mode, 'pending' => 1];
            return;
        }

        self::$pendingCipherModeByKey[$keyId]['pending']++;
    }

    private static function finishCipherModeReservation(string $keyId, string $mode, bool $commit): void
    {
        $pending = self::$pendingCipherModeByKey[$keyId] ?? null;
        if ($pending === null || $pending['mode'] !== $mode || $pending['pending'] < 1) {
            throw new \LogicException('SM4 encryption mode reservation is unavailable');
        }

        if ($commit) {
            self::$cipherModeByKey[$keyId] = $mode;
        }

        if ($pending['pending'] === 1) {
            unset(self::$pendingCipherModeByKey[$keyId]);
            return;
        }

        self::$pendingCipherModeByKey[$keyId]['pending']--;
    }

    private static function assertCtrCounterRangeIsDisjoint(?int $nodeId, string $start, string $end): void
    {
        while ($nodeId !== null) {
            $node = self::$ctrCounterRangeNodes[$nodeId];
            if (strcmp($end, $node['start']) < 0) {
                $nodeId = $node['left'];
            } elseif (strcmp($start, $node['end']) > 0) {
                $nodeId = $node['right'];
            } else {
                throw new CryptoException('SM4-CTR counter range reuse detected for this key');
            }
        }
    }

    private static function insertCtrCounterRange(?int $nodeId, string $start, string $end): int
    {
        if ($nodeId === null) {
            if (self::$trackedCtrCounterRangeCount >= self::MAX_TRACKED_STREAM_BLOCK_RANGES) {
                throw new CryptoException(
                    'SM4 stream-mode block tracker capacity reached; configure a shared '
                    . 'Sm4StreamBlockTrackerInterface during bootstrap and restart this process'
                );
            }

            $newNodeId = self::$trackedCtrCounterRangeCount++;
            self::$ctrCounterRangeNodes[$newNodeId] = [
                'start' => $start,
                'end' => $end,
                'left' => null,
                'right' => null,
                'height' => 1,
            ];
            return $newNodeId;
        }

        $node = self::$ctrCounterRangeNodes[$nodeId];
        if (strcmp($start, $node['start']) < 0) {
            $node['left'] = self::insertCtrCounterRange($node['left'], $start, $end);
        } else {
            $node['right'] = self::insertCtrCounterRange($node['right'], $start, $end);
        }
        self::$ctrCounterRangeNodes[$nodeId] = $node;

        return self::balanceCtrCounterRangeNode($nodeId);
    }

    private static function balanceCtrCounterRangeNode(int $nodeId): int
    {
        self::refreshCtrCounterRangeHeight($nodeId);
        $node = self::$ctrCounterRangeNodes[$nodeId];
        $balance = self::ctrCounterRangeNodeHeight($node['left']) - self::ctrCounterRangeNodeHeight($node['right']);

        if ($balance > 1) {
            $leftId = $node['left'];
            assert($leftId !== null);
            $left = self::$ctrCounterRangeNodes[$leftId];
            if (self::ctrCounterRangeNodeHeight($left['left']) < self::ctrCounterRangeNodeHeight($left['right'])) {
                $node['left'] = self::rotateCtrCounterRangeLeft($leftId);
                self::$ctrCounterRangeNodes[$nodeId] = $node;
            }
            return self::rotateCtrCounterRangeRight($nodeId);
        }

        if ($balance < -1) {
            $rightId = $node['right'];
            assert($rightId !== null);
            $right = self::$ctrCounterRangeNodes[$rightId];
            if (self::ctrCounterRangeNodeHeight($right['right']) < self::ctrCounterRangeNodeHeight($right['left'])) {
                $node['right'] = self::rotateCtrCounterRangeRight($rightId);
                self::$ctrCounterRangeNodes[$nodeId] = $node;
            }
            return self::rotateCtrCounterRangeLeft($nodeId);
        }

        return $nodeId;
    }

    private static function rotateCtrCounterRangeLeft(int $nodeId): int
    {
        $root = self::$ctrCounterRangeNodes[$nodeId];
        $pivotId = $root['right'];
        assert($pivotId !== null);
        $pivot = self::$ctrCounterRangeNodes[$pivotId];

        $root['right'] = $pivot['left'];
        $pivot['left'] = $nodeId;
        self::$ctrCounterRangeNodes[$nodeId] = $root;
        self::$ctrCounterRangeNodes[$pivotId] = $pivot;
        self::refreshCtrCounterRangeHeight($nodeId);
        self::refreshCtrCounterRangeHeight($pivotId);

        return $pivotId;
    }

    private static function rotateCtrCounterRangeRight(int $nodeId): int
    {
        $root = self::$ctrCounterRangeNodes[$nodeId];
        $pivotId = $root['left'];
        assert($pivotId !== null);
        $pivot = self::$ctrCounterRangeNodes[$pivotId];

        $root['left'] = $pivot['right'];
        $pivot['right'] = $nodeId;
        self::$ctrCounterRangeNodes[$nodeId] = $root;
        self::$ctrCounterRangeNodes[$pivotId] = $pivot;
        self::refreshCtrCounterRangeHeight($nodeId);
        self::refreshCtrCounterRangeHeight($pivotId);

        return $pivotId;
    }

    private static function refreshCtrCounterRangeHeight(int $nodeId): void
    {
        $node = self::$ctrCounterRangeNodes[$nodeId];
        $node['height'] = 1 + max(
            self::ctrCounterRangeNodeHeight($node['left']),
            self::ctrCounterRangeNodeHeight($node['right'])
        );
        self::$ctrCounterRangeNodes[$nodeId] = $node;
    }

    private static function ctrCounterRangeNodeHeight(?int $nodeId): int
    {
        return $nodeId === null ? 0 : self::$ctrCounterRangeNodes[$nodeId]['height'];
    }

    /** @var array<string, bool> Cached executable OpenSSL support per SM4 mode */
    private static array $openSslModeAvailability = [];

    /** @var array<string, Gcm> Cached GCM instances keyed by hex key */
    private static array $gcmCache = [];

    /** Maximum number of short-lived GCM key contexts retained by this facade. */
    private const MAX_GCM_CACHE_ENTRIES = 8;

    /**
     * Configure a shared atomic IV tracker before the first GCM encryption.
     *
     * When configured, all GCM IVs (including automatically generated IVs) are claimed through this tracker
     * instead of the process-local explicit-IV table. The tracker must atomically
     * enforce both IV uniqueness and the 2^32 per-key invocation limit across
     * every process and restart. Applications must configure this once during
     * bootstrap; changing it after GCM encryption starts would discard the
     * nonce history owned by the previous tracker.
     *
     * @throws CryptoException If a different tracker is configured after GCM encryption starts
     */
    public static function setGcmIvTracker(?GcmIvTrackerInterface $tracker): void
    {
        Gcm::setIvTracker($tracker);
    }

    /**
     * Configure a shared fixed tag-length profile before GCM processing starts.
     * Use this with shared IV tracking when one key is used across workers.
     */
    public static function setGcmTagLengthTracker(?GcmTagLengthTrackerInterface $tracker): void
    {
        Gcm::setTagLengthTracker($tracker);
    }

    public static function warmupGcm(string $key): void
    {
        self::validateHexKey($key);
        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }
        if (!isset(self::$gcmCache[$key])) {
            if (count(self::$gcmCache) >= self::MAX_GCM_CACHE_ENTRIES) {
                array_shift(self::$gcmCache);
            }
            self::$gcmCache[$key] = Gcm::fromKey($keyBin);
        }
        self::$gcmCache[$key]->warmup();
    }

    /**
     * Keep GCM IV reuse tracking enabled.
     *
     * Tracking is enabled by default: encrypting twice with the same key and IV
     * throws CryptoException. It cannot be disabled because GCM nonce reuse
     * compromises confidentiality and authentication. Use a fresh IV for each
     * encryption and configure a shared GcmIvTrackerInterface for coordination
     * across processes and restarts.
     *
     * @throws CryptoException If tracking is requested to be disabled
     */
    public static function enableGcmIvTracking(bool $enabled = true): void
    {
        Gcm::configureFacadeIvTracking($enabled);
    }

    /**
     * Reset GCM IV tracking before the first encryption.
     *
     * @throws CryptoException If encryption has started and history is in use
     */
    public static function resetGcmIvTracking(): void
    {
        Gcm::resetFacadeIvTracking();
    }

    private static function cryptGcm(string $data, string $key, bool $encrypt, Sm4Options $options): string
    {
        // If the caller has not materialized or supplied an IV, let GCM create
        // one internally. This keeps random IVs out of the bounded explicit-IV
        // table without exposing a caller-controlled tracking bypass.
        $generateIvInternally = $encrypt && !$options->hasExplicitIv() && !$options->hasIv();
        $ivBin = '';
        if (!$generateIvInternally) {
            $iv = $options->getIv();
            if (!preg_match('/\A[0-9a-fA-F]+\z/', $iv) || strlen($iv) < 2 || strlen($iv) % 2 !== 0) {
                throw new InvalidKeyException('GCM mode requires a valid IV (at least 1 byte)');
            }
            $ivBin = hex2bin($iv);
            if ($ivBin === false) {
                throw new InvalidKeyException('Invalid GCM IV hex');
            }
        }

        self::validateHexKey($key);
        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }

        if (!isset(self::$gcmCache[$key])) {
            if (count(self::$gcmCache) >= self::MAX_GCM_CACHE_ENTRIES) {
                array_shift(self::$gcmCache);
            }
            self::$gcmCache[$key] = Gcm::fromKey($keyBin);
        }
        $gcm = self::$gcmCache[$key];

        $aad = $options->getAad();
        $tagLength = $options->getTagLength();

        if ($encrypt) {
            if ($generateIvInternally) {
                // Let the base options object own and consume the generated IV.
                // This preserves single-use provenance across the public bridge.
                $options->getIv();
                $result = $gcm->encryptWithMaterializedRandomIvFromFacade($data, $options, $aad, $tagLength);
            } else {
                if ($options->hasExplicitIv()) {
                    $result = $gcm->encryptFromFacade($data, $ivBin, $aad, $tagLength);
                } else {
                    $result = $gcm->encryptWithMaterializedRandomIvFromFacade($data, $options, $aad, $tagLength);
                }
            }
            return bin2hex($result['ciphertext']) . bin2hex($result['tag']);
        }

        if (strlen($data) < $tagLength * 2 || strlen($data) % 2 !== 0) {
            throw new CryptoException('Invalid GCM ciphertext or tag length');
        }

        $tagHex = substr($data, -$tagLength * 2);
        $cipherHex = substr($data, 0, -$tagLength * 2);

        if (($cipherHex !== '' && !preg_match('/\A[0-9a-fA-F]+\z/', $cipherHex)) || strlen($cipherHex) % 2 !== 0) {
            throw new CryptoException('Invalid GCM ciphertext hex');
        }
        if (!preg_match('/\A[0-9a-fA-F]+\z/', $tagHex) || strlen($tagHex) % 2 !== 0) {
            throw new CryptoException('Invalid GCM tag hex');
        }

        $cipherBin = hex2bin($cipherHex);
        $tagBin = hex2bin($tagHex);
        if ($cipherBin === false || $tagBin === false) {
            throw new CryptoException('Invalid GCM ciphertext or tag');
        }

        return $gcm->decrypt($cipherBin, $tagBin, $ivBin, $aad, $tagLength);
    }

    /**
     * Get the OpenSSL cipher method name for the given SM4 mode.
     */
    private static function getOpenSSLMethodName(string $mode): string
    {
        return match ($mode) {
            self::MODE_ECB => 'SM4-ECB',
            self::MODE_CBC => 'SM4-CBC',
            self::MODE_CFB => 'SM4-CFB',
            self::MODE_OFB => 'SM4-OFB',
            self::MODE_CTR => 'SM4-CTR',
            default => throw new InvalidKeyException('Unsupported SM4 mode: ' . $mode),
        };
    }

    private static function validateHexKey(string $hex, string $label = 'Key'): void
    {
        if (!preg_match('/\A[0-9a-fA-F]{32}\z/', $hex)) {
            $msg = $label === 'IV' ? 'IV must be 128 bits (32 hex chars)' : 'Key must be 128 bits (32 hex chars)';
            throw new InvalidKeyException($msg);
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function payloadString(array $payload, string $key): string
    {
        if (!array_key_exists($key, $payload) || !is_string($payload[$key])) {
            throw new InvalidKeyException('Invalid SM4 payload: missing string field ' . $key);
        }
        return $payload[$key];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function payloadInt(array $payload, string $key): int
    {
        if (!array_key_exists($key, $payload) || !is_int($payload[$key])) {
            throw new InvalidKeyException('Invalid SM4 payload: missing integer field ' . $key);
        }
        return $payload[$key];
    }

    private static function validatePayloadHex(string $hex, string $label, bool $allowEmpty): void
    {
        if ($hex === '') {
            if ($allowEmpty) {
                return;
            }
            throw new InvalidKeyException('Invalid SM4 payload ' . $label . ': empty value');
        }
        if (!preg_match('/\A[0-9a-fA-F]+\z/', $hex) || strlen($hex) % 2 !== 0) {
            throw new InvalidKeyException('Invalid SM4 payload ' . $label . ' hex');
        }
    }

    private static function maybePad(string $data, string $padding): string
    {
        if ($padding === 'none') {
            if (strlen($data) % 16 !== 0) {
                throw new InvalidKeyException('Data length must be multiple of 16 when padding=none');
            }
            return $data;
        }

        $block = 16;
        $remainder = strlen($data) % $block;
        $padLen = $remainder === 0 ? $block : $block - $remainder;

        return match ($padding) {
            'pkcs5', 'pkcs7' => $data . str_repeat(chr($padLen), $padLen),
            'zero' => $data . str_repeat("\0", $padLen),
            'iso10126' => $data . ($padLen > 1 ? random_bytes($padLen - 1) : '') . chr($padLen),
            'ansix923' => $data . str_repeat("\0", $padLen - 1) . chr($padLen),
            default => throw new InvalidKeyException('Unsupported padding: ' . $padding),
        };
    }

    private static function maybeUnpad(string $data, string $padding): string
    {
        if ($padding === 'none') {
            return $data;
        }
        $len = strlen($data);
        if ($len === 0 || $len % 16 !== 0) {
            throw new CryptoException('Decryption failed');
        }

        if ($padding === 'zero') {
            return rtrim($data, "\0");
        }

        $pad = ord($data[$len - 1]);

        if ($padding === 'pkcs5' || $padding === 'pkcs7' || $padding === 'ansix923') {
            // Always inspect the complete final block. Variable-length suffix
            // comparisons make malformed CBC ciphertexts observably cheaper
            // to reject depending on the claimed padding length.
            $invalid = (int) ($pad < 1 || $pad > 16);
            $isPkcs = $padding === 'pkcs5' || $padding === 'pkcs7';
            for ($i = 1; $i <= 16; $i++) {
                $isLast = (int) ($i === 1);
                $withinPadding = (int) ($i <= $pad);
                $check = $isPkcs
                    ? $withinPadding
                    : ($isLast | ($withinPadding & (1 - $isLast)));
                $expected = $isPkcs ? $pad : ($pad * $isLast);
                $mask = -$check;
                $invalid |= (ord($data[$len - $i]) ^ $expected) & $mask;
            }
            if ($invalid !== 0) {
                throw new CryptoException('Decryption failed');
            }
        } else {
            if ($pad < 1 || $pad > 16) {
                throw new CryptoException('Decryption failed');
            }
        }

        return substr($data, 0, $len - $pad);
    }
}
