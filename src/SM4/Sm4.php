<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

use CryptoSm\Crypto\Gcm;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Interfaces\CipherInterface;

/**
 * SM4 block cipher implementation (GM/T 0002-2012).
 *
 * Supports ECB, CBC, CFB, OFB, CTR, and GCM modes with configurable padding.
 * CBC mode is the default; ECB is not recommended for new applications.
 * GCM mode provides authenticated encryption with associated data (AEAD).
 */
class Sm4 implements CipherInterface
{
    /**
     * @var string Electronic Codebook mode
     * @deprecated ECB mode does not provide data confidentiality for repeated patterns. Use CBC or GCM instead.
     */
    public const MODE_ECB = 'ecb';

    /** @var string Cipher Block Chaining mode (default, recommended) */
    public const MODE_CBC = 'cbc';

    /** @var string Cipher Feedback mode (stream-like, no padding needed) */
    public const MODE_CFB = 'cfb';

    /** @var string Output Feedback mode (stream-like, no padding needed) */
    public const MODE_OFB = 'ofb';

    /** @var string Counter mode (stream-like, no padding needed) */
    public const MODE_CTR = 'ctr';

    /** @var string Galois/Counter mode (authenticated encryption) */
    public const MODE_GCM = 'gcm';

    /** @var array<int,string> Modes that don't require padding (stream-like) */
    private const STREAM_MODES = [self::MODE_CFB, self::MODE_OFB, self::MODE_CTR, self::MODE_GCM];

    /**
     * Encrypt data using SM4.
     *
     * @param  string              $data    Plaintext data to encrypt
     * @param  string              $key     32-character hex string (128-bit key)
     * @param  mixed               $options Sm4Options instance or null for defaults
     * @return string              Hex-encoded ciphertext
     * @throws InvalidKeyException If key or options are invalid
     * @throws CryptoException     If encryption fails
     */
    public static function encrypt(string $data, string $key, mixed $options = null): string
    {
        return self::crypt($data, $key, true, $options instanceof Sm4Options ? $options : null);
    }

    /**
     * Decrypt data using SM4.
     *
     * @param  string              $data    Hex-encoded ciphertext
     * @param  string              $key     32-character hex string (128-bit key)
     * @param  mixed               $options Sm4Options instance or null for defaults
     * @return string              Decrypted plaintext
     * @throws InvalidKeyException If key, ciphertext, or options are invalid
     * @throws CryptoException     If decryption fails
     */
    public static function decrypt(string $data, string $key, mixed $options = null): string
    {
        return self::crypt($data, $key, false, $options instanceof Sm4Options ? $options : null);
    }

    private static function crypt(string $data, string $key, bool $encrypt, ?Sm4Options $options = null): string
    {
        if (!extension_loaded('openssl')) {
            throw new CryptoException('OpenSSL extension is required for SM4');
        }
        $options ??= new Sm4Options();
        $mode = strtolower($options->getMode());
        $padding = strtolower($options->getPadding());

        self::validateHexKey($key);

        // GCM mode has its own handling
        if ($mode === self::MODE_GCM) {
            return self::cryptGcm($data, $key, $encrypt, $options);
        }

        $ivBin = '';
        $needsIv = !in_array($mode, [self::MODE_ECB], true);
        if ($needsIv) {
            $iv = $options->getIv();
            self::validateHexKey($iv, 'IV');
            $ivBin = hex2bin($iv);
            if ($ivBin === false) {
                throw new InvalidKeyException('Invalid IV hex');
            }
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

        $opensslCipher = self::getOpenSSLMethodName($mode);
        $isStreamMode = in_array($mode, self::STREAM_MODES, true);

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
        if (!preg_match('/^[0-9a-fA-F]+$/', $data) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = hex2bin($data);
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

    /** @var array<string, Gcm> Cached GCM instances keyed by hex key */
    private static array $gcmCache = [];

    public static function warmupGcm(string $key): void
    {
        self::validateHexKey($key);
        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }
        if (!isset(self::$gcmCache[$key])) {
            if (count(self::$gcmCache) > 8) {
                array_shift(self::$gcmCache);
            }
            self::$gcmCache[$key] = Gcm::fromKey($keyBin);
        }
        self::$gcmCache[$key]->warmup();
    }

    private static function cryptGcm(string $data, string $key, bool $encrypt, Sm4Options $options): string
    {
        $iv = $options->getIv();
        if (!preg_match('/^[0-9a-fA-F]+$/', $iv) || strlen($iv) < 2 || strlen($iv) % 2 !== 0) {
            throw new InvalidKeyException('GCM mode requires a valid IV (at least 1 byte)');
        }
        $ivBin = hex2bin($iv);
        if ($ivBin === false) {
            throw new InvalidKeyException('Invalid GCM IV hex');
        }

        self::validateHexKey($key);
        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }

        if (!isset(self::$gcmCache[$key])) {
            if (count(self::$gcmCache) > 8) {
                array_shift(self::$gcmCache);
            }
            self::$gcmCache[$key] = Gcm::fromKey($keyBin);
        }
        $gcm = self::$gcmCache[$key];

        $aad = $options->getAad();
        $tagLength = $options->getTagLength();

        if ($encrypt) {
            $result = $gcm->encrypt($data, $ivBin, $aad, $tagLength);
            return bin2hex($result['ciphertext']) . bin2hex($result['tag']);
        }

        $tagHex = substr($data, -$tagLength * 2);
        $cipherHex = substr($data, 0, -$tagLength * 2);

        if (!preg_match('/^[0-9a-fA-F]+$/', $cipherHex) || strlen($cipherHex) % 2 !== 0) {
            throw new CryptoException('Invalid GCM ciphertext hex');
        }
        if (!preg_match('/^[0-9a-fA-F]+$/', $tagHex) || strlen($tagHex) % 2 !== 0) {
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
        if (!preg_match('/^[0-9a-fA-F]{32}$/', $hex)) {
            $msg = $label === 'IV' ? 'IV must be 128 bits (32 hex chars)' : 'Key must be 128 bits (32 hex chars)';
            throw new InvalidKeyException($msg);
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
            throw new InvalidKeyException('Invalid padded plaintext');
        }

        if ($padding === 'zero') {
            // WARNING: Zero padding cannot distinguish padding zeros from data that ends with \0.
            // Data with trailing null bytes will be silently truncated. Use PKCS5/PKCS7 instead
            // if your data may contain trailing null bytes.
            return rtrim($data, "\0");
        }

        // PKCS5/PKCS7, ISO 10126, ANSI X9.23 — all use last byte as pad length
        $pad = ord($data[$len - 1]);

        if ($padding === 'pkcs5' || $padding === 'pkcs7') {
            if ($pad < 1 || $pad > 16 || substr($data, -$pad) !== str_repeat(chr($pad), $pad)) {
                throw new InvalidKeyException('Invalid PKCS padding');
            }
        } elseif ($padding === 'ansix923') {
            if ($pad < 1 || $pad > 16) {
                throw new InvalidKeyException('Invalid ANSI X9.23 padding');
            }
            // All pad bytes except the last must be zero
            $padBytes = substr($data, -$pad, $pad - 1);
            if ($padBytes !== str_repeat("\0", $pad - 1)) {
                throw new InvalidKeyException('Invalid ANSI X9.23 padding');
            }
        } else {
            // ISO 10126: random pad bytes, only verify the last byte
            if ($pad < 1 || $pad > 16) {
                throw new InvalidKeyException('Invalid ISO 10126 padding');
            }
        }

        return substr($data, 0, $len - $pad);
    }
}
