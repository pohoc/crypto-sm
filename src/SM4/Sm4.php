<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Interface\CipherInterface;
use CryptoSm\Utils\Hex;

/**
 * SM4 block cipher implementation (GM/T 0002-2012).
 *
 * Supports ECB and CBC modes with PKCS5 padding.
 * CBC mode is the default; ECB is not recommended for new applications.
 */
class Sm4 implements CipherInterface
{
    /** @var string Electronic Codebook mode (not recommended) */
    public const MODE_ECB = 'ecb';

    /** @var string Cipher Block Chaining mode (default, recommended) */
    public const MODE_CBC = 'cbc';

    /**
     * Encrypt data using SM4.
     *
     * @param string $data    Plaintext data to encrypt
     * @param string $key     32-character hex string (128-bit key)
     * @param mixed  $options Sm4Options instance or null for defaults
     * @return string Hex-encoded ciphertext
     * @throws InvalidKeyException If key or options are invalid
     * @throws CryptoException    If encryption fails
     */
    public static function encrypt(string $data, string $key, mixed $options = null): string
    {
        return self::crypt($data, $key, true, $options instanceof Sm4Options ? $options : null);
    }

    /**
     * Decrypt data using SM4.
     *
     * @param string $data    Hex-encoded ciphertext
     * @param string $key     32-character hex string (128-bit key)
     * @param mixed  $options Sm4Options instance or null for defaults
     * @return string Decrypted plaintext
     * @throws InvalidKeyException If key, ciphertext, or options are invalid
     * @throws CryptoException    If decryption fails
     */
    public static function decrypt(string $data, string $key, mixed $options = null): string
    {
        return self::crypt($data, $key, false, $options instanceof Sm4Options ? $options : null);
    }

    /**
     * Convert a hex string to a byte array.
     *
     * @param string $hex Hex string to convert
     * @return array<int,int> Array of byte values
     */
    public static function hexToBytesStatic(string $hex): array
    {
        return Hex::toBytes($hex);
    }

    private static function crypt(string $data, string $key, bool $encrypt, ?Sm4Options $options = null): string
    {
        $options ??= new Sm4Options();
        $mode = strtolower($options->getMode());
        $padding = strtolower($options->getPadding());
        $iv = $options->getIv();

        self::validateHexKey($key);
        if ($mode === self::MODE_CBC) {
            self::validateHexKey($iv, 'IV');
            $ivBin = hex2bin($iv);
        } elseif ($mode !== self::MODE_ECB) {
            throw new InvalidKeyException('Mode must be ecb or cbc');
        }

        $keyBin = hex2bin($key);

        if ($encrypt) {
            $input = self::maybePad($data, $padding);
            $cipher = openssl_encrypt(
                $input,
                $mode === self::MODE_ECB ? 'SM4-ECB' : 'SM4-CBC',
                $keyBin,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $mode === self::MODE_CBC ? $ivBin : ''
            );
            if ($cipher === false) {
                throw new CryptoException('SM4 encryption failed');
            }
            return bin2hex($cipher);
        }

        if (!preg_match('/^[0-9a-fA-F]+$/', $data) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = hex2bin($data);
        if ($cipher === false || strlen($cipher) % 16 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $plain = openssl_decrypt(
            $cipher,
            $mode === self::MODE_ECB ? 'SM4-ECB' : 'SM4-CBC',
            $keyBin,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $mode === self::MODE_CBC ? $ivBin : ''
        );
        if ($plain === false) {
            throw new CryptoException('SM4 decryption failed');
        }

        return self::maybeUnpad($plain, $padding);
    }

    private static function validateHexKey(string $hex, string $label = 'Key'): void
    {
        if (!preg_match('/^[0-9a-fA-F]{32}$/', $hex)) {
            $msg = $label === 'IV' ? 'CBC mode requires IV' : 'Key must be 128 bits (32 hex chars)';
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
        $pad = $remainder === 0 ? $block : $block - $remainder;
        return $data . str_repeat(chr($pad), $pad);
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
        $pad = ord($data[$len - 1]);
        if ($pad < 1 || $pad > 16 || substr($data, -$pad) !== str_repeat(chr($pad), $pad)) {
            throw new InvalidKeyException('Invalid PKCS padding');
        }
        return substr($data, 0, $len - $pad);
    }
}
