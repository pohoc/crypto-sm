<?php

declare(strict_types=1);

namespace CryptoSm\SM3;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Utils\Hex;

/** PBKDF2 using HMAC-SM3 as its pseudorandom function (RFC 8018 §5.2). */
final class Pbkdf2Sm3
{
    private const HMAC_LENGTH = 32;
    private const MAX_BLOCK_INDEX = 0xFFFFFFFF;
    private const SM3_BLOCK_SIZE = 64;

    private static ?bool $nativeSm3Available = null;

    /**
     * Derive key material as raw bytes.
     *
     * Password and salt are byte strings. Applications should use a unique
     * random salt of at least 8 bytes and choose the largest iteration count
     * their latency budget permits; the iteration count is deliberately
     * required rather than silently selecting a hardware-dependent default.
     *
     * @throws CryptoException If the iteration count or output length is invalid
     */
    public static function derive(string $password, string $salt, int $iterations, int $keyLength): string
    {
        if ($iterations < 1) {
            throw new CryptoException('PBKDF2-HMAC-SM3 iteration count must be positive');
        }
        if ($keyLength < 1) {
            throw new CryptoException('PBKDF2-HMAC-SM3 derived key length must be positive');
        }

        $blockCount = intdiv($keyLength - 1, self::HMAC_LENGTH) + 1;
        if ($blockCount > self::MAX_BLOCK_INDEX || $blockCount > PHP_INT_MAX) {
            throw new CryptoException('PBKDF2-HMAC-SM3 derived key is too long');
        }

        $key = $password;
        if (strlen($key) > self::SM3_BLOCK_SIZE) {
            $key = self::sm3Raw($key);
        }
        $key = str_pad($key, self::SM3_BLOCK_SIZE, "\0");
        $innerPad = $key ^ str_repeat("\x36", self::SM3_BLOCK_SIZE);
        $outerPad = $key ^ str_repeat("\x5C", self::SM3_BLOCK_SIZE);
        $derivedKey = '';

        for ($blockIndex = 1; $blockIndex <= $blockCount; $blockIndex++) {
            $u = self::hmacRaw($innerPad, $outerPad, $salt . pack('N', $blockIndex));
            $block = $u;
            for ($iteration = 1; $iteration < $iterations; $iteration++) {
                $u = self::hmacRaw($innerPad, $outerPad, $u);
                $block ^= $u;
            }

            $derivedKey .= $block;
        }

        return substr($derivedKey, 0, $keyLength);
    }

    private static function hmacRaw(string $innerPad, string $outerPad, string $data): string
    {
        return self::sm3Raw($outerPad . self::sm3Raw($innerPad . $data));
    }

    private static function sm3Raw(string $data): string
    {
        if (self::$nativeSm3Available === null) {
            $probe = function_exists('openssl_digest')
                ? @openssl_digest('', 'SM3', true)
                : false;
            self::$nativeSm3Available = is_string($probe) && strlen($probe) === self::HMAC_LENGTH;
        }

        if (self::$nativeSm3Available) {
            $digest = @openssl_digest($data, 'SM3', true);
            if (is_string($digest) && strlen($digest) === self::HMAC_LENGTH) {
                return $digest;
            }
            // Provider availability can change at runtime; retain a correct fallback.
            self::$nativeSm3Available = false;
        }

        return Hex::fromHex(Sm3::sm3($data));
    }

    /** Derive key material and encode the result as lowercase hexadecimal. */
    public static function deriveHex(string $password, string $salt, int $iterations, int $keyLength): string
    {
        return bin2hex(self::derive($password, $salt, $iterations, $keyLength));
    }
}
