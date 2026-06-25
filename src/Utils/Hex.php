<?php

declare(strict_types=1);

namespace CryptoSm\Utils;

/**
 * Utility class for hexadecimal encoding/decoding.
 */
class Hex
{
    /**
     * Convert a hex string to a byte array.
     *
     * @param  string         $hex Hex string (odd-length will be zero-padded for backward compatibility)
     * @return array<int,int> Array of byte values (0-255)
     */
    public static function toBytes(string $hex): array
    {
        if ($hex === '') {
            return [];
        }
        if (!ctype_xdigit($hex)) {
            throw new \InvalidArgumentException('Invalid hex string');
        }
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }
        $binary = hex2bin($hex);
        if ($binary === false) {
            return [];
        }
        $unpacked = unpack('C*', $binary);
        return $unpacked === false ? [] : array_values($unpacked);
    }

    /**
     * Convert a byte array to a hex string.
     *
     * @param  array<int,int> $bytes Array of byte values
     * @return string         Lowercase hex string
     */
    public static function toHex(array $bytes): string
    {
        return bin2hex(implode('', array_map(static fn (int $b): string => chr($b & 0xFF), $bytes)));
    }

    /**
     * Convert a binary string to a hex string.
     *
     * @param  string $str Binary string
     * @return string Lowercase hex string
     */
    public static function toHexString(string $str): string
    {
        return bin2hex($str);
    }

    /**
     * Convert a hex string to a binary string.
     *
     * @param  string $hex Hex string (odd-length will be zero-padded for backward compatibility)
     * @return string Binary string, or empty string on invalid input
     */
    public static function fromHex(string $hex): string
    {
        if ($hex === '') {
            return '';
        }
        if (!ctype_xdigit($hex)) {
            throw new \InvalidArgumentException('Invalid hex string');
        }
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }
        $result = hex2bin($hex);
        return $result === false ? '' : $result;
    }

    public static function isValidHex(string $hex): bool
    {
        return $hex === '' || preg_match('/^[0-9a-fA-F]+$/', $hex) === 1;
    }
}
