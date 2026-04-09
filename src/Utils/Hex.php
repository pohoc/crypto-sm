<?php

declare(strict_types=1);

namespace CryptoSm\Utils;

/**
 * Utility class for hexadecimal encoding/decoding.
 */
class Hex
{
    public static function toBytes(string $hex): array
    {
        $hex = preg_replace('/[^0-9a-fA-F]/', '', $hex);
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }
        $binary = hex2bin($hex);
        if ($binary === false) {
            return [];
        }
        return array_values(unpack('C*', $binary));
    }

    public static function toHex(array $bytes): string
    {
        return bin2hex(implode('', array_map('chr', $bytes)));
    }

    public static function toHexString(string $str): string
    {
        return bin2hex($str);
    }

    public static function fromHex(string $hex): string
    {
        $hex = preg_replace('/[^0-9a-fA-F]/', '', $hex);
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }
        $result = hex2bin($hex);
        return $result === false ? '' : $result;
    }
}
