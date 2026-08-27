<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

use CryptoSm\Exception\CryptoException;

/**
 * ASN.1/DER encode/decode utility for SM2 signatures.
 */
class Asn1
{
    public const TAG_SEQUENCE = 0x30;
    public const TAG_INTEGER = 0x02;
    public const TAG_OCTET_STRING = 0x04;

    /**
     * Decode an ASN.1 INTEGER from DER data.
     *
     * @param  string          $data   DER-encoded data
     * @param  int             $offset Current offset (passed by reference, updated after read)
     * @return string          Decimal string representation of the integer
     * @throws CryptoException If the INTEGER tag is invalid
     */
    public static function decodeInteger(string $data, int &$offset): string
    {
        if (!isset($data[$offset])) {
            throw new CryptoException('Unexpected end of ASN.1 data');
        }
        if (ord($data[$offset]) !== self::TAG_INTEGER) {
            throw new CryptoException('Invalid INTEGER tag');
        }
        $offset++;

        $len = self::decodeLength($data, $offset);

        if ($offset + $len > strlen($data)) {
            throw new CryptoException('ASN.1 length exceeds available data');
        }

        if ($len === 0) {
            throw new CryptoException('Invalid DER INTEGER: empty value');
        }

        $valueBytes = substr($data, $offset, $len);
        $offset += $len;

        $first = ord($valueBytes[0]);
        if (($first & 0x80) !== 0) {
            throw new CryptoException('Invalid DER INTEGER: negative values are not supported');
        }
        if ($len > 1 && $first === 0x00 && (ord($valueBytes[1]) & 0x80) === 0) {
            throw new CryptoException('Invalid DER INTEGER: non-minimal encoding');
        }

        $hex = bin2hex($valueBytes);
        $value = preg_replace('/^0+(?=[0-9a-f])/', '', $hex) ?: '0';

        return gmp_strval(gmp_init($value, 16), 10);
    }

    /**
     * Decode an ASN.1 SEQUENCE header from DER data.
     *
     * @param  string          $data   DER-encoded data
     * @param  int             $offset Current offset (passed by reference, updated after read)
     * @return int             Length of the SEQUENCE content
     * @throws CryptoException If the SEQUENCE tag is invalid
     */
    public static function decodeSequence(string $data, int &$offset): int
    {
        if (!isset($data[$offset])) {
            throw new CryptoException('Unexpected end of ASN.1 data');
        }
        if (ord($data[$offset]) !== self::TAG_SEQUENCE) {
            throw new CryptoException('Invalid SEQUENCE tag');
        }
        $offset++;

        $seqLen = self::decodeLength($data, $offset);

        if ($offset + $seqLen > strlen($data)) {
            throw new CryptoException('ASN.1 length exceeds available data');
        }

        return $seqLen;
    }

    /**
     * Decode a DER length field and advance the offset.
     */
    private static function decodeLength(string $data, int &$offset): int
    {
        if (!isset($data[$offset])) {
            throw new CryptoException('Unexpected end of ASN.1 data');
        }

        $len = ord($data[$offset++]);
        if (($len & 0x80) === 0) {
            return $len;
        }

        $lenBytes = $len & 0x7F;
        if ($lenBytes === 0) {
            throw new CryptoException('ASN.1 indefinite lengths are not valid DER');
        }
        if ($lenBytes > 4 || $offset + $lenBytes > strlen($data)) {
            throw new CryptoException('ASN.1 length bytes exceed available data');
        }
        if ($lenBytes > 1 && ord($data[$offset]) === 0x00) {
            throw new CryptoException('ASN.1 length is not minimally encoded');
        }

        $decoded = 0;
        for ($i = 0; $i < $lenBytes; $i++) {
            $decoded = ($decoded << 8) | ord($data[$offset++]);
        }
        if ($decoded < 128) {
            throw new CryptoException('ASN.1 length is not minimally encoded');
        }

        return $decoded;
    }

    /**
     * Encode a DER length field using the minimum number of bytes.
     *
     * For lengths < 128: single byte.
     * For lengths >= 128: 0x80 | N followed by N big-endian bytes of the length.
     *
     * @param  int    $len Length value to encode
     * @return string DER-encoded length bytes
     */
    public static function encodeLength(int $len): string
    {
        if ($len < 128) {
            return chr($len & 0xFF);
        }

        $lenBytes = '';
        $temp = $len;
        do {
            $lenBytes = chr($temp & 0xFF) . $lenBytes;
            $temp >>= 8;
        } while ($temp > 0);

        return chr((0x80 | strlen($lenBytes)) & 0xFF) . $lenBytes;
    }

    /**
     * Encode a hex value as an ASN.1 INTEGER.
     *
     * @param  string          $hex Hex string of the integer value
     * @return string          DER-encoded INTEGER (binary)
     * @throws CryptoException If the hex string is invalid
     */
    public static function encodeInteger(string $hex): string
    {
        if (strlen($hex) % 2 !== 0) {
            throw new CryptoException('Invalid hex for integer encoding: odd length');
        }
        if (!preg_match('/^[0-9a-fA-F]+$/', $hex)) {
            throw new CryptoException('Invalid hex for integer encoding');
        }
        // 上游 preg_match 已确保纯十六进制且偶数长度，hex2bin 不可能失败
        $bytes = (string) hex2bin($hex);

        while (strlen($bytes) > 1 && ord($bytes[0]) === 0) {
            $bytes = substr($bytes, 1);
        }

        if (ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }

        $len = strlen($bytes);
        $lenByte = self::encodeLength($len);

        return chr(self::TAG_INTEGER) . $lenByte . $bytes;
    }

    /**
     * Encode content as an ASN.1 SEQUENCE.
     *
     * @param  string $content DER-encoded content
     * @return string DER-encoded SEQUENCE (binary)
     */
    public static function encodeSequence(string $content): string
    {
        $len = strlen($content);
        $lenByte = self::encodeLength($len);
        return chr(self::TAG_SEQUENCE) . $lenByte . $content;
    }

    /**
     * Encode an SM2 signature in DER format.
     *
     * @param  string $rHex R component as 64-char hex string
     * @param  string $sHex S component as 64-char hex string
     * @return string DER-encoded signature as hex string
     */
    public static function encodeDerSignature(string $rHex, string $sHex): string
    {
        return bin2hex(self::encodeDerSignatureBinary($rHex, $sHex));
    }

    /**
     * Encode an SM2 signature in DER format as raw binary.
     *
     * @param  string $rHex R component as 64-char hex string
     * @param  string $sHex S component as 64-char hex string
     * @return string DER-encoded signature as raw binary
     */
    public static function encodeDerSignatureBinary(string $rHex, string $sHex): string
    {
        $rBytes = self::encodeInteger($rHex);
        $sBytes = self::encodeInteger($sHex);
        $sequence = $rBytes . $sBytes;
        return self::encodeSequence($sequence);
    }

    /**
     * Decode a DER-encoded SM2 signature.
     *
     * @param  string               $der DER-encoded signature as hex string
     * @return array{string,string} [rHex, sHex] — 64-char zero-padded hex strings
     * @throws CryptoException      If the DER data is invalid
     */
    public static function decodeDerSignature(string $der): array
    {
        if (!preg_match('/^[0-9a-fA-F]+$/', $der)) {
            throw new CryptoException('Invalid DER signature hex');
        }
        $data = @hex2bin($der);
        if ($data === false) {
            throw new CryptoException('Invalid DER signature hex');
        }

        return self::decodeDerSignatureBinary($data);
    }

    /**
     * Decode a DER-encoded SM2 signature from raw binary.
     *
     * @param  string               $data DER-encoded signature as raw binary
     * @return array{string,string} [rHex, sHex] — 64-char zero-padded hex strings
     * @throws CryptoException      If the DER data is invalid
     */
    public static function decodeDerSignatureBinary(string $data): array
    {
        $offset = 0;
        $seqLen = self::decodeSequence($data, $offset);
        $seqEnd = $offset + $seqLen;

        $r = self::decodeInteger($data, $offset);
        $s = self::decodeInteger($data, $offset);
        if ($offset !== $seqEnd || $offset !== strlen($data)) {
            throw new CryptoException('Invalid DER signature structure');
        }

        $rHex = gmp_strval(gmp_init($r), 16);
        $sHex = gmp_strval(gmp_init($s), 16);

        return [
            str_pad($rHex, 64, '0', STR_PAD_LEFT),
            str_pad($sHex, 64, '0', STR_PAD_LEFT),
        ];
    }
}
