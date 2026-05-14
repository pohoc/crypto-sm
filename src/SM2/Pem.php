<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Utils\Hex;

/**
 * PEM format import/export for SM2 keys.
 *
 * Supports standard SEC 1 / PKCS#8 PEM formats for SM2 elliptic curve keys:
 * - Private key: SEC 1 (BEGIN EC PRIVATE KEY) or PKCS#8 (BEGIN PRIVATE KEY)
 * - Public key:  SEC 1 (BEGIN PUBLIC KEY) with uncompressed point
 *
 * The SM2 curve OID is 1.2.156.10197.1.301.
 */
class Pem
{
    /** SM2 curve OID: 1.2.156.10197.1.301 */
    private const OID_SM2 = '1.2.156.10197.1.301';

    /** OID for public key algorithm (ecPublicKey) */
    private const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

    /**
     * Export a private key in SEC 1 PEM format (BEGIN EC PRIVATE KEY).
     *
     * @param  string              $privateKey 64-char hex private key
     * @param  string              $publicKey  128-char hex uncompressed public key (optional, included if provided)
     * @return string              PEM-encoded private key
     * @throws InvalidKeyException If key format is invalid
     */
    public static function exportPrivateKey(string $privateKey, string $publicKey = ''): string
    {
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $privateKey)) {
            throw new InvalidKeyException('Private key must be 64 hex chars');
        }

        // SEC 1 structure:
        // SEQUENCE {
        //   INTEGER 1 (version)
        //   OCTET STRING <privateKey>
        //   [0] OID <curve> (optional)
        //   [1] BIT STRING <publicKey> (optional)
        // }

        $version = "\x02\x01\x01"; // INTEGER 1
        $privKeyBytes = hex2bin($privateKey);
        if ($privKeyBytes === false) {
            throw new InvalidKeyException('Invalid private key hex');
        }
        $privKeyOctetString = "\x04" . self::encodeDerLength(strlen($privKeyBytes)) . $privKeyBytes;

        // Context-specific [0] with SM2 OID
        $oidBytes = self::encodeOid(self::OID_SM2);
        $curveCtx = "\xa0" . self::encodeDerLength(strlen($oidBytes)) . $oidBytes;

        // Context-specific [1] with public key (if provided)
        $pubKeyCtx = '';
        if ($publicKey !== '') {
            if (!preg_match('/^[0-9a-fA-F]{128}$/', $publicKey)) {
                throw new InvalidKeyException('Public key must be 128 hex chars');
            }
            // Uncompressed point: 04 || x || y
            $pubPoint = "\x04" . hex2bin($publicKey);
            // BIT STRING: 00 (no unused bits) || uncompressed point
            $bitString = "\x03" . self::encodeDerLength(strlen($pubPoint) + 1) . "\x00" . $pubPoint;
            $pubKeyCtx = "\xa1" . self::encodeDerLength(strlen($bitString)) . $bitString;
        }

        $content = $version . $privKeyOctetString . $curveCtx . $pubKeyCtx;
        $sequence = "\x30" . self::encodeDerLength(strlen($content)) . $content;

        return self::wrapPem('EC PRIVATE KEY', $sequence);
    }

    /**
     * Export a private key in PKCS#8 PEM format (BEGIN PRIVATE KEY).
     *
     * @param  string              $privateKey 64-char hex private key
     * @return string              PEM-encoded private key
     * @throws InvalidKeyException If key format is invalid
     */
    public static function exportPrivateKeyPkcs8(string $privateKey): string
    {
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $privateKey)) {
            throw new InvalidKeyException('Private key must be 64 hex chars');
        }

        // PKCS#8 structure:
        // SEQUENCE {
        //   INTEGER 0 (version)
        //   SEQUENCE { OID ecPublicKey, OID sm2 }
        //   OCTET STRING { SEC1 private key structure }
        // }

        $version = "\x02\x01\x00"; // INTEGER 0

        $algId = self::encodeOid(self::OID_EC_PUBLIC_KEY);
        $curveOid = self::encodeOid(self::OID_SM2);
        $algSeq = "\x30" . self::encodeDerLength(strlen($algId) + strlen($curveOid)) . $algId . $curveOid;

        // SEC1 private key structure: SEQUENCE { INTEGER 1, OCTET STRING <key> }
        $sec1Version = "\x02\x01\x01"; // INTEGER 1
        $privKeyBytes = hex2bin($privateKey);
        if ($privKeyBytes === false) {
            throw new InvalidKeyException('Invalid private key hex');
        }
        $sec1KeyOctet = "\x04" . self::encodeDerLength(strlen($privKeyBytes)) . $privKeyBytes;
        $sec1Content = $sec1Version . $sec1KeyOctet;
        $sec1Seq = "\x30" . self::encodeDerLength(strlen($sec1Content)) . $sec1Content;

        $content = $version . $algSeq . "\x04" . self::encodeDerLength(strlen($sec1Seq)) . $sec1Seq;
        $sequence = "\x30" . self::encodeDerLength(strlen($content)) . $content;

        return self::wrapPem('PRIVATE KEY', $sequence);
    }

    /**
     * Export a public key in PEM format (BEGIN PUBLIC KEY).
     *
     * @param  string              $publicKey 128-char hex uncompressed public key
     * @return string              PEM-encoded public key
     * @throws InvalidKeyException If key format is invalid
     */
    public static function exportPublicKey(string $publicKey): string
    {
        if (!preg_match('/^[0-9a-fA-F]{128}$/', $publicKey)) {
            throw new InvalidKeyException('Public key must be 128 hex chars');
        }

        // SubjectPublicKeyInfo structure:
        // SEQUENCE {
        //   SEQUENCE { OID ecPublicKey, OID sm2 }
        //   BIT STRING <uncompressed point>
        // }

        $algId = self::encodeOid(self::OID_EC_PUBLIC_KEY);
        $curveOid = self::encodeOid(self::OID_SM2);
        $algSeq = "\x30" . self::encodeDerLength(strlen($algId) + strlen($curveOid)) . $algId . $curveOid;

        // Uncompressed point: 04 || x || y
        $pubPoint = "\x04" . hex2bin($publicKey);
        // BIT STRING: 00 (no unused bits) || point
        $bitString = "\x03" . self::encodeDerLength(strlen($pubPoint) + 1) . "\x00" . $pubPoint;

        $content = $algSeq . $bitString;
        $sequence = "\x30" . self::encodeDerLength(strlen($content)) . $content;

        return self::wrapPem('PUBLIC KEY', $sequence);
    }

    /**
     * Export a private key in SEC 1 DER format (raw binary).
     *
     * @param  string              $privateKey 64-char hex private key
     * @param  string              $publicKey  128-char hex uncompressed public key (optional)
     * @return string              DER-encoded binary data
     * @throws InvalidKeyException If key format is invalid
     */
    public static function exportPrivateKeyDer(string $privateKey, string $publicKey = ''): string
    {
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $privateKey)) {
            throw new InvalidKeyException('Private key must be 64 hex chars');
        }

        $version = "\x02\x01\x01";
        $privKeyBytes = hex2bin($privateKey);
        if ($privKeyBytes === false) {
            throw new InvalidKeyException('Invalid private key hex');
        }
        $privKeyOctetString = "\x04" . self::encodeDerLength(strlen($privKeyBytes)) . $privKeyBytes;

        $oidBytes = self::encodeOid(self::OID_SM2);
        $curveCtx = "\xa0" . self::encodeDerLength(strlen($oidBytes)) . $oidBytes;

        $pubKeyCtx = '';
        if ($publicKey !== '') {
            if (!preg_match('/^[0-9a-fA-F]{128}$/', $publicKey)) {
                throw new InvalidKeyException('Public key must be 128 hex chars');
            }
            $pubPoint = "\x04" . hex2bin($publicKey);
            $bitString = "\x03" . self::encodeDerLength(strlen($pubPoint) + 1) . "\x00" . $pubPoint;
            $pubKeyCtx = "\xa1" . self::encodeDerLength(strlen($bitString)) . $bitString;
        }

        $content = $version . $privKeyOctetString . $curveCtx . $pubKeyCtx;
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Export a private key in PKCS#8 DER format (raw binary).
     *
     * @param  string              $privateKey 64-char hex private key
     * @return string              DER-encoded binary data
     * @throws InvalidKeyException If key format is invalid
     */
    public static function exportPrivateKeyPkcs8Der(string $privateKey): string
    {
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $privateKey)) {
            throw new InvalidKeyException('Private key must be 64 hex chars');
        }

        $version = "\x02\x01\x00";

        $algId = self::encodeOid(self::OID_EC_PUBLIC_KEY);
        $curveOid = self::encodeOid(self::OID_SM2);
        $algSeq = "\x30" . self::encodeDerLength(strlen($algId) + strlen($curveOid)) . $algId . $curveOid;

        $sec1Version = "\x02\x01\x01";
        $privKeyBytes = hex2bin($privateKey);
        if ($privKeyBytes === false) {
            throw new InvalidKeyException('Invalid private key hex');
        }
        $sec1KeyOctet = "\x04" . self::encodeDerLength(strlen($privKeyBytes)) . $privKeyBytes;
        $sec1Content = $sec1Version . $sec1KeyOctet;
        $sec1Seq = "\x30" . self::encodeDerLength(strlen($sec1Content)) . $sec1Content;

        $content = $version . $algSeq . "\x04" . self::encodeDerLength(strlen($sec1Seq)) . $sec1Seq;
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Export a public key in DER format (raw binary, SubjectPublicKeyInfo).
     *
     * @param  string              $publicKey 128-char hex uncompressed public key
     * @return string              DER-encoded binary data
     * @throws InvalidKeyException If key format is invalid
     */
    public static function exportPublicKeyDer(string $publicKey): string
    {
        if (!preg_match('/^[0-9a-fA-F]{128}$/', $publicKey)) {
            throw new InvalidKeyException('Public key must be 128 hex chars');
        }

        $algId = self::encodeOid(self::OID_EC_PUBLIC_KEY);
        $curveOid = self::encodeOid(self::OID_SM2);
        $algSeq = "\x30" . self::encodeDerLength(strlen($algId) + strlen($curveOid)) . $algId . $curveOid;

        $pubPoint = "\x04" . hex2bin($publicKey);
        $bitString = "\x03" . self::encodeDerLength(strlen($pubPoint) + 1) . "\x00" . $pubPoint;

        $content = $algSeq . $bitString;
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Import a private key from PEM format.
     *
     * Supports both SEC 1 (EC PRIVATE KEY) and PKCS#8 (PRIVATE KEY) formats.
     *
     * @param  string                                       $pem PEM-encoded private key
     * @return array{privateKey: string, publicKey: string} Keys as hex strings
     * @throws InvalidKeyException                          If PEM format is invalid or unsupported
     */
    public static function importPrivateKey(string $pem): array
    {
        $der = self::pemToDer($pem);
        if ($der === '') {
            throw new InvalidKeyException('Invalid PEM data');
        }

        $label = self::getPemLabel($pem);

        if ($label === 'EC PRIVATE KEY') {
            return self::parseSec1PrivateKey($der);
        }

        if ($label === 'PRIVATE KEY') {
            return self::parsePkcs8PrivateKey($der);
        }

        throw new InvalidKeyException('Unsupported PEM type: ' . $label);
    }

    /**
     * Import a public key from PEM format.
     *
     * @param  string              $pem PEM-encoded public key
     * @return string              128-char hex uncompressed public key
     * @throws InvalidKeyException If PEM format is invalid
     */
    public static function importPublicKey(string $pem): string
    {
        $der = self::pemToDer($pem);
        if ($der === '') {
            throw new InvalidKeyException('Invalid PEM data');
        }

        $label = self::getPemLabel($pem);
        if ($label !== 'PUBLIC KEY') {
            throw new InvalidKeyException('Expected PUBLIC KEY PEM, got: ' . $label);
        }

        return self::parseSubjectPublicKeyInfo($der);
    }

    /**
     * Import a private key from DER binary data.
     *
     * Auto-detects SEC 1 vs PKCS#8 format based on the SEQUENCE content.
     *
     * @param  string                                       $der DER-encoded binary data
     * @return array{privateKey: string, publicKey: string} Keys as hex strings
     * @throws InvalidKeyException                          If DER format is invalid or unsupported
     */
    public static function importPrivateKeyFromDer(string $der): array
    {
        if (strlen($der) < 10) {
            throw new InvalidKeyException('Invalid DER data: too short');
        }

        // Peek into the SEQUENCE to detect format:
        // SEC 1:  SEQUENCE { INTEGER 1, OCTET STRING ... }
        // PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { OID ... } }
        // After SEQUENCE header and first INTEGER, version byte distinguishes:
        //   SEC 1  → version = 1 (0x01)
        //   PKCS#8 → version = 0 (0x00)
        $offset = 0;
        if (ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid DER: expected SEQUENCE');
        }
        $offset++;
        [, $offset] = self::parseDerLength($der, $offset);
        if (ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid DER: expected version INTEGER');
        }
        $offset++;
        [$verLen, $offset] = self::parseDerLength($der, $offset);
        $version = ord($der[$offset]);

        if ($version === 1) {
            return self::parseSec1PrivateKey($der);
        }
        if ($version === 0) {
            return self::parsePkcs8PrivateKey($der);
        }

        throw new InvalidKeyException('Unsupported DER private key version: ' . $version);
    }

    /**
     * Import a public key from DER binary data (SubjectPublicKeyInfo).
     *
     * @param  string              $der DER-encoded binary data
     * @return string              128-char hex uncompressed public key
     * @throws InvalidKeyException If DER format is invalid
     */
    public static function importPublicKeyFromDer(string $der): string
    {
        if (strlen($der) < 10) {
            throw new InvalidKeyException('Invalid DER data: too short');
        }

        return self::parseSubjectPublicKeyInfo($der);
    }

    // ─── DER Encoding Helpers ─────────────────────────────────────────────

    /**
     * Encode DER length field.
     */
    private static function encodeDerLength(int $len): string
    {
        if ($len < 128) {
            return chr($len & 0xFF);
        }
        $bytes = '';
        $temp = $len;
        do {
            $bytes = chr($temp & 0xFF) . $bytes;
            $temp >>= 8;
        } while ($temp > 0);
        return chr((0x80 | strlen($bytes)) & 0xFF) . $bytes;
    }

    /**
     * Encode an OID from dot notation to DER.
     */
    private static function encodeOid(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));
        $bytes = [40 * $parts[0] + $parts[1]];
        for ($i = 2, $count = count($parts); $i < $count; $i++) {
            $bytes = array_merge($bytes, self::encodeOidComponent($parts[$i]));
        }
        $content = implode('', array_map(static fn (int $b): string => chr($b & 0xFF), $bytes));
        return "\x06" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Encode a single OID component using base-128 encoding.
     *
     * @return array<int>
     */
    private static function encodeOidComponent(int $value): array
    {
        if ($value < 128) {
            return [$value];
        }
        $bytes = [$value & 0x7F];
        $value >>= 7;
        while ($value > 0) {
            $bytes = [0x80 | ($value & 0x7F), ...$bytes];
            $value >>= 7;
        }
        return $bytes;
    }

    // ─── PEM Helpers ──────────────────────────────────────────────────────

    private static function wrapPem(string $label, string $der): string
    {
        $b64 = base64_encode($der);
        $lines = str_split($b64, 64);
        return "-----BEGIN {$label}-----\n"
            . implode("\n", $lines)
            . "\n-----END {$label}-----\n";
    }

    private static function pemToDer(string $pem): string
    {
        // Strip headers/footers and whitespace
        $pem = preg_replace('/-----BEGIN [^-]+-----/', '', $pem) ?? '';
        $pem = preg_replace('/-----END [^-]+-----/', '', $pem) ?? '';
        $pem = preg_replace('/\s+/', '', $pem) ?? '';
        if ($pem === '') {
            return '';
        }
        $der = base64_decode($pem, true);
        return $der === false ? '' : $der;
    }

    private static function getPemLabel(string $pem): string
    {
        if (preg_match('/-----BEGIN ([^-]+)-----/', $pem, $m)) {
            return $m[1];
        }
        return '';
    }

    // ─── DER Parsing Helpers ──────────────────────────────────────────────

    /**
     * Parse DER length at offset.
     *
     * @return array{int, int} [length, newOffset]
     */
    private static function parseDerLength(string $data, int $offset): array
    {
        $byte = ord($data[$offset]);
        if ($byte < 128) {
            return [$byte, $offset + 1];
        }
        $numBytes = $byte & 0x7F;
        if ($numBytes > 4 || $offset + 1 + $numBytes > strlen($data)) {
            throw new InvalidKeyException('Invalid DER: length field too long');
        }
        $len = 0;
        for ($i = 0; $i < $numBytes; $i++) {
            $len = ($len << 8) | ord($data[$offset + 1 + $i]);
        }
        return [$len, $offset + 1 + $numBytes];
    }

    /**
     * Decode a DER-encoded OID starting at offset.
     *
     * @return array{string, int} [OID in dot notation, new offset]
     */
    private static function decodeOid(string $data, int $offset): array
    {
        if ($offset >= strlen($data) || ord($data[$offset]) !== 0x06) {
            throw new InvalidKeyException('Invalid DER: expected OID tag');
        }
        $offset++;
        [$len, $offset] = self::parseDerLength($data, $offset);
        if ($offset + $len > strlen($data)) {
            throw new InvalidKeyException('Invalid DER: OID length exceeds data');
        }
        $oidBytes = substr($data, $offset, $len);
        $offset += $len;

        $components = [];
        $components[] = (int) (ord($oidBytes[0]) / 40);
        $components[] = ord($oidBytes[0]) % 40;
        $value = 0;
        for ($i = 1; $i < strlen($oidBytes); $i++) {
            $value = ($value << 7) | (ord($oidBytes[$i]) & 0x7F);
            if (!(ord($oidBytes[$i]) & 0x80)) {
                $components[] = $value;
                $value = 0;
            }
        }

        return [implode('.', $components), $offset];
    }

    /**
     * Parse SEC 1 private key DER.
     *
     * @return array{privateKey: string, publicKey: string}
     */
    private static function parseSec1PrivateKey(string $der): array
    {
        $offset = 0;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid SEC1 private key: expected SEQUENCE');
        }
        $offset++;
        [, $offset] = self::parseDerLength($der, $offset);

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid SEC1 private key: expected version INTEGER');
        }
        $offset++;
        [$verLen, $offset] = self::parseDerLength($der, $offset);
        $offset += $verLen;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x04) {
            throw new InvalidKeyException('Invalid SEC1 private key: expected OCTET STRING');
        }
        $offset++;
        [$keyLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $keyLen > strlen($der)) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $privateKeyBin = substr($der, $offset, $keyLen);
        $offset += $keyLen;

        $privateKey = str_pad(bin2hex($privateKeyBin), 64, '0', STR_PAD_LEFT);

        $publicKey = '';
        if ($offset < strlen($der)) {
            $tag = ord($der[$offset]);
            if ($tag === 0xA1) {
                $offset++;
                [$ctxLen, $offset] = self::parseDerLength($der, $offset);
                if ($offset >= strlen($der) || ord($der[$offset]) !== 0x03) {
                    throw new InvalidKeyException('Invalid SEC1 private key: expected BIT STRING in [1]');
                }
                $offset++;
                [$bsLen, $offset] = self::parseDerLength($der, $offset);
                if ($offset >= strlen($der)) {
                    throw new InvalidKeyException('Invalid DER: unexpected end of data');
                }
                $unusedBits = ord($der[$offset]);
                $offset++;
                if ($offset + $bsLen - 1 > strlen($der)) {
                    throw new InvalidKeyException('Invalid DER: unexpected end of data');
                }
                $pointData = substr($der, $offset, $bsLen - 1);
                if (strlen($pointData) === 65 && ord($pointData[0]) === 0x04) {
                    $publicKey = bin2hex(substr($pointData, 1));
                }
            }
        }

        if ($publicKey === '') {
            $publicKey = Sm2::getPublicKey($privateKey);
        }

        return ['privateKey' => $privateKey, 'publicKey' => $publicKey];
    }

    /**
     * Parse PKCS#8 private key DER.
     *
     * @return array{privateKey: string, publicKey: string}
     */
    private static function parsePkcs8PrivateKey(string $der): array
    {
        $offset = 0;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected SEQUENCE');
        }
        $offset++;
        [, $offset] = self::parseDerLength($der, $offset);

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected version INTEGER');
        }
        $offset++;
        [$verLen, $offset] = self::parseDerLength($der, $offset);
        $offset += $verLen;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected algorithm SEQUENCE');
        }
        $offset++;
        [$algSeqLen, $offset] = self::parseDerLength($der, $offset);
        $offset += $algSeqLen;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x04) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected OCTET STRING');
        }
        $offset++;
        [$octLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $octLen > strlen($der)) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $innerDer = substr($der, $offset, $octLen);

        if (strlen($innerDer) > 0 && ord($innerDer[0]) === 0x30) {
            return self::parseSec1PrivateKeyInner($innerDer);
        }

        $privateKeyBin = $innerDer;
        $privateKey = str_pad(bin2hex($privateKeyBin), 64, '0', STR_PAD_LEFT);
        $publicKey = Sm2::getPublicKey($privateKey);

        return ['privateKey' => $privateKey, 'publicKey' => $publicKey];
    }

    /**
     * Parse inner SEC1 structure (without outer SEQUENCE wrapper).
     *
     * The PKCS#8 OCTET STRING contains a full SEC1 structure:
     * SEQUENCE { INTEGER 1, OCTET STRING <key> }
     *
     * @return array{privateKey: string, publicKey: string}
     */
    private static function parseSec1PrivateKeyInner(string $der): array
    {
        $offset = 0;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid SEC1 inner: expected SEQUENCE');
        }
        $offset++;
        [$seqLen, $offset] = self::parseDerLength($der, $offset);

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid SEC1 inner: expected version INTEGER');
        }
        $offset++;
        [$verLen, $offset] = self::parseDerLength($der, $offset);
        $offset += $verLen;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x04) {
            throw new InvalidKeyException('Invalid SEC1 inner: expected OCTET STRING');
        }
        $offset++;
        [$keyLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $keyLen > strlen($der)) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $privateKeyBin = substr($der, $offset, $keyLen);

        $privateKey = str_pad(bin2hex($privateKeyBin), 64, '0', STR_PAD_LEFT);

        $publicKey = '';
        $offset += $keyLen;
        if ($offset < strlen($der)) {
            $tag = ord($der[$offset]);
            if ($tag === 0xA1) {
                $offset++;
                [$ctxLen, $offset] = self::parseDerLength($der, $offset);
                if ($offset >= strlen($der) || ord($der[$offset]) !== 0x03) {
                    throw new InvalidKeyException('Invalid SEC1 inner: expected BIT STRING in [1]');
                }
                $offset++;
                [$bsLen, $offset] = self::parseDerLength($der, $offset);
                if ($offset >= strlen($der)) {
                    throw new InvalidKeyException('Invalid DER: unexpected end of data');
                }
                $unusedBits = ord($der[$offset]);
                $offset++;
                if ($offset + $bsLen - 1 > strlen($der)) {
                    throw new InvalidKeyException('Invalid DER: unexpected end of data');
                }
                $pointData = substr($der, $offset, $bsLen - 1);
                if (strlen($pointData) === 65 && ord($pointData[0]) === 0x04) {
                    $publicKey = bin2hex(substr($pointData, 1));
                }
            }
        }

        if ($publicKey === '') {
            $publicKey = Sm2::getPublicKey($privateKey);
        }

        return ['privateKey' => $privateKey, 'publicKey' => $publicKey];
    }

    /**
     * Parse SubjectPublicKeyInfo DER.
     */
    private static function parseSubjectPublicKeyInfo(string $der): string
    {
        $offset = 0;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid public key: expected SEQUENCE');
        }
        $offset++;
        [, $offset] = self::parseDerLength($der, $offset);

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid public key: expected algorithm SEQUENCE');
        }
        $offset++;
        [$algSeqLen, $offset] = self::parseDerLength($der, $offset);
        $algSeqEnd = $offset + $algSeqLen;

        [$algOid, $offset] = self::decodeOid($der, $offset);
        if ($algOid !== self::OID_EC_PUBLIC_KEY) {
            throw new InvalidKeyException('Invalid public key: expected ecPublicKey algorithm, got ' . $algOid);
        }
        [$curveOid, $offset] = self::decodeOid($der, $offset);
        if ($curveOid !== self::OID_SM2) {
            throw new InvalidKeyException('Invalid public key: expected SM2 curve OID, got ' . $curveOid);
        }

        $offset = $algSeqEnd;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x03) {
            throw new InvalidKeyException('Invalid public key: expected BIT STRING');
        }
        $offset++;
        [$bsLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset >= strlen($der)) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $unusedBits = ord($der[$offset]);
        $offset++;
        if ($offset + $bsLen - 1 > strlen($der)) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $pointData = substr($der, $offset, $bsLen - 1);

        if (strlen($pointData) !== 65 || ord($pointData[0]) !== 0x04) {
            throw new InvalidKeyException('Invalid public key: expected uncompressed point (04 || x || y)');
        }

        return bin2hex(substr($pointData, 1));
    }
}
