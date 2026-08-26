<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Crypto\Asn1;
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
        return self::wrapPem('EC PRIVATE KEY', self::buildSec1PrivateKeyDer($privateKey, $publicKey));
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
        return self::wrapPem('PRIVATE KEY', self::buildPkcs8PrivateKeyDer($privateKey));
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
        return self::wrapPem('PUBLIC KEY', self::buildSpkiPublicKeyDer($publicKey));
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
        return self::buildSec1PrivateKeyDer($privateKey, $publicKey);
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
        return self::buildPkcs8PrivateKeyDer($privateKey);
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
        return self::buildSpkiPublicKeyDer($publicKey);
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
        [$seqLen, $offset] = self::parseDerLength($der, $offset);
        $seqEnd = $offset + $seqLen;
        if ($seqEnd !== strlen($der)) {
            throw new InvalidKeyException('Invalid DER: trailing data after private key');
        }
        if ($offset >= $seqEnd || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid DER: expected version INTEGER');
        }
        $offset++;
        [$verLen, $offset] = self::parseDerLength($der, $offset);
        if ($verLen !== 1 || $offset + $verLen > $seqEnd) {
            throw new InvalidKeyException('Invalid DER: invalid version INTEGER');
        }
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
     * Build an AlgorithmIdentifier SEQUENCE: SEQUENCE { OID ecPublicKey, OID sm2 }.
     */
    private static function buildAlgorithmIdentifier(): string
    {
        $algId = self::encodeOid(self::OID_EC_PUBLIC_KEY);
        $curveOid = self::encodeOid(self::OID_SM2);
        return "\x30" . self::encodeDerLength(strlen($algId) + strlen($curveOid)) . $algId . $curveOid;
    }

    /**
     * Encode an uncompressed EC point as a DER BIT STRING (0x00 || 0x04 || x || y).
     *
     * @param  string              $publicKeyHex 128-char hex public key
     * @throws InvalidKeyException If the public key format is invalid
     */
    private static function encodeBitStringPoint(string $publicKeyHex): string
    {
        $pubPoint = "\x04" . hex2bin($publicKeyHex);
        // BIT STRING: 00 (no unused bits) || uncompressed point
        return "\x03" . self::encodeDerLength(strlen($pubPoint) + 1) . "\x00" . $pubPoint;
    }

    /**
     * Build a SEC 1 EC private key DER structure:
     * SEQUENCE { INTEGER 1, OCTET STRING <key>, [0] OID <curve>, [1] BIT STRING <pub> }
     *
     * @param  string              $privateKey 64-char hex private key
     * @param  string              $publicKey  128-char hex public key (optional)
     * @throws InvalidKeyException If key format is invalid
     */
    private static function buildSec1PrivateKeyDer(string $privateKey, string $publicKey = ''): string
    {
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $privateKey)) {
            throw new InvalidKeyException('Private key must be 64 hex chars');
        }
        $privKeyBytes = hex2bin($privateKey);
        if ($privKeyBytes === false) {
            throw new InvalidKeyException('Invalid private key hex');
        }

        $version = "\x02\x01\x01"; // INTEGER 1
        $privKeyOctetString = "\x04" . self::encodeDerLength(strlen($privKeyBytes)) . $privKeyBytes;
        $oidBytes = self::encodeOid(self::OID_SM2);
        $curveCtx = "\xa0" . self::encodeDerLength(strlen($oidBytes)) . $oidBytes;

        $pubKeyCtx = '';
        if ($publicKey !== '') {
            if (!preg_match('/^[0-9a-fA-F]{128}$/', $publicKey)) {
                throw new InvalidKeyException('Public key must be 128 hex chars');
            }
            $bitString = self::encodeBitStringPoint($publicKey);
            $pubKeyCtx = "\xa1" . self::encodeDerLength(strlen($bitString)) . $bitString;
        }

        $content = $version . $privKeyOctetString . $curveCtx . $pubKeyCtx;
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Build a PKCS#8 private key DER structure:
     * SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING { inner SEC 1 } }
     *
     * @param  string              $privateKey 64-char hex private key
     * @throws InvalidKeyException If key format is invalid
     */
    private static function buildPkcs8PrivateKeyDer(string $privateKey): string
    {
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $privateKey)) {
            throw new InvalidKeyException('Private key must be 64 hex chars');
        }
        $privKeyBytes = hex2bin($privateKey);
        if ($privKeyBytes === false) {
            throw new InvalidKeyException('Invalid private key hex');
        }

        $version = "\x02\x01\x00"; // INTEGER 0

        // Inner SEC1 structure: SEQUENCE { INTEGER 1, OCTET STRING <key> }
        $sec1Version = "\x02\x01\x01";
        $sec1KeyOctet = "\x04" . self::encodeDerLength(strlen($privKeyBytes)) . $privKeyBytes;
        $sec1Content = $sec1Version . $sec1KeyOctet;
        $sec1Seq = "\x30" . self::encodeDerLength(strlen($sec1Content)) . $sec1Content;

        $content = $version . self::buildAlgorithmIdentifier()
            . "\x04" . self::encodeDerLength(strlen($sec1Seq)) . $sec1Seq;
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Build a SubjectPublicKeyInfo DER structure:
     * SEQUENCE { AlgorithmIdentifier, BIT STRING <uncompressed point> }
     *
     * @param  string              $publicKey 128-char hex public key
     * @throws InvalidKeyException If key format is invalid
     */
    private static function buildSpkiPublicKeyDer(string $publicKey): string
    {
        if (!preg_match('/^[0-9a-fA-F]{128}$/', $publicKey)) {
            throw new InvalidKeyException('Public key must be 128 hex chars');
        }
        $content = self::buildAlgorithmIdentifier() . self::encodeBitStringPoint($publicKey);
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Encode DER length field.
     *
     * Delegates to Asn1::encodeLength() to avoid code duplication.
     */
    private static function encodeDerLength(int $len): string
    {
        return Asn1::encodeLength($len);
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
        // Require a well-formed, matching BEGIN/END pair; anything outside the
        // armor boundaries is ignored per common PEM practice.
        if (!preg_match('/-----BEGIN ([^-]+)-----(.*?)-----END \1-----/s', $pem, $m)) {
            return '';
        }
        $body = preg_replace('/\s+/', '', $m[2]) ?? '';
        if ($body === '') {
            return '';
        }
        $der = base64_decode($body, true);
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
        if ($offset >= strlen($data)) {
            throw new InvalidKeyException('Invalid DER: unexpected end of length field');
        }
        $byte = ord($data[$offset]);
        if ($byte < 128) {
            return [$byte, $offset + 1];
        }
        $numBytes = $byte & 0x7F;
        if ($numBytes === 0) {
            throw new InvalidKeyException('Invalid DER: indefinite length is not allowed');
        }
        if ($numBytes > 4 || $offset + 1 + $numBytes > strlen($data)) {
            throw new InvalidKeyException('Invalid DER: length field too long');
        }
        if ($numBytes > 1 && ord($data[$offset + 1]) === 0x00) {
            throw new InvalidKeyException('Invalid DER: non-minimal length encoding');
        }
        $len = 0;
        for ($i = 0; $i < $numBytes; $i++) {
            $len = ($len << 8) | ord($data[$offset + 1 + $i]);
        }
        if ($len < 128) {
            throw new InvalidKeyException('Invalid DER: non-minimal length encoding');
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
        if ($oidBytes === '') {
            throw new InvalidKeyException('Invalid DER: empty OID');
        }

        $subIdentifiers = [];
        $value = 0;
        for ($i = 0; $i < strlen($oidBytes); $i++) {
            $byte = ord($oidBytes[$i]);
            $value = ($value << 7) | ($byte & 0x7F);
            if (($byte & 0x80) === 0) {
                $subIdentifiers[] = $value;
                $value = 0;
            }
        }
        if ((ord($oidBytes[strlen($oidBytes) - 1]) & 0x80) !== 0) {
            throw new InvalidKeyException('Invalid DER: unterminated OID component');
        }
        if ($subIdentifiers === []) {
            throw new InvalidKeyException('Invalid DER: empty OID');
        }

        $first = array_shift($subIdentifiers);
        if ($first < 40) {
            $components = [0, $first];
        } elseif ($first < 80) {
            $components = [1, $first - 40];
        } else {
            $components = [2, $first - 80];
        }
        foreach ($subIdentifiers as $component) {
            $components[] = $component;
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
        return self::parseSec1Structure($der, 'Invalid SEC1 private key');
    }

    /**
     * Parse a SEC 1 EC private key structure:
     * SEQUENCE { INTEGER 1, OCTET STRING <key>, [0] OID <curve>, [1] BIT STRING <pub> }
     *
     * Handles both the standalone SEC 1 format and the inner SEC 1 payload
     * embedded in a PKCS#8 OCTET STRING; only the error message prefix differs.
     *
     * @param  string                                       $der         DER-encoded SEC 1 structure
     * @param  string                                       $errorPrefix Prefix used in format-specific error messages
     * @return array{privateKey: string, publicKey: string}
     */
    private static function parseSec1Structure(string $der, string $errorPrefix): array
    {
        $prefix = $errorPrefix . ': ';
        $offset = 0;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException($prefix . 'expected SEQUENCE');
        }
        $offset++;
        [$seqLen, $offset] = self::parseDerLength($der, $offset);
        $seqEnd = $offset + $seqLen;
        if ($seqEnd !== strlen($der)) {
            throw new InvalidKeyException($prefix . 'trailing data');
        }

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException($prefix . 'expected version INTEGER');
        }
        $offset++;
        [$verLen, $offset] = self::parseDerLength($der, $offset);
        if ($verLen !== 1 || $offset + $verLen > $seqEnd || ord($der[$offset]) !== 1) {
            throw new InvalidKeyException($prefix . 'invalid version');
        }
        $offset += $verLen;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x04) {
            throw new InvalidKeyException($prefix . 'expected OCTET STRING');
        }
        $offset++;
        [$keyLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $keyLen > $seqEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $privateKeyBin = substr($der, $offset, $keyLen);
        $offset += $keyLen;
        if ($keyLen < 1 || $keyLen > 32) {
            throw new InvalidKeyException($prefix . 'invalid private key length');
        }

        $privateKey = str_pad(bin2hex($privateKeyBin), 64, '0', STR_PAD_LEFT);
        Sm2::validatePrivateKey($privateKey);

        $publicKey = '';
        if ($offset < $seqEnd) {
            $tag = ord($der[$offset]);
            if ($tag === 0xA0) {
                $offset++;
                [$ctxLen, $offset] = self::parseDerLength($der, $offset);
                $ctxEnd = $offset + $ctxLen;
                if ($ctxEnd > $seqEnd) {
                    throw new InvalidKeyException('Invalid DER: unexpected end of data');
                }
                [$curveOid, $offset] = self::decodeOid($der, $offset);
                if ($curveOid !== self::OID_SM2) {
                    throw new InvalidKeyException($prefix . 'expected SM2 curve OID, got ' . $curveOid);
                }
                if ($offset !== $ctxEnd) {
                    throw new InvalidKeyException($prefix . 'invalid curve parameters');
                }
                $offset = $ctxEnd;
            }
        }
        if ($offset < $seqEnd) {
            $tag = ord($der[$offset]);
            if ($tag === 0xA1) {
                [$publicKey, $offset] = self::parseSec1PublicKeyBitString($der, $offset, $seqEnd, $prefix);
            }
        }

        if ($offset !== $seqEnd) {
            throw new InvalidKeyException($prefix . 'trailing data');
        }

        if ($publicKey === '') {
            $publicKey = Sm2::getPublicKey($privateKey);
        }
        self::validateImportedKeyPair($privateKey, $publicKey);

        return ['privateKey' => $privateKey, 'publicKey' => $publicKey];
    }

    /**
     * Parse the context-specific [1] element holding the optional public key:
     * [1] BIT STRING (0x00 || 0x04 || x || y).
     *
     * @param  string             $der    DER data
     * @param  int                $offset Offset of the 0xA1 tag
     * @param  int                $seqEnd End offset of the enclosing SEQUENCE
     * @param  string             $prefix Error message prefix
     * @return array{string, int} [128-char hex public key, offset past the [1] element]
     */
    private static function parseSec1PublicKeyBitString(string $der, int $offset, int $seqEnd, string $prefix): array
    {
        $offset++;
        [$ctxLen, $offset] = self::parseDerLength($der, $offset);
        $ctxEnd = $offset + $ctxLen;
        if ($ctxEnd > $seqEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x03) {
            throw new InvalidKeyException($prefix . 'expected BIT STRING in [1]');
        }
        $offset++;
        [$bsLen, $offset] = self::parseDerLength($der, $offset);
        if ($bsLen < 1 || $offset >= $ctxEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $unusedBits = ord($der[$offset]);
        if ($unusedBits !== 0) {
            throw new InvalidKeyException($prefix . 'public key BIT STRING has unused bits');
        }
        $offset++;
        if ($offset + $bsLen - 1 > $ctxEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        if ($offset + $bsLen - 1 !== $ctxEnd) {
            throw new InvalidKeyException($prefix . 'invalid public key parameters');
        }
        $pointData = substr($der, $offset, $bsLen - 1);
        if ($pointData === '') {
            throw new InvalidKeyException($prefix . 'empty public key BIT STRING content');
        }
        $pointTag = ord($pointData[0]);
        if ($pointTag === 0x02 || $pointTag === 0x03) {
            // Compressed point: recover y from x and parity bit
            if (strlen($pointData) !== 33) {
                throw new InvalidKeyException($prefix . 'invalid compressed point length (expected 0x02/03 || x, 33 bytes)');
            }
            $xHex = bin2hex(substr($pointData, 1));
            try {
                $pubHex = Sm2::decompressPublicKey($xHex, $pointTag);
            } catch (\CryptoSm\Exception\CryptoException $e) {
                throw new InvalidKeyException($prefix . $e->getMessage(), 0, $e);
            }
            return [substr($pubHex, 0, 128), $ctxEnd];
        }
        if (strlen($pointData) !== 65 || $pointTag !== 0x04) {
            throw new InvalidKeyException($prefix . 'expected uncompressed public key (0x04 || x || y)');
        }
        return [bin2hex(substr($pointData, 1)), $ctxEnd];
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
        [$seqLen, $offset] = self::parseDerLength($der, $offset);
        $seqEnd = $offset + $seqLen;
        if ($seqEnd !== strlen($der)) {
            throw new InvalidKeyException('Invalid PKCS8 private key: trailing data');
        }

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected version INTEGER');
        }
        $offset++;
        [$verLen, $offset] = self::parseDerLength($der, $offset);
        if ($verLen !== 1 || $offset + $verLen > $seqEnd || ord($der[$offset]) !== 0) {
            throw new InvalidKeyException('Invalid PKCS8 private key: invalid version');
        }
        $offset += $verLen;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected algorithm SEQUENCE');
        }
        $offset++;
        [$algSeqLen, $offset] = self::parseDerLength($der, $offset);
        $algSeqEnd = $offset + $algSeqLen;
        if ($algSeqEnd > $seqEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        [$algOid, $offset] = self::decodeOid($der, $offset);
        if ($algOid !== self::OID_EC_PUBLIC_KEY) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected ecPublicKey algorithm, got ' . $algOid);
        }
        [$curveOid, $offset] = self::decodeOid($der, $offset);
        if ($curveOid !== self::OID_SM2) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected SM2 curve OID, got ' . $curveOid);
        }
        if ($offset !== $algSeqEnd) {
            throw new InvalidKeyException('Invalid PKCS8 private key: invalid algorithm parameters');
        }
        $offset = $algSeqEnd;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x04) {
            throw new InvalidKeyException('Invalid PKCS8 private key: expected OCTET STRING');
        }
        $offset++;
        [$octLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $octLen > $seqEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $innerDer = substr($der, $offset, $octLen);
        $offset += $octLen;
        if ($offset !== $seqEnd) {
            throw new InvalidKeyException('Invalid PKCS8 private key: trailing data');
        }

        if (strlen($innerDer) > 0 && ord($innerDer[0]) === 0x30) {
            return self::parseSec1PrivateKeyInner($innerDer);
        }

        $privateKeyBin = $innerDer;
        if (strlen($privateKeyBin) < 1 || strlen($privateKeyBin) > 32) {
            throw new InvalidKeyException('Invalid PKCS8 private key length');
        }
        $privateKey = str_pad(bin2hex($privateKeyBin), 64, '0', STR_PAD_LEFT);
        Sm2::validatePrivateKey($privateKey);
        $publicKey = Sm2::getPublicKey($privateKey);

        return ['privateKey' => $privateKey, 'publicKey' => $publicKey];
    }

    /**
     * Parse inner SEC1 structure (without outer SEQUENCE wrapper).
     *
     * The PKCS#8 OCTET STRING contains a full SEC1 structure:
     * SEQUENCE { INTEGER 1, OCTET STRING <key>, [0] OID <curve>, [1] BIT STRING <pub> }
     *
     * @return array{privateKey: string, publicKey: string}
     */
    private static function parseSec1PrivateKeyInner(string $der): array
    {
        return self::parseSec1Structure($der, 'Invalid SEC1 inner');
    }

    private static function validateImportedKeyPair(string $privateKey, string $publicKey): void
    {
        Sm2::validatePrivateKey($privateKey);
        if (!Sm2::isOnCurve($publicKey)) {
            throw new InvalidKeyException('Invalid imported public key: not on SM2 curve');
        }
        $derived = Sm2::getPublicKey($privateKey);
        if (!hash_equals(strtolower($derived), strtolower($publicKey))) {
            throw new InvalidKeyException('Invalid imported key pair: public key does not match private key');
        }
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
        [$seqLen, $offset] = self::parseDerLength($der, $offset);
        $seqEnd = $offset + $seqLen;
        if ($seqEnd !== strlen($der)) {
            throw new InvalidKeyException('Invalid public key: trailing data');
        }

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid public key: expected algorithm SEQUENCE');
        }
        $offset++;
        [$algSeqLen, $offset] = self::parseDerLength($der, $offset);
        $algSeqEnd = $offset + $algSeqLen;
        if ($algSeqEnd > $seqEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }

        [$algOid, $offset] = self::decodeOid($der, $offset);
        if ($algOid !== self::OID_EC_PUBLIC_KEY) {
            throw new InvalidKeyException('Invalid public key: expected ecPublicKey algorithm, got ' . $algOid);
        }
        [$curveOid, $offset] = self::decodeOid($der, $offset);
        if ($curveOid !== self::OID_SM2) {
            throw new InvalidKeyException('Invalid public key: expected SM2 curve OID, got ' . $curveOid);
        }
        if ($offset !== $algSeqEnd) {
            throw new InvalidKeyException('Invalid public key: invalid algorithm parameters');
        }

        $offset = $algSeqEnd;

        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x03) {
            throw new InvalidKeyException('Invalid public key: expected BIT STRING');
        }
        $offset++;
        [$bsLen, $offset] = self::parseDerLength($der, $offset);
        if ($bsLen < 1 || $offset >= $seqEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $unusedBits = ord($der[$offset]);
        if ($unusedBits !== 0) {
            throw new InvalidKeyException('Invalid public key: BIT STRING has unused bits');
        }
        $offset++;
        if ($offset + $bsLen - 1 > $seqEnd) {
            throw new InvalidKeyException('Invalid DER: unexpected end of data');
        }
        $pointData = substr($der, $offset, $bsLen - 1);
        $offset += $bsLen - 1;

        if ($pointData === '') {
            throw new InvalidKeyException('Invalid public key: empty BIT STRING content');
        }
        $pointTag = ord($pointData[0]);
        if ($pointTag === 0x02 || $pointTag === 0x03) {
            $publicKey = Sm2::decompressPublicKey(bin2hex(substr($pointData, 1)), $pointTag);
            if (!Sm2::isOnCurve($publicKey)) {
                throw new InvalidKeyException('Invalid public key: decompressed point not on SM2 curve');
            }
            if ($offset !== $seqEnd) {
                throw new InvalidKeyException('Invalid public key: trailing data');
            }
            return $publicKey;
        }
        if (strlen($pointData) !== 65 || $pointTag !== 0x04) {
            throw new InvalidKeyException('Invalid public key: expected uncompressed point (0x04 || x || y)');
        }

        $publicKey = bin2hex(substr($pointData, 1));
        if (!Sm2::isOnCurve($publicKey)) {
            throw new InvalidKeyException('Invalid public key: not on SM2 curve');
        }
        if ($offset !== $seqEnd) {
            throw new InvalidKeyException('Invalid public key: trailing data');
        }

        return $publicKey;
    }

    // ─── SM2 密文 ASN.1 格式（GM/T 0009-2012）────────────────────────────

    /**
     * Export an SM2 ciphertext in GM/T 0009 ASN.1 DER format.
     *
     * SM2Cipher ::= SEQUENCE {
     *     xCoordinate  INTEGER,
     *     yCoordinate  INTEGER,
     *     hash         OCTET STRING SIZE(32),
     *     cipherText   OCTET STRING
     * }
     *
     * @param  string              $ciphertextHex Internal hex ciphertext (C1C3C2 or C1C2C3)
     * @param  int                 $mode          Sm2::CIPHER_MODE_1 (C1C3C2) or Sm2::CIPHER_MODE_0 (C1C2C3)
     * @return string              DER-encoded binary
     * @throws InvalidKeyException If ciphertext format is invalid
     */
    public static function exportCiphertextAsn1(string $ciphertextHex, int $mode = Sm2::CIPHER_MODE_1): string
    {
        $c1Len = 128; // x||y, uncompressed point without 04 prefix
        $hashLen = 64; // SM3 output, 32 bytes
        if (strlen($ciphertextHex) < $c1Len + $hashLen) {
            throw new InvalidKeyException('Ciphertext too short for SM2 format');
        }
        $x1 = substr($ciphertextHex, 0, 64);
        $y1 = substr($ciphertextHex, 64, 64);
        if ($mode === Sm2::CIPHER_MODE_0) {
            $c2 = substr($ciphertextHex, 128, -64);
            $c3 = substr($ciphertextHex, -64);
        } else {
            $c3 = substr($ciphertextHex, 128, 64);
            $c2 = substr($ciphertextHex, 192);
        }
        if (!preg_match('/^[0-9a-fA-F]+$/', $x1) || !preg_match('/^[0-9a-fA-F]+$/', $y1)) {
            throw new InvalidKeyException('Ciphertext C1 is not valid hex');
        }

        // Strip leading zero bytes from coordinates for DER INTEGER encoding,
        // but preserve at least one byte and add a leading 0x00 when high bit is set
        $x1Int = ltrim($x1, '0');
        if ($x1Int === '') {
            $x1Int = '00';
        } elseif (strlen($x1Int) % 2 !== 0) {
            $x1Int = '0' . $x1Int;
        }
        $x1Bytes = (string) hex2bin($x1Int);
        if (ord($x1Bytes[0]) >= 0x80) {
            $x1Bytes = "\x00" . $x1Bytes;
        }

        $y1Int = ltrim($y1, '0');
        if ($y1Int === '') {
            $y1Int = '00';
        } elseif (strlen($y1Int) % 2 !== 0) {
            $y1Int = '0' . $y1Int;
        }
        $y1Bytes = (string) hex2bin($y1Int);
        if (ord($y1Bytes[0]) >= 0x80) {
            $y1Bytes = "\x00" . $y1Bytes;
        }

        $c3Bin = (string) hex2bin($c3);
        $c2Bin = (string) hex2bin($c2);

        // Build TLV elements
        $intX = "\x02" . self::encodeDerLength(strlen($x1Bytes)) . $x1Bytes;
        $intY = "\x02" . self::encodeDerLength(strlen($y1Bytes)) . $y1Bytes;
        $octHash = "\x04" . self::encodeDerLength(strlen($c3Bin)) . $c3Bin;
        $octCipher = "\x04" . self::encodeDerLength(strlen($c2Bin)) . $c2Bin;

        $content = $intX . $intY . $octHash . $octCipher;
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Import an SM2 ciphertext from GM/T 0009 ASN.1 DER format.
     *
     * @param  string              $der  DER-encoded SM2Cipher
     * @param  int                 $mode Target internal mode: Sm2::CIPHER_MODE_1 or Sm2::CIPHER_MODE_0
     * @return string              Internal hex ciphertext in the requested mode
     * @throws InvalidKeyException If the DER structure is invalid
     */
    public static function importCiphertextAsn1(string $der, int $mode = Sm2::CIPHER_MODE_1): string
    {
        $offset = 0;
        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x30) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: expected SEQUENCE');
        }
        $offset++;
        [$seqLen, $offset] = self::parseDerLength($der, $offset);
        $seqEnd = $offset + $seqLen;
        if ($seqEnd !== strlen($der)) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: trailing data');
        }

        // Parse x1 INTEGER
        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: expected x INTEGER');
        }
        $offset++;
        [$xLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $xLen > $seqEnd || $xLen < 1 || $xLen > 33) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: invalid x length');
        }
        $x1Bin = substr($der, $offset, $xLen);
        $offset += $xLen;

        // Parse y1 INTEGER
        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: expected y INTEGER');
        }
        $offset++;
        [$yLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $yLen > $seqEnd || $yLen < 1 || $yLen > 33) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: invalid y length');
        }
        $y1Bin = substr($der, $offset, $yLen);
        $offset += $yLen;

        // Parse hash OCTET STRING
        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x04) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: expected hash OCTET STRING');
        }
        $offset++;
        [$hLen, $offset] = self::parseDerLength($der, $offset);
        if ($hLen !== 32) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: hash must be 32 bytes');
        }
        $c3Bin = substr($der, $offset, $hLen);
        $offset += $hLen;

        // Parse cipherText OCTET STRING
        if ($offset >= strlen($der) || ord($der[$offset]) !== 0x04) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: expected cipherText OCTET STRING');
        }
        $offset++;
        [$ctLen, $offset] = self::parseDerLength($der, $offset);
        if ($offset + $ctLen !== $seqEnd) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: cipherText length mismatch');
        }
        $c2Bin = substr($der, $offset, $ctLen);

        // Reconstruct coordinates as fixed-width 32-byte big-endian.
        // DER INTEGER may include a leading 0x00 sign-bit pad (making it 33 bytes),
        // so always take the last 32 bytes and left-pad with zeros.
        $x1 = str_pad(substr(bin2hex($x1Bin), -64), 64, '0', STR_PAD_LEFT);
        $y1 = str_pad(substr(bin2hex($y1Bin), -64), 64, '0', STR_PAD_LEFT);

        // Validate point on curve
        $c1 = strtolower($x1 . $y1);
        if (!Sm2::isOnCurve($c1)) {
            throw new InvalidKeyException('Invalid SM2 cipher ASN.1: C1 point not on curve');
        }

        $c3 = bin2hex($c3Bin);
        $c2 = bin2hex($c2Bin);

        if ($mode === Sm2::CIPHER_MODE_0) {
            return strtolower($c1 . $c2 . $c3);
        }
        return strtolower($c1 . $c3 . $c2);
    }
}
