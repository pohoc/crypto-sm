<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM3\Sm3;
use CryptoSm\Utils\Hex;

/**
 * SM2 key exchange implementation (GM/T 0003-2012 Section 6).
 *
 * Implements the SM2 key exchange protocol (ECDH-style with SM2-specific derivation).
 * Two parties (initiator A and responder B) exchange temporary public keys
 * and derive a shared secret key.
 *
 * Protocol flow:
 * 1. A generates ephemeral keypair (rA, RA), sends RA to B
 * 2. B generates ephemeral keypair (rB, RB), sends RB to A
 * 3. A computes shared key using: dA, rA, PB, RB
 * 4. B computes shared key using: dB, rB, PA, RA
 * 5. Both derive the same key
 */
class KeyExchange
{
    /**
     * Generate an ephemeral keypair for key exchange.
     *
     * @return Keypair Ephemeral keypair (rA or rB)
     */
    public static function generateEphemeralKeyPair(): Keypair
    {
        return Sm2::generateKeyPairHex();
    }

    /**
     * Compute the shared secret key (initiator side).
     *
     * Per GM/T 0003-2012 Section 6.1:
     * sA = (h * dA + x̄A * rA) mod n
     * V  = (h * sA) * (PB + x̄B * RB)
     * K  = KDF(xV || yV || ENTLA || IDA || ENTLB || IDB || xRA || yRA || xRB || yRB, klen)
     *
     * @param  string              $dA   Initiator's static private key (64-char hex)
     * @param  string              $rA   Initiator's ephemeral private key (64-char hex)
     * @param  string              $PB   Responder's static public key (128-char hex)
     * @param  string              $RB   Responder's ephemeral public key (128-char hex)
     * @param  int                 $klen Desired key length in bytes
     * @param  string              $ida  Initiator's ID (default: "1234567812345678")
     * @param  string              $idb  Responder's ID (default: "1234567812345678")
     * @return string              Derived key as hex string (2*klen hex chars)
     * @throws InvalidKeyException If any key is invalid
     * @throws CryptoException     If key exchange fails
     */
    public static function initiatorComputeKey(
        string $dA,
        string $rA,
        string $PB,
        string $RB,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): string {
        return self::computeKey($dA, $rA, $PB, $RB, $klen, $ida, $idb, true)['key'];
    }

    /**
     * Compute the shared secret key (responder side).
     *
     * Per GM/T 0003-2012 Section 6.2:
     * sB = (h * dB + x̄B * rB) mod n
     * V  = (h * sB) * (PA + x̄A * RA)
     * K  = KDF(xV || yV || ENTLA || IDA || ENTLB || IDB || xRA || yRA || xRB || yRB, klen)
     *
     * @param  string              $dB   Responder's static private key (64-char hex)
     * @param  string              $rB   Responder's ephemeral private key (64-char hex)
     * @param  string              $PA   Initiator's static public key (128-char hex)
     * @param  string              $RA   Initiator's ephemeral public key (128-char hex)
     * @param  int                 $klen Desired key length in bytes
     * @param  string              $ida  Initiator's ID
     * @param  string              $idb  Responder's ID
     * @return string              Derived key as hex string (2*klen hex chars)
     * @throws InvalidKeyException If any key is invalid
     * @throws CryptoException     If key exchange fails
     */
    public static function responderComputeKey(
        string $dB,
        string $rB,
        string $PA,
        string $RA,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): string {
        return self::computeKey($dB, $rB, $PA, $RA, $klen, $ida, $idb, false)['key'];
    }

    /**
     * Compute the shared secret key with V point coordinates (initiator side).
     *
     * Returns the derived key and V point coordinates for optional key confirmation.
     *
     * @return array{key: string, xV: string, yV: string}
     */
    public static function initiatorComputeKeyFull(
        string $dA,
        string $rA,
        string $PB,
        string $RB,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): array {
        return self::computeKey($dA, $rA, $PB, $RB, $klen, $ida, $idb, true);
    }

    /**
     * Compute the shared secret key with V point coordinates (responder side).
     *
     * @return array{key: string, xV: string, yV: string}
     */
    public static function responderComputeKeyFull(
        string $dB,
        string $rB,
        string $PA,
        string $RA,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): array {
        return self::computeKey($dB, $rB, $PA, $RA, $klen, $ida, $idb, false);
    }

    public static function computeInitiatorConfirmation(
        string $xV,
        string $yV,
        string $ida,
        string $idb,
        string $RA,
        string $RB
    ): string {
        return self::computeConfirmation(0x02, $xV, $yV, $ida, $idb, $RA, $RB);
    }

    public static function computeResponderConfirmation(
        string $xV,
        string $yV,
        string $ida,
        string $idb,
        string $RA,
        string $RB
    ): string {
        return self::computeConfirmation(0x03, $xV, $yV, $ida, $idb, $RA, $RB);
    }

    private static function computeConfirmation(
        int $prefix,
        string $xV,
        string $yV,
        string $ida,
        string $idb,
        string $RA,
        string $RB
    ): string {
        $prefixByte = chr($prefix);
        $entla = self::encodeEntl($ida);
        $entlb = self::encodeEntl($idb);
        $xRA = substr($RA, 0, 64);
        $yRA = substr($RA, 64);
        $xRB = substr($RB, 0, 64);
        $yRB = substr($RB, 64);

        $innerInput = $prefixByte . Hex::fromHex($yV) . Hex::fromHex($xV)
            . Hex::fromHex($entla) . $ida . Hex::fromHex($entlb) . $idb
            . Hex::fromHex($xRA) . Hex::fromHex($yRA) . Hex::fromHex($xRB) . Hex::fromHex($yRB);
        $innerHash = Sm3::sm3($innerInput);

        $outerInput = $prefixByte . Hex::fromHex($yV) . Hex::fromHex($innerHash);
        return Sm3::sm3($outerInput);
    }

    /**
     * Core key derivation per GM/T 0003-2012 Section 6.
     *
     * @param  string                                     $d           Own static private key
     * @param  string                                     $r           Own ephemeral private key
     * @param  string                                     $P_other     Other party's static public key
     * @param  string                                     $R_other     Other party's ephemeral public key
     * @param  int                                        $klen        Key length in bytes
     * @param  string                                     $ida         Initiator's ID
     * @param  string                                     $idb         Responder's ID
     * @param  bool                                       $isInitiator Whether computing on initiator side
     * @return array{key: string, xV: string, yV: string}
     */
    private static function computeKey(
        string $d,
        string $r,
        string $P_other,
        string $R_other,
        int $klen,
        string $ida,
        string $idb,
        bool $isInitiator
    ): array {
        // Validate keys
        Sm2::validatePrivateKey($d);
        Sm2::validatePrivateKey($r);

        if (!Sm2::isOnCurve($P_other)) {
            throw new InvalidKeyException('Invalid other party static public key');
        }
        if (!Sm2::isOnCurve($R_other)) {
            throw new InvalidKeyException('Invalid other party ephemeral public key');
        }

        if ($klen <= 0) {
            throw new InvalidKeyException('Key length (klen) must be greater than 0');
        }

        // Compute own ephemeral public key
        $R_self = Sm2::getPublicKey($r);

        // w = ⌈⌈log₂(n)⌉/2⌉ - 1
        $n = Sm2::gmpParamPublic('n');
        $bitLen = (int) ceil(log((float) gmp_strval($n, 10), 2) ?: 256);
        $w = (int) ceil($bitLen / 2) - 1;

        // x̄ = 2^w + (x & (2^w - 1))
        $twoPowW = gmp_pow(gmp_init(2), $w);
        $mask = gmp_sub($twoPowW, gmp_init(1));

        // For initiator: A's own point is RA, other's point is RB
        // For responder: B's own point is RB, other's point is RA
        if ($isInitiator) {
            $xBarSelf = gmp_add($twoPowW, gmp_and(gmp_init(substr($R_self, 0, 64), 16), $mask));  // x̄A
            $xBarOther = gmp_add($twoPowW, gmp_and(gmp_init(substr($R_other, 0, 64), 16), $mask)); // x̄B
        } else {
            $xBarSelf = gmp_add($twoPowW, gmp_and(gmp_init(substr($R_self, 0, 64), 16), $mask));  // x̄B
            $xBarOther = gmp_add($twoPowW, gmp_and(gmp_init(substr($R_other, 0, 64), 16), $mask)); // x̄A
        }

        // h = cofactor = 1 for SM2 curve
        $h = gmp_init(1);
        $dGmp = gmp_init($d, 16);
        $rGmp = gmp_init($r, 16);

        // s = (h * d + x̄self * r) mod n
        // For initiator: sA = (h * dA + x̄A * rA) mod n
        // For responder: sB = (h * dB + x̄B * rB) mod n
        $s = gmp_mod(gmp_add(gmp_mul($h, $dGmp), gmp_mul($xBarSelf, $rGmp)), $n);

        if (gmp_cmp($s, 0) === 0) {
            throw new CryptoException('SM2 key exchange failed: s = 0');
        }

        // Compute V
        // Initiator: V = (h * sA) * (PB + x̄B * RB)
        // Responder: V = (h * sB) * (PA + x̄A * RA)
        $scaledOtherEphem = Sm2::pointMultiplyPublic($R_other, gmp_strval($xBarOther, 16));
        $sum = Sm2::pointAddPublic($P_other, $scaledOtherEphem);
        if ($sum === null) {
            throw new CryptoException('SM2 key exchange: point addition failed');
        }
        $factor = gmp_mod(gmp_mul($h, $s), $n);
        $V = Sm2::pointMultiplyPublic($sum, gmp_strval($factor, 16));

        $xV = substr($V, 0, 64);
        $yV = substr($V, 64);

        // KDF input: xV || yV || ENTLA || IDA || ENTLB || IDB || xRA || yRA || xRB || yRB
        // RA is always the initiator's ephemeral key, RB is always the responder's
        if ($isInitiator) {
            $RA = $R_self;
            $RB = $R_other;
        } else {
            $RA = $R_other;
            $RB = $R_self;
        }

        $entla = self::encodeEntl($ida);
        $entlb = self::encodeEntl($idb);
        $xRA = substr($RA, 0, 64);
        $yRA = substr($RA, 64);
        $xRB = substr($RB, 0, 64);
        $yRB = substr($RB, 64);

        $kdfInput = $xV . $yV . $entla . bin2hex($ida) . $entlb . bin2hex($idb)
            . $xRA . $yRA . $xRB . $yRB;

        $key = self::kdfKeyExchange($kdfInput, $klen);

        return ['key' => $key, 'xV' => $xV, 'yV' => $yV];
    }

    /**
     * Encode ENTL (bit length of ID) as 2-byte hex.
     */
    private static function encodeEntl(string $id): string
    {
        $bitLen = strlen($id) * 8;
        return sprintf('%04x', $bitLen);
    }

    /**
     * KDF for key exchange (same algorithm as SM2 KDF).
     */
    private static function kdfKeyExchange(string $seed, int $klen): string
    {
        $ct = 1;
        $key = '';
        $maxCt = 0xFFFFFFFF;
        while (strlen($key) < $klen) {
            if ($ct > $maxCt) {
                throw new CryptoException('KDF counter overflow');
            }
            $hash = Sm3::sm3(Hex::fromHex($seed . sprintf('%08x', $ct)));
            $key .= Hex::fromHex($hash);
            $ct++;
        }
        return bin2hex(substr($key, 0, $klen));
    }
}
