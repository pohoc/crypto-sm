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
 * This GM/T 0003 protocol is not the TLS 1.3 key exchange; RFC 8998 explicitly
 * prohibits using it in its TLS profile. Use a TLS implementation for TLS.
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
    /** Maximum derived key length in bytes; bounds CPU and memory use for the pure-PHP KDF. */
    public const MAX_KLEN = 4096;

    /**
     * Generate an ephemeral keypair for one key-exchange session.
     *
     * Never reuse the returned private scalar in another session or with
     * another peer. The exchange methods also accept caller-supplied scalars
     * and cannot detect reuse across processes or restarts.
     *
     * @return Keypair One-session ephemeral keypair (rA or rB)
     */
    public static function generateEphemeralKeyPair(): Keypair
    {
        return Sm2::generateEphemeralKeyPairHex();
    }

    /**
     * Compute the shared secret key (initiator side).
     *
     * Per GM/T 0003-2012 Section 6.1:
     * sA = (h * dA + x̄A * rA) mod n
     * V  = (h * sA) * (PB + x̄B * RB)
     * K  = KDF(xV || yV || ZA || ZB, klen)
     *
     * @param  string              $dA   Initiator's static private key (64-char hex)
     * @param  string              $rA   Fresh, one-session initiator ephemeral private key (64-char hex)
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
     * K  = KDF(xV || yV || ZA || ZB, klen)
     *
     * @param  string              $dB   Responder's static private key (64-char hex)
     * @param  string              $rB   Fresh, one-session responder ephemeral private key (64-char hex)
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
        string $RB,
        string $PA,
        string $PB
    ): string {
        // GM/T 0003.3: initiator's outgoing confirmation S_A uses prefix 0x03.
        return self::computeConfirmation(0x03, $xV, $yV, $ida, $idb, $RA, $RB, $PA, $PB);
    }

    public static function computeResponderConfirmation(
        string $xV,
        string $yV,
        string $ida,
        string $idb,
        string $RA,
        string $RB,
        string $PA,
        string $PB
    ): string {
        // GM/T 0003.3: responder's outgoing confirmation S_B uses prefix 0x02.
        return self::computeConfirmation(0x02, $xV, $yV, $ida, $idb, $RA, $RB, $PA, $PB);
    }

    /** Verify the responder's received S_B against the initiator's expected S_1. */
    public static function verifyResponderConfirmationForInitiator(string $expectedS1, string $receivedSB): bool
    {
        return self::verifyConfirmationValue($expectedS1, $receivedSB);
    }

    /** Verify the initiator's received S_A against the responder's expected S_2. */
    public static function verifyInitiatorConfirmationForResponder(string $expectedS2, string $receivedSA): bool
    {
        return self::verifyConfirmationValue($expectedS2, $receivedSA);
    }

    private static function verifyConfirmationValue(string $expected, string $received): bool
    {
        if (!preg_match('/\A[0-9a-fA-F]{64}\z/', $expected)
            || !preg_match('/\A[0-9a-fA-F]{64}\z/', $received)) {
            return false;
        }

        return hash_equals(strtolower($expected), strtolower($received));
    }

    /**
     * Initiator key exchange with automatic key confirmation.
     *
     * Computes the key, expected responder confirmation S1, and outgoing S_A.
     *
     * S1 uses prefix 0x02 and must match the responder's S_B. S_A uses prefix
     * 0x03 and is sent to the responder; the responder verifies it as S2.
     * The returned `sa` is computed locally before the responder's message
     * arrives. The caller MUST withhold it until `s1` has been verified against
     * the received `sb`; use the explicit verify-then-send protocol ordering.
     *
     * @return array{key: string, xV: string, yV: string, s1: string, sa: string}
     */
    public static function initiatorComputeKeyWithConfirmation(
        string $dA,
        string $rA,
        string $PB,
        string $RB,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): array {
        $result = self::computeKey($dA, $rA, $PB, $RB, $klen, $ida, $idb, true);
        $RA = Sm2::getEphemeralPublicKey($rA);
        $PA = Sm2::getPublicKey($dA);
        $s1 = self::computeResponderConfirmation($result['xV'], $result['yV'], $ida, $idb, $RA, $RB, $PA, $PB);
        $sa = self::computeInitiatorConfirmation($result['xV'], $result['yV'], $ida, $idb, $RA, $RB, $PA, $PB);
        return ['key' => $result['key'], 'xV' => $result['xV'], 'yV' => $result['yV'], 's1' => $s1, 'sa' => $sa];
    }

    /**
     * Responder key exchange with automatic key confirmation.
     *
     * Computes the key, outgoing responder confirmation S_B, and expected S2.
     *
     * S_B uses prefix 0x02 and is sent to the initiator. S2 uses prefix 0x03
     * and must match the initiator's S_A.
     *
     * @return array{key: string, xV: string, yV: string, s2: string, sb: string}
     */
    public static function responderComputeKeyWithConfirmation(
        string $dB,
        string $rB,
        string $PA,
        string $RA,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): array {
        $result = self::computeKey($dB, $rB, $PA, $RA, $klen, $ida, $idb, false);
        $RB = Sm2::getEphemeralPublicKey($rB);
        $PB = Sm2::getPublicKey($dB);
        $sb = self::computeResponderConfirmation($result['xV'], $result['yV'], $ida, $idb, $RA, $RB, $PA, $PB);
        $s2 = self::computeInitiatorConfirmation($result['xV'], $result['yV'], $ida, $idb, $RA, $RB, $PA, $PB);
        return ['key' => $result['key'], 'xV' => $result['xV'], 'yV' => $result['yV'], 's2' => $s2, 'sb' => $sb];
    }

    private static function computeConfirmation(
        int $prefix,
        string $xV,
        string $yV,
        string $ida,
        string $idb,
        string $RA,
        string $RB,
        string $PA,
        string $PB
    ): string {
        if (strlen($xV) !== 64 || strlen($yV) !== 64) {
            throw new InvalidKeyException('Invalid SM2 key confirmation point: V coordinates must each be 64 hex characters');
        }
        $points = [
            'V' => $xV . $yV,
            'RA' => $RA,
            'RB' => $RB,
            'PA' => $PA,
            'PB' => $PB,
        ];
        foreach ($points as $name => $point) {
            if (!Sm2::isOnCurve($point)) {
                throw new InvalidKeyException('Invalid SM2 key confirmation point: ' . $name);
            }
        }

        $prefixByte = chr(self::toByte($prefix));
        $za = Sm2::getUserIdDigest($ida, $PA);
        $zb = Sm2::getUserIdDigest($idb, $PB);
        $xRA = substr($RA, 0, 64);
        $yRA = substr($RA, 64);
        $xRB = substr($RB, 0, 64);
        $yRB = substr($RB, 64);

        $innerInput = Hex::fromHex($xV . $za . $zb . $xRA . $yRA . $xRB . $yRB);
        $innerHash = Sm3::sm3($innerInput);

        $outerInput = $prefixByte . Hex::fromHex($yV) . Hex::fromHex($innerHash);
        return Sm3::sm3($outerInput);
    }

    /**
     * @return int<0, 255>
     */
    /**
     * @codeCoverageIgnore 调用方仅传入恒为 0x02 的常量前缀
     */
    private static function toByte(int $value): int
    {
        if ($value < 0 || $value > 255) {
            throw new \InvalidArgumentException('Value must be in byte range 0..255.');
        }
        return $value;
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
        // GM/T 0003 fixes ENTL at 16 bits, so reject oversized identities
        // before doing the scalar multiplications below.
        if (strlen($ida) > 8191 || strlen($idb) > 8191) {
            throw new CryptoException('SM2 key exchange user ID exceeds the 16-bit ENTL limit (maximum 8191 bytes)');
        }

        // Validate keys
        Sm2::validatePrivateKey($d);
        Sm2::validateEphemeralScalar($r);

        if (!Sm2::isOnCurve($P_other)) {
            throw new InvalidKeyException('Invalid other party static public key');
        }
        if (!Sm2::isOnCurve($R_other)) {
            throw new InvalidKeyException('Invalid other party ephemeral public key');
        }

        if ($klen <= 0) {
            throw new InvalidKeyException('Key length (klen) must be greater than 0');
        }
        if ($klen > self::MAX_KLEN) {
            throw new InvalidKeyException('Key length (klen) must not exceed ' . self::MAX_KLEN . ' bytes');
        }

        // Compute own ephemeral public key
        $R_self = Sm2::getEphemeralPublicKey($r);

        // w = ⌈⌈log₂(n)⌉/2⌉ - 1, computed exactly from the bit length of n
        $n = Sm2::gmpParamPublic('n');
        $bitLen = strlen(gmp_strval($n, 2));
        $w = intdiv($bitLen + 1, 2) - 1;

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

        // [不可达守卫] 触发概率 ~2^-256
        if (gmp_cmp($s, 0) === 0) {
            throw new CryptoException('SM2 key exchange failed: s = 0');
        }
        // [/不可达守卫]

        // Compute V
        // Initiator: V = (h * sA) * (PB + x̄B * RB)
        // Responder: V = (h * sB) * (PA + x̄A * RA)
        $scaledOtherEphem = Sm2::pointMultiplyPublic($R_other, gmp_strval($xBarOther, 16));
        $sum = Sm2::pointAddPublic($P_other, $scaledOtherEphem);
        // [不可达守卫] 素数阶群内互逆相加仅得无穷远
        if ($sum === null) {
            throw new CryptoException('SM2 key exchange: point addition failed');
        }
        // [/不可达守卫]
        $factor = gmp_mod(gmp_mul($h, $s), $n);
        $V = Sm2::pointMultiplyPublic($sum, gmp_strval($factor, 16));

        $xV = substr($V, 0, 64);
        $yV = substr($V, 64);

        // KDF input: xV || yV || ZA || ZB
        $P_self = Sm2::getPublicKey($d);
        if ($isInitiator) {
            $RA = $R_self;
            $RB = $R_other;
            $PA = $P_self;
            $PB = $P_other;
        } else {
            $RA = $R_other;
            $RB = $R_self;
            $PA = $P_other;
            $PB = $P_self;
        }

        $za = Sm2::getUserIdDigest($ida, $PA);
        $zb = Sm2::getUserIdDigest($idb, $PB);
        $kdfInput = $xV . $yV . $za . $zb;

        $key = self::kdfKeyExchange($kdfInput, $klen);

        return ['key' => $key, 'xV' => $xV, 'yV' => $yV];
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
            // [不可达守卫] klen 受 MAX_KLEN 约束
            if ($ct > $maxCt) {
                throw new CryptoException('KDF counter overflow');
            }
            // [/不可达守卫]
            $hash = Sm3::sm3(Hex::fromHex($seed . sprintf('%08x', $ct)));
            $key .= Hex::fromHex($hash);
            $ct++;
        }
        $derivedKey = substr($key, 0, $klen);
        self::rejectAllZeroDerivedKey($derivedKey);

        return bin2hex($derivedKey);
    }

    /** Reject the exceptional all-zero KDF output required by GM/T 0003.3. */
    private static function rejectAllZeroDerivedKey(string $key): void
    {
        $nonZero = 0;
        $length = strlen($key);
        for ($i = 0; $i < $length; $i++) {
            $nonZero |= ord($key[$i]);
        }

        if ($nonZero === 0) {
            throw new CryptoException('SM2 key exchange failed: KDF derived an all-zero key');
        }
    }
}
