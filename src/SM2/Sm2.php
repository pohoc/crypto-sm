<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Interfaces\CipherInterface;
use CryptoSm\Interfaces\SignerInterface;
use CryptoSm\SM3\Sm3;
use CryptoSm\Utils\Hex;

class Sm2 implements SignerInterface, CipherInterface
{
    /** @var int C1C3C2 cipher mode (recommended per GM/T 0003-2012) */
    public const CIPHER_MODE_1 = 1;

    /** @var int C1C2C3 cipher mode (legacy, for backward compatibility) */
    public const CIPHER_MODE_0 = 0;

    /** @var array<string, string> SM2 curve parameters as hex strings */
    private static array $eccTable = [
        'n' => 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
        'p' => 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        'a' => 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
        'b' => '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
        'gX' => '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7',
        'gY' => 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    ];

    /** @var array<string, \GMP>|null Cached GMP objects for curve parameters */
    private static ?array $gmpCache = null;

    /** @var array<int, array{x: \GMP, y: \GMP}>|null Precomputed base point table for fixed-base multiplication (8-bit window: i*G for i=1..255) */
    private static ?array $basePointTable = null;

    /** @var array<string, array<int, array{x: \GMP, y: \GMP}>>|null Cached variable-base multiplication tables, keyed by point hex */
    private static ?array $windowTableCache = null;

    private static function gmpParam(string $key): \GMP
    {
        if (self::$gmpCache === null) {
            self::$gmpCache = [];
        }
        if (!isset(self::$gmpCache[$key])) {
            self::$gmpCache[$key] = gmp_init(self::$eccTable[$key], 16);
        }
        return self::$gmpCache[$key];
    }

    /**
     * Build a precomputed table for fixed-base point multiplication (base point G).
     *
     * Uses 8-bit window: precomputes i*G for i = 1..255.
     * This avoids recomputing these points on every key generation / signature.
     *
     * @return array<int, array{x: \GMP, y: \GMP}>
     */
    private static function getBasePointTable(): array
    {
        if (self::$basePointTable !== null) {
            return self::$basePointTable;
        }

        $p = self::gmpParam('p');
        $a = self::gmpParam('a');
        $Gx = self::gmpParam('gX');
        $Gy = self::gmpParam('gY');

        $table = [];
        $table[1] = ['x' => $Gx, 'y' => $Gy];
        for ($i = 2; $i <= 255; $i++) {
            $prev = $table[$i - 1];
            $sum = self::pointAdd($prev['x'], $prev['y'], $Gx, $Gy, $p, $a);
            if ($sum === null) {
                break;
            }
            $table[$i] = $sum;
        }

        self::$basePointTable = $table;
        return $table;
    }

    /**
     * Derive the public key from a private key.
     *
     * @param  string              $privateKey 64-char hex string
     * @return string              128-char hex uncompressed public key
     * @throws InvalidKeyException If private key is invalid
     */
    public static function getPublicKey(string $privateKey): string
    {
        self::validatePrivateKey($privateKey);
        return self::pointMultiply($privateKey);
    }

    /**
     * Validate a private key format and range.
     *
     * @param  string              $privateKey 64-char hex string
     * @throws InvalidKeyException If private key is invalid
     */
    public static function validatePrivateKey(string $privateKey): void
    {
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $privateKey)) {
            throw new InvalidKeyException('Private key must be 256 bits (64 hex chars)');
        }
        $n = self::gmpParam('n');
        $d = gmp_init($privateKey, 16);
        if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, $n) >= 0) {
            throw new InvalidKeyException('Private key must be in range [1, n-1]');
        }
    }

    /**
     * Check if a public key is on the SM2 curve.
     *
     * @param  string $publicKey 128-char hex string
     * @return bool
     */
    public static function isOnCurve(string $publicKey): bool
    {
        if (!preg_match('/^[0-9a-fA-F]{128}$/', $publicKey)) {
            return false;
        }
        $p = self::gmpParam('p');
        $a = self::gmpParam('a');
        $b = self::gmpParam('b');
        $x = gmp_init(substr($publicKey, 0, 64), 16);
        $y = gmp_init(substr($publicKey, 64), 16);

        if (gmp_cmp($x, 0) < 0 || gmp_cmp($x, $p) >= 0 || gmp_cmp($y, 0) < 0 || gmp_cmp($y, $p) >= 0) {
            return false;
        }

        $left = gmp_mod(gmp_pow($y, 2), $p);
        $right = gmp_mod(gmp_add(gmp_add(gmp_pow($x, 3), gmp_mul($a, $x)), $b), $p);
        return gmp_cmp($left, $right) === 0;
    }

    /**
     * Generate a new SM2 key pair (static).
     *
     * @return Keypair Generated key pair with hex-encoded keys
     */
    public static function generateKeyPairHex(): Keypair
    {
        $pair = self::generateKeyPairMaterial();
        return new Keypair($pair['privateKey'], $pair['publicKey']);
    }

    /**
     * Generate a new SM2 key pair (instance method for testability via interface).
     *
     * @return Keypair Generated key pair with hex-encoded keys
     */
    public function generateKeyPair(): Keypair
    {
        return self::generateKeyPairHex();
    }

    /** @return array{privateKey: string, publicKey: string} */
    private static function generateKeyPairMaterial(): array
    {
        $d = self::randomScalar();
        $privateKey = str_pad(gmp_strval($d, 16), 64, '0', STR_PAD_LEFT);
        $publicKey = self::pointMultiply($privateKey);
        return ['privateKey' => $privateKey, 'publicKey' => $publicKey];
    }

    /**
     * Generate a cryptographic scalar in [1, n-1] using rejection sampling.
     *
     * @throws CryptoException If max retries exceeded (extremely unlikely with 256-bit random)
     */
    private static function randomScalar(): \GMP
    {
        $n = self::gmpParam('n');
        $hexLength = strlen(self::$eccTable['n']);
        $byteLength = max(1, intdiv($hexLength + 1, 2));
        $maxRetries = 1000;

        for ($retry = 0; $retry < $maxRetries; $retry++) {
            $candidate = gmp_init(bin2hex(random_bytes($byteLength)), 16);
            if (gmp_cmp($candidate, 1) >= 0 && gmp_cmp($candidate, $n) < 0) {
                return $candidate;
            }
        }

        throw new CryptoException('SM2 random scalar generation failed: max retries exceeded');
    }

    /**
     * Encrypt data using SM2.
     *
     * @param  string                $data      Plaintext data to encrypt
     * @param  string                $publicKey 128-char hex string (uncompressed public key)
     * @param  Sm2CipherOptions|null $options   Cipher mode options (default: C1C3C2)
     * @return string                Hex-encoded ciphertext
     * @throws InvalidKeyException   If public key is invalid
     * @throws CryptoException       If encryption fails (e.g., KDF zero-key after max retries)
     */
    public static function doEncrypt(string $data, string $publicKey, ?Sm2CipherOptions $options = null): string
    {
        $options ??= new Sm2CipherOptions();
        $cipherMode = $options->getCipherMode();

        if (!self::isOnCurve($publicKey)) {
            throw new InvalidKeyException('Invalid public key');
        }

        $dataLen = strlen($data);

        // GM/T 0003-2012 5.4.2: k must be in [1, n-1]
        $kGmp = self::randomScalar();
        $k = str_pad(gmp_strval($kGmp, 16), 64, '0', STR_PAD_LEFT);

        $x1y1 = self::pointMultiply($k);
        $x1 = substr($x1y1, 0, 64);
        $y1 = substr($x1y1, 64);
        $C1 = $x1y1;

        $x2y2 = self::pointMultiply($publicKey, $k);
        $x2 = substr($x2y2, 0, 64);
        $y2 = substr($x2y2, 64);

        $t = self::kdf($x2 . $y2, $dataLen);
        if ($dataLen > 0) {
            $maxRetries = 100;
            $retry = 0;
            while (self::isAllZero($t)) {
                $retry++;
                if ($retry >= $maxRetries) {
                    throw new CryptoException('SM2 encryption failed: KDF derived all-zero key after max retries');
                }
                $kGmp = self::randomScalar();
                $k = str_pad(gmp_strval($kGmp, 16), 64, '0', STR_PAD_LEFT);
                $x1y1 = self::pointMultiply($k);
                $x1 = substr($x1y1, 0, 64);
                $C1 = $x1y1;
                $x2y2 = self::pointMultiply($publicKey, $k);
                $x2 = substr($x2y2, 0, 64);
                $y2 = substr($x2y2, 64);
                $t = self::kdf($x2 . $y2, $dataLen);
            }
        }

        $C2 = $data ^ $t;
        $C2Hex = bin2hex($C2);
        $C3 = Sm3::sm3(Hex::fromHex($x2) . $data . Hex::fromHex($y2));

        return $cipherMode === self::CIPHER_MODE_1 ? $C1 . $C3 . $C2Hex : $C1 . $C2Hex . $C3;
    }

    /**
     * Decrypt data using SM2.
     *
     * @param  string                $data       Hex-encoded ciphertext
     * @param  string                $privateKey 64-char hex string
     * @param  Sm2CipherOptions|null $options    Cipher mode options (must match encryption)
     * @return string                Decrypted plaintext
     * @throws InvalidKeyException   If private key or ciphertext is invalid
     * @throws CryptoException       If decryption or verification fails
     */
    public static function doDecrypt(string $data, string $privateKey, ?Sm2CipherOptions $options = null): string
    {
        self::validatePrivateKey($privateKey);

        $options ??= new Sm2CipherOptions();
        $cipherMode = $options->getCipherMode();

        if (strlen($data) > 2 && substr($data, 0, 2) === '04' && (strlen($data) - 2) >= 192 && (strlen($data) - 2) % 2 === 0) {
            $stripped = substr($data, 2);
            $testC1 = substr($stripped, 0, 128);
            if (self::isOnCurve($testC1)) {
                $data = $stripped;
            }
        }

        if (strlen($data) < 192 || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length must be >= 192 hex chars and even');
        }

        $C1 = substr($data, 0, 128);
        if ($cipherMode === self::CIPHER_MODE_1) {
            $C3 = substr($data, 128, 64);
            $C2 = substr($data, 192);
        } else {
            $C2 = substr($data, 128, -64);
            $C3 = substr($data, -64);
        }

        $C1Point = self::parsePoint($C1);
        if ($C1Point === null || !self::isOnCurve($C1)) {
            throw new InvalidKeyException('Invalid C1');
        }

        $x2y2 = self::pointMultiply($C1, $privateKey);
        $x2 = substr($x2y2, 0, 64);
        $y2 = substr($x2y2, 64);

        $dataLen = (int) (strlen($C2) / 2);
        $t = self::kdf($x2 . $y2, $dataLen);
        if ($dataLen > 0 && self::isAllZero($t)) {
            throw new CryptoException('KDF derived all-zero key');
        }

        $C2Bin = Hex::fromHex($C2);
        $M = $C2Bin ^ $t;

        $u = Sm3::sm3(Hex::fromHex($x2) . $M . Hex::fromHex($y2));
        if (!hash_equals($C3, $u)) {
            throw new CryptoException('SM2 decryption failed: ciphertext verification failed');
        }

        return $M;
    }

    /**
     * Encrypt data using SM2 (CipherInterface compliant).
     *
     * @param  string $data      Plaintext data
     * @param  string $publicKey 128-char hex string
     * @param  mixed  $options   Sm2CipherOptions instance or null
     * @return string Hex-encoded ciphertext
     */
    public static function encrypt(string $data, string $publicKey, mixed $options = null): string
    {
        return self::doEncrypt($data, $publicKey, $options instanceof Sm2CipherOptions ? $options : null);
    }

    /**
     * Decrypt data using SM2 (CipherInterface compliant).
     *
     * @param  string $data       Hex-encoded ciphertext
     * @param  string $privateKey 64-char hex string
     * @param  mixed  $options    Sm2CipherOptions instance or null
     * @return string Decrypted plaintext
     */
    public static function decrypt(string $data, string $privateKey, mixed $options = null): string
    {
        return self::doDecrypt($data, $privateKey, $options instanceof Sm2CipherOptions ? $options : null);
    }

    /**
     * Sign data using SM2 (SignerInterface compliant).
     *
     * @param  string $data       Data to sign
     * @param  string $privateKey 64-char hex string
     * @param  mixed  $options    SignatureOptions instance or null
     * @return string Signature (hex or DER depending on options)
     */
    public static function sign(string $data, string $privateKey, mixed $options = null): string
    {
        return self::doSignature($data, $privateKey, $options instanceof SignatureOptions ? $options : null);
    }

    /**
     * Verify SM2 signature (SignerInterface compliant).
     *
     * @param  string $data      Original data
     * @param  string $signature Signature to verify
     * @param  string $publicKey 128-char hex string
     * @param  mixed  $options   SignatureOptions instance or null
     * @return bool   True if signature is valid
     */
    public static function verify(string $data, string $signature, string $publicKey, mixed $options = null): bool
    {
        return self::doVerifySignature($data, $signature, $publicKey, $options instanceof SignatureOptions ? $options : null);
    }

    /**
     * Sign data using SM2.
     *
     * @param  string                $data       Data to sign
     * @param  string                $privateKey 64-char hex string
     * @param  SignatureOptions|null $options    Signature options (DER, hash, publicKey, userId)
     * @return string                Hex-encoded signature (or DER hex if options.der=true)
     * @throws InvalidKeyException   If private key is invalid
     * @throws CryptoException       If signing fails after max retries
     */
    public static function doSignature(string $data, string $privateKey, ?SignatureOptions $options = null): string
    {
        $options ??= new SignatureOptions();

        $der = $options->getDer();
        $hash = $options->getHash();
        $publicKey = $options->getPublicKey();
        $userId = $options->getUserId();

        self::validatePrivateKey($privateKey);

        if ($hash && $publicKey === '') {
            $publicKey = self::getPublicKey($privateKey);
        }
        $e = self::calcE($data, $hash, $publicKey, $userId);

        $n = self::gmpParam('n');
        $d = gmp_init($privateKey, 16);
        $dPlus1 = gmp_add($d, gmp_init(1));
        if (gmp_cmp($dPlus1, $n) === 0) {
            throw new CryptoException('SM2 signature failed: private key d=n-1 is not supported');
        }
        $dPlus1Inv = gmp_invert($dPlus1, $n);
        if ($dPlus1Inv === false) {
            throw new CryptoException('SM2 signature failed: modular inverse computation error');
        }

        $maxRetries = 100;
        $p = self::gmpParam('p');
        $a = self::gmpParam('a');

        for ($retry = 0; $retry < $maxRetries; $retry++) {
            $k = self::randomScalar();
            $x1y1 = self::fixedBaseMultiply($k, $p, $a);
            if ($x1y1 === null) {
                continue;
            }
            $x1Dec = $x1y1['x'];

            if (gmp_cmp($x1Dec, $n) >= 0) {
                $x1Dec = gmp_mod($x1Dec, $n);
            }

            $r = gmp_mod(gmp_add($e, $x1Dec), $n);
            if (gmp_cmp($r, 0) === 0 || gmp_cmp(gmp_add($r, $k), $n) === 0) {
                continue;
            }

            $tmp = gmp_mod(gmp_sub($k, gmp_mul($r, $d)), $n);
            $s = gmp_mod(gmp_mul($dPlus1Inv, $tmp), $n);
            if (gmp_cmp($s, 0) !== 0) {
                $rHex = str_pad(gmp_strval($r, 16), 64, '0', STR_PAD_LEFT);
                $sHex = str_pad(gmp_strval($s, 16), 64, '0', STR_PAD_LEFT);
                return $der ? Asn1::encodeDerSignature($rHex, $sHex) : $rHex . $sHex;
            }
        }

        throw new CryptoException('SM2 signature failed: max retries exceeded');
    }

    /**
     * Verify an SM2 signature.
     *
     * @param  string                $data      Original data
     * @param  string                $signature Signature to verify (hex or DER)
     * @param  string                $publicKey 128-char hex string
     * @param  SignatureOptions|null $options   Signature options (must match signing)
     * @return bool                  True if signature is valid
     */
    public static function doVerifySignature(string $data, string $signature, string $publicKey, ?SignatureOptions $options = null): bool
    {
        $options ??= new SignatureOptions();
        $der = $options->getDer();
        $hash = $options->getHash();
        $userId = $options->getUserId();

        if (!self::isOnCurve($publicKey)) {
            return false;
        }

        if (!$der && strlen($signature) !== 128 && strlen($signature) > 4 && substr($signature, 0, 2) === '30') {
            $der = true;
        }

        try {
            [$x1Hex, $sHex] = $der ? Asn1::decodeDerSignature($signature) : [substr($signature, 0, 64), substr($signature, 64)];
        } catch (CryptoException) {
            return false;
        }

        $n = self::gmpParam('n');
        $x1Dec = gmp_init($x1Hex, 16);
        $sDec = gmp_init($sHex, 16);
        if (!self::constantTimeInSignatureRange($x1Dec, $n) || !self::constantTimeInSignatureRange($sDec, $n)) {
            return false;
        }

        $e = self::calcE($data, $hash, $publicKey, $userId);
        $t = gmp_mod(gmp_add($x1Dec, $sDec), $n);
        if (self::constantTimeIsZero($t)) {
            return false;
        }

        // Use internal methods to avoid str↔GMP round-trip
        $p = self::gmpParam('p');
        $a = self::gmpParam('a');
        $point1 = self::fixedBaseMultiply($sDec, $p, $a);
        $point2 = self::pointMultiplyInternal($publicKey, gmp_strval($t, 16));
        if ($point1 === null || $point2 === null) {
            return false;
        }

        $sum = self::pointAdd(
            $point1['x'],
            $point1['y'],
            $point2['x'],
            $point2['y'],
            $p,
            $a
        );
        if ($sum === null) {
            return false;
        }

        $v = gmp_mod(gmp_add($e, $sum['x']), $n);
        return hash_equals(str_pad(gmp_strval($v, 16), 64, '0', STR_PAD_LEFT), str_pad(gmp_strval($x1Dec, 16), 64, '0', STR_PAD_LEFT));
    }

    private static function calcE(string $data, bool $hash, string $publicKey, string $userId): \GMP
    {
        if ($hash) {
            $x = substr($publicKey, 0, 64);
            $y = substr($publicKey, 64);
            $zInput = self::getUserIdHash($userId, $x, $y);
            $z = Sm3::sm3(Hex::fromHex($zInput));
            $e = Sm3::sm3(Hex::fromHex($z) . $data);
            return gmp_init($e, 16);
        }
        $dataHex = $data === '' ? '00' : bin2hex($data);
        return gmp_init($dataHex, 16);
    }

    private static function getUserIdHash(string $userId, string $x, string $y): string
    {
        $len = strlen($userId) * 8;
        $userIdHex = Hex::toHexString($userId);

        $a = self::$eccTable['a'];
        $b = self::$eccTable['b'];
        $gX = self::$eccTable['gX'];
        $gY = self::$eccTable['gY'];

        return sprintf('%04x', $len) . $userIdHex . $a . $b . $gX . $gY . $x . $y;
    }

    /**
     * Compute ZA/ZB user identity digest for SM2 signature and key exchange.
     *
     * @internal For internal use by KeyExchange and tests. Not covered by backward compatibility.
     */
    public static function getUserIdDigest(string $userId, string $publicKey): string
    {
        if (!self::isOnCurve($publicKey)) {
            throw new InvalidKeyException('Invalid public key: not on SM2 curve');
        }

        $x = substr($publicKey, 0, 64);
        $y = substr($publicKey, 64);
        return Sm3::sm3(Hex::fromHex(self::getUserIdHash($userId, $x, $y)));
    }

    private static function kdf(string $seed, int $keyLen): string
    {
        $ct = 1;
        $key = '';
        $maxCt = 0xFFFFFFFF; // 32-bit counter limit per GM/T 0003-2012
        while (strlen($key) < $keyLen) {
            if ($ct > $maxCt) {
                throw new CryptoException('KDF counter overflow: key length too large');
            }
            $hash = Sm3::sm3(Hex::fromHex($seed . sprintf('%08x', $ct)));
            $key .= Hex::fromHex($hash);
            $ct++;
        }
        return substr($key, 0, $keyLen);
    }

    private static function pointMultiply(string $point, ?string $factor = null): string
    {
        $result = self::pointMultiplyInternal($point, $factor);
        if ($result === null) {
            throw new CryptoException('SM2 point multiplication failed');
        }
        return str_pad(gmp_strval($result['x'], 16), 64, '0', STR_PAD_LEFT) .
            str_pad(gmp_strval($result['y'], 16), 64, '0', STR_PAD_LEFT);
    }

    /**
     * Internal point multiplication returning GMP objects (avoids string round-trip).
     *
     * @return array{x: \GMP, y: \GMP}|null
     */
    private static function pointMultiplyInternal(string $point, ?string $factor = null): ?array
    {
        $p = self::gmpParam('p');
        $a = self::gmpParam('a');

        $isBasePoint = strlen($point) <= 64;

        if ($isBasePoint) {
            $Gx = self::gmpParam('gX');
            $Gy = self::gmpParam('gY');
            $pointX = $Gx;
            $pointY = $Gy;
            $factor ??= $point;
        } else {
            $pointX = gmp_init(substr($point, 0, 64), 16);
            $pointY = gmp_init(substr($point, 64), 16);
        }

        $factor ??= str_pad(gmp_strval(self::randomScalar(), 16), 64, '0', STR_PAD_LEFT);
        $factorDec = gmp_init($factor, 16);
        $n = self::gmpParam('n');
        if (gmp_cmp($factorDec, 1) < 0 || gmp_cmp($factorDec, $n) >= 0) {
            throw new CryptoException('Signature factor must be in range [1, n-1]');
        }

        if ($isBasePoint) {
            return self::fixedBaseMultiply($factorDec, $p, $a);
        }

        return self::windowMultiply($pointX, $pointY, $factorDec, $p, $a);
    }

    /**
     * Fixed-base multiplication using precomputed table (8-bit window).
     *
     * For base point G, we precompute i*G for i=1..255.
     * The scalar is processed 8 bits at a time from the most significant bit,
     * reducing point additions from ~128 (binary method) to ~32.
     *
     * @return array{x: \GMP, y: \GMP}|null
     */
    private static function fixedBaseMultiply(\GMP $k, \GMP $p, \GMP $a): ?array
    {
        $table = self::getBasePointTable();
        $n = self::gmpParam('n');
        $k = gmp_mod($k, $n);

        if (gmp_cmp($k, 0) === 0) {
            return null;
        }

        $bin = gmp_strval($k, 2);
        $len = strlen($bin);

        $padLen = (8 - ($len % 8)) % 8;
        $bin = str_repeat('0', $padLen) . $bin;
        $len = strlen($bin);

        $resultX = null;
        $resultY = null;

        for ($i = 0; $i < $len; $i += 8) {
            if ($resultX !== null && $resultY !== null) {
                for ($d = 0; $d < 8; $d++) {
                    $temp = self::pointDouble($resultX, $resultY, $p, $a);
                    $resultX = $temp['x'];
                    $resultY = $temp['y'];
                }
            }

            $windowVal = (int) bindec(substr($bin, $i, 8));
            if ($windowVal === 0) {
                continue;
            }

            $point = $table[$windowVal] ?? null;
            if ($point === null) {
                continue;
            }

            if ($resultX === null) {
                $resultX = $point['x'];
                $resultY = $point['y'];
            } else {
                assert($resultY !== null);
                $temp = self::pointAdd($resultX, $resultY, $point['x'], $point['y'], $p, $a);
                if ($temp === null) {
                    return null;
                }
                $resultX = $temp['x'];
                $resultY = $temp['y'];
            }
        }

        if ($resultX === null || $resultY === null) {
            return null;
        }

        return ['x' => $resultX, 'y' => $resultY];
    }

    /**
     * Variable-base multiplication using 8-bit window method.
     *
     * Precomputes i*P for i=1..255 on the fly, then processes
     * the scalar 8 bits at a time from MSB.
     *
     * @return array{x: \GMP, y: \GMP}|null
     */
    private static function windowMultiply(\GMP $px, \GMP $py, \GMP $k, \GMP $p, \GMP $a): ?array
    {
        $n = self::gmpParam('n');
        $k = gmp_mod($k, $n);

        if (gmp_cmp($k, 0) === 0) {
            return null;
        }

        $cacheKey = str_pad(gmp_strval($px, 16), 64, '0', STR_PAD_LEFT) . str_pad(gmp_strval($py, 16), 64, '0', STR_PAD_LEFT);

        if (self::$windowTableCache === null) {
            self::$windowTableCache = [];
        }

        if (!isset(self::$windowTableCache[$cacheKey])) {
            $table = [];
            $table[1] = ['x' => $px, 'y' => $py];
            for ($i = 2; $i <= 255; $i++) {
                $prev = $table[$i - 1];
                $sum = self::pointAdd($prev['x'], $prev['y'], $px, $py, $p, $a);
                if ($sum === null) {
                    break;
                }
                $table[$i] = $sum;
            }

            if (count(self::$windowTableCache) > 16) {
                array_shift(self::$windowTableCache);
            }

            self::$windowTableCache[$cacheKey] = $table;
        }

        $table = self::$windowTableCache[$cacheKey];

        $bin = gmp_strval($k, 2);
        $len = strlen($bin);

        $padLen = (8 - ($len % 8)) % 8;
        $bin = str_repeat('0', $padLen) . $bin;
        $len = strlen($bin);

        $resultX = null;
        $resultY = null;

        for ($i = 0; $i < $len; $i += 8) {
            if ($resultX !== null && $resultY !== null) {
                for ($d = 0; $d < 8; $d++) {
                    $temp = self::pointDouble($resultX, $resultY, $p, $a);
                    $resultX = $temp['x'];
                    $resultY = $temp['y'];
                }
            }

            $windowVal = (int) bindec(substr($bin, $i, 8));
            if ($windowVal === 0) {
                continue;
            }

            $point = $table[$windowVal] ?? null;
            if ($point === null) {
                continue;
            }

            if ($resultX === null) {
                $resultX = $point['x'];
                $resultY = $point['y'];
            } else {
                assert($resultY !== null);
                $temp = self::pointAdd($resultX, $resultY, $point['x'], $point['y'], $p, $a);
                if ($temp === null) {
                    return null;
                }
                $resultX = $temp['x'];
                $resultY = $temp['y'];
            }
        }

        if ($resultX === null || $resultY === null) {
            return null;
        }

        return ['x' => $resultX, 'y' => $resultY];
    }

    /**
     * @return array{x: \GMP, y: \GMP}|null
     */
    private static function pointAdd(\GMP $x1, \GMP $y1, \GMP $x2, \GMP $y2, \GMP $p, \GMP $a): ?array
    {
        if (gmp_cmp($x1, $x2) === 0) {
            if (gmp_cmp($y1, $y2) === 0) {
                return self::pointDouble($x1, $y1, $p, $a);
            }
            return null;
        }

        $inv = gmp_invert(gmp_sub($x2, $x1), $p);
        if ($inv === false) {
            return null;
        }
        $lambda = gmp_mod(gmp_mul(gmp_sub($y2, $y1), $inv), $p);
        $x3 = gmp_mod(gmp_sub(gmp_sub(gmp_pow($lambda, 2), $x1), $x2), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x1, $x3)), $y1), $p);

        return ['x' => $x3, 'y' => $y3];
    }

    /** @var \GMP|null Cached GMP integer 2 */
    private static ?\GMP $gmpTwo = null;

    /** @var \GMP|null Cached GMP integer 3 */
    private static ?\GMP $gmpThree = null;

    /**
     * @return array{x: \GMP, y: \GMP}
     */
    private static function pointDouble(\GMP $x, \GMP $y, \GMP $p, \GMP $a): array
    {
        self::$gmpTwo ??= gmp_init(2);
        self::$gmpThree ??= gmp_init(3);

        $denom = gmp_mul(self::$gmpTwo, $y);
        $yInv = gmp_invert($denom, $p);
        if ($yInv === false) {
            throw new CryptoException('Point doubling failed: modular inverse does not exist (point at infinity)');
        }
        $lambda = gmp_mod(
            gmp_mul(
                gmp_add(gmp_mul(self::$gmpThree, gmp_pow($x, 2)), $a),
                $yInv
            ),
            $p
        );
        $x3 = gmp_mod(gmp_sub(gmp_pow($lambda, 2), gmp_mul(self::$gmpTwo, $x)), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x, $x3)), $y), $p);
        return ['x' => $x3, 'y' => $y3];
    }

    /**
     * Constant-time check if a GMP value equals zero.
     * Uses hash_equals on fixed-length hex strings to avoid GMP's variable-time limb comparison.
     */
    private static function constantTimeIsZero(\GMP $value): bool
    {
        $hex = str_pad(gmp_strval($value, 16), 64, '0', STR_PAD_LEFT);
        return hash_equals($hex, str_repeat('0', 64));
    }

    /**
     * Constant-time check if a GMP value is in the valid signature range (0 < value < n).
     */
    private static function constantTimeInSignatureRange(\GMP $value, \GMP $n): bool
    {
        $hex = str_pad(gmp_strval($value, 16), 64, '0', STR_PAD_LEFT);
        $nHex = str_pad(gmp_strval($n, 16), 64, '0', STR_PAD_LEFT);

        // Check not zero (constant-time using hash_equals)
        $notZero = !hash_equals($hex, str_repeat('0', 64));
        // Check strictly less than n (constant-time byte-by-byte)
        $less = 0;
        $equal = 1;
        for ($i = 0; $i < 64; $i++) {
            $vByte = ord($hex[$i]);
            $nByte = ord($nHex[$i]);
            $less |= (($vByte < $nByte) ? 1 : 0) & $equal;
            $equal &= ($vByte === $nByte) ? 1 : 0;
        }
        return $notZero && $less !== 0;
    }

    private static function isAllZero(string $data): bool
    {
        return trim($data, "\0") === '';
    }

    /**
     * Get a GMP curve parameter by key (public accessor for KeyExchange).
     *
     * @internal For internal use by KeyExchange only. Not covered by backward compatibility.
     * @return \GMP
     */
    public static function gmpParamPublic(string $key): \GMP
    {
        return self::gmpParam($key);
    }

    /**
     * Point multiplication returning hex string (public accessor for KeyExchange).
     *
     * @internal For internal use by KeyExchange only. Not covered by backward compatibility.
     * @param  string      $point  128-char hex point or scalar (for base point)
     * @param  string|null $factor 64-char hex scalar (optional)
     * @return string      128-char hex result point
     */
    public static function pointMultiplyPublic(string $point, ?string $factor = null): string
    {
        if (strlen($point) === 128 && !self::isOnCurve($point)) {
            throw new InvalidKeyException('Invalid point: not on SM2 curve');
        }
        return self::pointMultiply($point, $factor);
    }

    /**
     * Point addition returning hex string (public accessor for KeyExchange).
     *
     * @internal For internal use by KeyExchange only. Not covered by backward compatibility.
     * @param  string      $point1Hex 128-char hex point
     * @param  string      $point2Hex 128-char hex point
     * @return string|null 128-char hex result point, or null if points cancel
     */
    public static function pointAddPublic(string $point1Hex, string $point2Hex): ?string
    {
        $p1 = self::parsePoint($point1Hex);
        $p2 = self::parsePoint($point2Hex);
        if ($p1 === null || $p2 === null) {
            return null;
        }
        $result = self::pointAdd($p1['x'], $p1['y'], $p2['x'], $p2['y'], self::gmpParam('p'), self::gmpParam('a'));
        if ($result === null) {
            return null;
        }
        return str_pad(gmp_strval($result['x'], 16), 64, '0', STR_PAD_LEFT) .
            str_pad(gmp_strval($result['y'], 16), 64, '0', STR_PAD_LEFT);
    }

    /**
     * @return array{x: \GMP, y: \GMP}|null
     */
    private static function parsePoint(string $hex): ?array
    {
        if (!preg_match('/^[0-9a-fA-F]{128}$/', $hex)) {
            return null;
        }
        return [
            'x' => gmp_init(substr($hex, 0, 64), 16),
            'y' => gmp_init(substr($hex, 64), 16),
        ];
    }
}
