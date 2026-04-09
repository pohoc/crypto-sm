<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Interface\CipherInterface;
use CryptoSm\Interface\SignerInterface;
use CryptoSm\SM3\Sm3;
use CryptoSm\Utils\Hex;

class Sm2 implements SignerInterface, CipherInterface
{
    /** @var int C1C3C2 cipher mode (recommended per GM/T 0003-2012) */
    public const CIPHER_MODE_1 = 1;

    /** @var int C1C2C3 cipher mode (legacy, for backward compatibility) */
    public const CIPHER_MODE_0 = 0;

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
     * Generate a new SM2 key pair.
     *
     * @return Keypair Generated key pair with hex-encoded keys
     */
    public static function generateKeyPairHex(): Keypair
    {
        $pair = self::generateKeyPair();
        return new Keypair($pair['privateKey'], $pair['publicKey']);
    }

    private static function generateKeyPair(): array
    {
        $n = self::gmpParam('n');
        do {
            $d = gmp_random_range(gmp_init(1), gmp_sub($n, gmp_init(1)));
        } while (gmp_cmp($d, 1) < 0 || gmp_cmp($d, $n) >= 0);

        $privateKey = str_pad(gmp_strval($d, 16), 64, '0', STR_PAD_LEFT);
        $publicKey = self::pointMultiply($privateKey);

        return ['privateKey' => $privateKey, 'publicKey' => $publicKey];
    }

    /**
     * Encrypt data using SM2.
     *
     * @param string           $data     Plaintext data to encrypt
     * @param string           $publicKey 128-char hex string (uncompressed public key)
     * @param Sm2CipherOptions|null $options Cipher mode options (default: C1C3C2)
     * @return string Hex-encoded ciphertext
     * @throws InvalidKeyException If public key is invalid
     * @throws CryptoException    If encryption fails (e.g., KDF zero-key after max retries)
     */
    public static function doEncrypt(string $data, string $publicKey, ?Sm2CipherOptions $options = null): string
    {
        $options ??= new Sm2CipherOptions();
        $cipherMode = $options->getCipherMode();

        if (!self::isOnCurve($publicKey)) {
            throw new InvalidKeyException('Invalid public key');
        }

        $dataLen = strlen($data);
        $k = bin2hex(random_bytes(32));

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
                $k = bin2hex(random_bytes(32));
                $x1y1 = self::pointMultiply($k);
                $x1 = substr($x1y1, 0, 64);
                $C1 = $x1y1;
                $x2y2 = self::pointMultiply($publicKey, $k);
                $x2 = substr($x2y2, 0, 64);
                $y2 = substr($x2y2, 64);
                $t = self::kdf($x2 . $y2, $dataLen);
            }
        }

        $C2 = '';
        for ($i = 0; $i < $dataLen; $i++) {
            $C2 .= chr(ord($data[$i]) ^ ord($t[$i]));
        }
        $C2Hex = bin2hex($C2);
        $C3 = Sm3::sm3(Hex::fromHex($x2) . $data . Hex::fromHex($y2));

        return $cipherMode === self::CIPHER_MODE_1 ? $C1 . $C3 . $C2Hex : $C1 . $C2Hex . $C3;
    }

    /**
     * Decrypt data using SM2.
     *
     * @param string           $data      Hex-encoded ciphertext
     * @param string           $privateKey 64-char hex string
     * @param Sm2CipherOptions|null $options Cipher mode options (must match encryption)
     * @return string Decrypted plaintext
     * @throws InvalidKeyException If private key or ciphertext is invalid
     * @throws CryptoException    If decryption or verification fails
     */
    public static function doDecrypt(string $data, string $privateKey, ?Sm2CipherOptions $options = null): string
    {
        self::validatePrivateKey($privateKey);

        $options ??= new Sm2CipherOptions();
        $cipherMode = $options->getCipherMode();

        if (strlen($data) < 192 || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext');
        }

        $C1 = substr($data, 0, 128);
        if ($cipherMode === self::CIPHER_MODE_1) {
            $C3 = substr($data, 128, 64);
            $C2 = substr($data, 192);
        } else {
            $C2 = substr($data, 128, -64);
            $C3 = substr($data, -64);
        }

        $p = self::gmpParam('p');
        $a = self::gmpParam('a');
        $C1Point = self::parsePoint($C1);
        if ($C1Point === null || !self::isOnCurve($C1)) {
            throw new InvalidKeyException('Invalid C1');
        }

        $x2y2 = self::pointMultiply($C1, $privateKey);
        $x2 = substr($x2y2, 0, 64);
        $y2 = substr($x2y2, 64);

        $dataLen = strlen($C2) / 2;
        $t = self::kdf($x2 . $y2, $dataLen);
        if ($dataLen > 0 && self::isAllZero($t)) {
            throw new CryptoException('KDF derived all-zero key');
        }

        $M = '';
        $C2Bin = Hex::fromHex($C2);
        for ($i = 0; $i < $dataLen; $i++) {
            $M .= chr(ord($C2Bin[$i]) ^ ord($t[$i]));
        }

        $u = Sm3::sm3(Hex::fromHex($x2) . $M . Hex::fromHex($y2));
        if ($u !== $C3) {
            throw new CryptoException('SM2 decryption failed: ciphertext verification failed');
        }

        return $M;
    }

    /**
     * Encrypt data using SM2 (CipherInterface compliant).
     *
     * @param string $data     Plaintext data
     * @param string $publicKey 128-char hex string
     * @param mixed  $options  Sm2CipherOptions instance or null
     * @return string Hex-encoded ciphertext
     */
    public static function encrypt(string $data, string $publicKey, mixed $options = null): string
    {
        return self::doEncrypt($data, $publicKey, $options);
    }

    /**
     * Decrypt data using SM2 (CipherInterface compliant).
     *
     * @param string $data      Hex-encoded ciphertext
     * @param string $privateKey 64-char hex string
     * @param mixed  $options   Sm2CipherOptions instance or null
     * @return string Decrypted plaintext
     */
    public static function decrypt(string $data, string $privateKey, mixed $options = null): string
    {
        return self::doDecrypt($data, $privateKey, $options);
    }

    /**
     * Sign data using SM2 (SignerInterface compliant).
     *
     * @param string $data      Data to sign
     * @param string $privateKey 64-char hex string
     * @param mixed  $options   SignatureOptions instance or null
     * @return string Signature (hex or DER depending on options)
     */
    public static function sign(string $data, string $privateKey, mixed $options = null): string
    {
        return self::doSignature($data, $privateKey, $options);
    }

    /**
     * Verify SM2 signature (SignerInterface compliant).
     *
     * @param string $data      Original data
     * @param string $signature Signature to verify
     * @param string $publicKey 128-char hex string
     * @param mixed  $options   SignatureOptions instance or null
     * @return bool True if signature is valid
     */
    public static function verify(string $data, string $signature, string $publicKey, mixed $options = null): bool
    {
        return self::doVerifySignature($data, $signature, $publicKey, $options);
    }

    /**
     * Sign data using SM2.
     *
     * @param string              $data      Data to sign
     * @param string              $privateKey 64-char hex string
     * @param SignatureOptions|null $options  Signature options (DER, hash, publicKey, userId)
     * @return string Hex-encoded signature (or DER hex if options.der=true)
     * @throws InvalidKeyException If private key is invalid
     * @throws CryptoException    If signing fails after max retries
     */
    public static function doSignature(string $data, string $privateKey, ?SignatureOptions $options = null): string
    {
        $options ??= new SignatureOptions();

        $der = $options->getDer();
        $hash = $options->getHash();
        $publicKey = $options->getPublicKey();
        $userId = $options->getUserId();

        self::validatePrivateKey($privateKey);

        $e = self::calcE($data, $hash, $publicKey ?: self::pointMultiply($privateKey), $userId);

        $n = self::gmpParam('n');
        $d = gmp_init($privateKey, 16);
        $dPlus1Inv = gmp_invert(gmp_add($d, gmp_init(1)), $n);

        $maxRetries = 100;
        $retry = 0;
        $s = gmp_init(0);
        do {
            $k = gmp_random_range(gmp_init(1), gmp_sub($n, gmp_init(1)));
            $x1y1 = self::pointMultiply(gmp_strval($k, 16));
            $x1Dec = gmp_init(substr($x1y1, 0, 64), 16);

            if (gmp_cmp($x1Dec, $n) >= 0 || gmp_cmp($x1Dec, 0) === 0) {
                continue;
            }

            $r = gmp_mod(gmp_add($e, $x1Dec), $n);
            if (gmp_cmp($r, 0) === 0 || gmp_cmp(gmp_add($r, $k), $n) === 0) {
                continue;
            }

            $tmp = gmp_mod(gmp_sub($k, gmp_mul($r, $d)), $n);
            $s = gmp_mod(gmp_mul($dPlus1Inv, $tmp), $n);

            $retry++;
            if ($retry >= $maxRetries) {
                throw new CryptoException('SM2 signature failed: max retries exceeded');
            }
        } while (gmp_cmp($s, 0) === 0);

        $rHex = str_pad(gmp_strval($r, 16), 64, '0', STR_PAD_LEFT);
        $sHex = str_pad(gmp_strval($s, 16), 64, '0', STR_PAD_LEFT);

        return $der ? Asn1::encodeDerSignature($rHex, $sHex) : $rHex . $sHex;
    }

    /**
     * Verify an SM2 signature.
     *
     * @param string              $data      Original data
     * @param string              $signature Signature to verify (hex or DER)
     * @param string              $publicKey 128-char hex string
     * @param SignatureOptions|null $options  Signature options (must match signing)
     * @return bool True if signature is valid
     */
    public static function doVerifySignature(string $data, string $signature, string $publicKey, ?SignatureOptions $options = null): bool
    {
        $options ??= new SignatureOptions();
        $der = $options->getDer() || strtolower(substr($signature, 0, 2)) === '30';
        $hash = $options->getHash();
        $userId = $options->getUserId();

        if (!self::isOnCurve($publicKey)) {
            return false;
        }

        try {
            [$x1Hex, $sHex] = $der ? Asn1::decodeDerSignature($signature) : [substr($signature, 0, 64), substr($signature, 64)];
        } catch (CryptoException) {
            return false;
        }

        $n = self::gmpParam('n');
        $x1Dec = gmp_init($x1Hex, 16);
        $sDec = gmp_init($sHex, 16);
        if (gmp_cmp($x1Dec, 0) <= 0 || gmp_cmp($x1Dec, $n) >= 0 || gmp_cmp($sDec, 0) <= 0 || gmp_cmp($sDec, $n) >= 0) {
            return false;
        }

        $e = self::calcE($data, $hash, $publicKey, $userId);
        $t = gmp_mod(gmp_add($x1Dec, $sDec), $n);
        if (gmp_cmp($t, 0) === 0) {
            return false;
        }

        $point1 = self::pointMultiply('', gmp_strval($sDec, 16));
        $point2 = self::pointMultiply($publicKey, gmp_strval($t, 16));
        if ($point1 === null || $point2 === null) {
            return false;
        }

        $p = self::gmpParam('p');
        $a = self::gmpParam('a');
        $sum = self::pointAdd(
            gmp_init(substr($point1, 0, 64), 16),
            gmp_init(substr($point1, 64), 16),
            gmp_init(substr($point2, 0, 64), 16),
            gmp_init(substr($point2, 64), 16),
            $p,
            $a
        );
        if ($sum === null) {
            return false;
        }

        $x2Hex = str_pad(gmp_strval($sum['x'], 16), 64, '0', STR_PAD_LEFT);
        $v = gmp_mod(gmp_add($e, gmp_init($x2Hex, 16)), $n);
        return gmp_strval($v, 16) === gmp_strval($x1Dec, 16);
    }

    private static function calcE(string $data, bool $hash, string $publicKey, string $userId): \GMP
    {
        if ($hash) {
            $x = substr($publicKey, 0, 64);
            $y = substr($publicKey, 64);
            $userId = is_string($userId) ? $userId : '';
            $z = Sm3::sm3(self::getUserIdHash($userId, $x, $y));
            $dataHex = empty($data) ? '00' : $z . bin2hex($data);
            return gmp_init($dataHex, 16);
        }
        $dataHex = empty($data) ? '00' : bin2hex($data);
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

        return $userIdHex . self::intToHex($len) . $a . $b . $gX . $gY . $x . $y;
    }

    private static function intToHex(int $n): string
    {
        return str_pad(dechex($n), 8, '0', STR_PAD_LEFT);
    }

    private static function kdf(string $seed, int $keyLen): string
    {
        $ct = 1;
        $key = '';
        while (strlen($key) < $keyLen) {
            $hash = Sm3::sm3(Hex::fromHex($seed . self::intToHex($ct)));
            $key .= Hex::fromHex($hash);
            $ct++;
        }
        return substr($key, 0, $keyLen);
    }

    private static function pointMultiply(string $point, ?string $factor = null): ?string
    {
        $p = self::gmpParam('p');
        $a = self::gmpParam('a');

        $Gx = self::gmpParam('gX');
        $Gy = self::gmpParam('gY');

        if (strlen($point) > 64) {
            $pointX = gmp_init(substr($point, 0, 64), 16);
            $pointY = gmp_init(substr($point, 64), 16);
        } else {
            $pointX = $Gx;
            $pointY = $Gy;
            $factor ??= $point;
        }

        $factor ??= bin2hex(random_bytes(32));
        $factorDec = gmp_init($factor, 16);
        $factorBin = gmp_strval($factorDec, 2);

        $resultX = null;
        $resultY = null;
        $currentX = $pointX;
        $currentY = $pointY;

        for ($i = strlen($factorBin) - 1; $i >= 0; $i--) {
            if ($factorBin[$i] === '1') {
                if ($resultX === null) {
                    $resultX = $currentX;
                    $resultY = $currentY;
                } else {
                    $temp = self::pointAdd($resultX, $resultY, $currentX, $currentY, $p, $a);
                    if ($temp === null) {
                        return null;
                    }
                    $resultX = $temp['x'];
                    $resultY = $temp['y'];
                }
            }
            $temp = self::pointDouble($currentX, $currentY, $p, $a);
            $currentX = $temp['x'];
            $currentY = $temp['y'];
        }

        if ($resultX === null) {
            return str_repeat('0', 128);
        }

        return str_pad(gmp_strval($resultX, 16), 64, '0', STR_PAD_LEFT) .
            str_pad(gmp_strval($resultY, 16), 64, '0', STR_PAD_LEFT);
    }

    private static function pointAdd(\GMP $x1, \GMP $y1, \GMP $x2, \GMP $y2, \GMP $p, \GMP $a): ?array
    {
        if (gmp_cmp($x1, $x2) === 0) {
            if (gmp_cmp($y1, $y2) === 0) {
                return self::pointDouble($x1, $y1, $p, $a);
            }
            return null;
        }

        $lambda = gmp_mod(gmp_mul(gmp_sub($y2, $y1), gmp_invert(gmp_sub($x2, $x1), $p)), $p);
        $x3 = gmp_mod(gmp_sub(gmp_sub(gmp_pow($lambda, 2), $x1), $x2), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x1, $x3)), $y1), $p);

        return ['x' => $x3, 'y' => $y3];
    }

    private static function pointDouble(\GMP $x, \GMP $y, \GMP $p, \GMP $a): array
    {
        $lambda = gmp_mod(
            gmp_mul(
                gmp_add(gmp_mul(gmp_init(3), gmp_pow($x, 2)), $a),
                gmp_invert(gmp_mul(gmp_init(2), $y), $p)
            ),
            $p
        );
        $x3 = gmp_mod(gmp_sub(gmp_pow($lambda, 2), gmp_mul(gmp_init(2), $x)), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x, $x3)), $y), $p);
        return ['x' => $x3, 'y' => $y3];
    }

    private static function validatePrivateKey(string $privateKey): void
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

    private static function isAllZero(string $data): bool
    {
        return trim($data, "\0") === '';
    }

    private static function isOnCurve(string $publicKey): bool
    {
        if (strlen($publicKey) !== 128) {
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

    private static function parsePoint(string $hex): ?array
    {
        if (strlen($hex) !== 128) {
            return null;
        }
        return [
            'x' => gmp_init(substr($hex, 0, 64), 16),
            'y' => gmp_init(substr($hex, 64), 16),
        ];
    }
}
