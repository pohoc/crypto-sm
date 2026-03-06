<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\SM3\Sm3;
use CryptoSm\Utils\Hex;

/**
 * SM2 cryptographic algorithm implementation.
 *
 * Supports encryption, decryption, signature, and verification
 * based on the Chinese national standard GM/T 0003-2012.
 */
class Sm2
{
    public const CIPHER_MODE_1 = 1;
    public const CIPHER_MODE_0 = 0;

    private static array $eccTable = [
        'n' => 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
        'p' => 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        'a' => 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
        'b' => '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
        'gX' => '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7',
        'gY' => 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    ];

    /**
     * Generates an SM2 key pair in hexadecimal format.
     */
    public static function generateKeyPairHex(): Keypair
    {
        $keypair = self::generateKeyPair();
        return new Keypair($keypair['privateKey'], $keypair['publicKey']);
    }

    /**
     * Generates an SM2 key pair.
     */
    private static function generateKeyPair(): array
    {
        $n = gmp_init(self::$eccTable['n'], 16);

        do {
            $d = gmp_random_range(gmp_init(1), gmp_sub($n, gmp_init(1)));
        } while (gmp_cmp($d, 1) < 0 || gmp_cmp($d, $n) >= 0);

        $privateKey = gmp_strval($d, 16);
        $privateKey = str_pad($privateKey, 64, '0', STR_PAD_LEFT);

        $publicKey = self::pointMultiply($privateKey);

        return [
            'privateKey' => $privateKey,
            'publicKey' => $publicKey,
        ];
    }

    /**
     * Encrypts data using SM2 algorithm.
     *
     * @param string $data The plaintext data to encrypt
     * @param string $publicKey The public key in hexadecimal format (128 characters)
     * @param Sm2CipherOptions|null $options Cipher options
     * @return string The encrypted ciphertext
     */
    public static function doEncrypt(string $data, string $publicKey, ?Sm2CipherOptions $options = null): string
    {
        $options = $options ?? new Sm2CipherOptions();
        $cipherMode = $options->getCipherMode();

        do {
            $k = bin2hex(random_bytes(32));

            $x1y1 = self::pointMultiply($k);
            $x1 = substr($x1y1, 0, 64);
            $y1 = substr($x1y1, 64);
            $C1 = $x1y1;

            $x2y1 = self::pointMultiply($publicKey, $k);
            $x2 = substr($x2y1, 0, 64);
            $y2 = substr($x2y1, 64);

            $dataLen = strlen($data);
            $t = self::kdf($x2 . $y2, $dataLen);

            $C2 = '';
            for ($i = 0; $i < $dataLen; $i++) {
                $C2 .= chr(ord($data[$i]) ^ ord($t[$i]));
            }
            $C2Bin = $C2;
            $C2 = bin2hex($C2);

            $C3 = Sm3::sm3(Hex::fromHex($x2) . $data . Hex::fromHex($y2));
        } while (strpos($t, "\0") !== false);

        if ($cipherMode === self::CIPHER_MODE_1) {
            return $C1 . $C3 . $C2;
        } else {
            return $C1 . $C2 . $C3;
        }
    }

    /**
     * Decrypts data using SM2 algorithm.
     *
     * @param string $data The ciphertext data to decrypt
     * @param string $privateKey The private key in hexadecimal format (64 characters)
     * @param Sm2CipherOptions|null $options Cipher options
     * @return string The decrypted plaintext
     * @throws \Exception If decryption fails
     */
    public static function doDecrypt(string $data, string $privateKey, ?Sm2CipherOptions $options = null): string
    {
        $options = $options ?? new Sm2CipherOptions();
        $cipherMode = $options->getCipherMode();

        $C1 = substr($data, 0, 128);

        if ($cipherMode === self::CIPHER_MODE_1) {
            $C3 = substr($data, 128, 64);
            $C2 = substr($data, 192);
        } else {
            $C2 = substr($data, 128, -64);
            $C3 = substr($data, -64);
        }

        $x2y1 = self::pointMultiply($C1, $privateKey);
        $x2 = substr($x2y1, 0, 64);
        $y2 = substr($x2y1, 64);

        $dataLen = strlen($C2) / 2;
        $t = self::kdf($x2 . $y2, $dataLen);

        $C2Bin = Hex::fromHex($C2);
        $M = '';
        for ($i = 0; $i < $dataLen; $i++) {
            $M .= chr(ord($C2Bin[$i]) ^ ord($t[$i]));
        }

        $u = Sm3::sm3(Hex::fromHex($x2) . $M . Hex::fromHex($y2));

        if ($u !== $C3) {
            throw new \Exception('Verification failed');
        }

        return $M;
    }

    /**
     * Signs data using SM2 algorithm.
     *
     * @param string $data The data to sign
     * @param string $privateKey The private key in hexadecimal format (64 characters)
     * @param SignatureOptions|null $options Signature options
     * @return string The signature in hexadecimal format (128 chars) or DER format
     */
    public static function doSignature(string $data, string $privateKey, ?SignatureOptions $options = null): string
    {
        $options = $options ?? new SignatureOptions();

        $der = $options->getDer();
        $hash = $options->getHash();
        $publicKey = $options->getPublicKey();
        $userId = $options->getUserId();

        $e = '';
        $x = '';
        $y = '';

        if ($hash) {
            if ($publicKey) {
                $x = substr($publicKey, 0, 64);
                $y = substr($publicKey, 64);
            } else {
                $x1y1 = self::pointMultiply($privateKey);
                $x = substr($x1y1, 0, 64);
                $y = substr($x1y1, 64);
            }

            $userId = is_string($userId) ? $userId : '';
            $z = Sm3::sm3(self::getUserIdHash($userId, $x, $y));
            $dataHex = empty($data) ? '00' : $z . bin2hex($data);
            $e = gmp_init($dataHex, 16);
        } else {
            $dataHex = empty($data) ? '00' : bin2hex($data);
            $e = gmp_init($dataHex, 16);
        }

        $n = gmp_init(self::$eccTable['n'], 16);
        $d = gmp_init($privateKey, 16);

        $dPlus1 = gmp_add($d, gmp_init(1));
        $dPlus1Inv = gmp_invert($dPlus1, $n);

        do {
            $k = gmp_random_range(gmp_init(1), gmp_sub($n, gmp_init(1)));

            $x1y1 = self::pointMultiply(gmp_strval($k, 16));
            $x1 = substr($x1y1, 0, 64);
            $y1 = substr($x1y1, 64);
            $x1Dec = gmp_init($x1, 16);

            if (gmp_cmp($x1Dec, $n) >= 0 || gmp_cmp($x1Dec, 0) === 0) {
                continue;
            }

            $r = gmp_mod(gmp_add($e, $x1Dec), $n);

            $tmp = gmp_mod(gmp_sub($k, gmp_mul($r, $d)), $n);
            $s = gmp_mod(gmp_mul($dPlus1Inv, $tmp), $n);
        } while (gmp_cmp($s, 0) === 0);

        $rHex = gmp_strval($r, 16);
        $rHex = str_pad($rHex, 64, '0', STR_PAD_LEFT);
        $sHex = gmp_strval($s, 16);
        $sHex = str_pad($sHex, 64, '0', STR_PAD_LEFT);

        if ($der) {
            return self::createDerSignature($sHex, $rHex);
        }

        return $rHex . $sHex;
    }

    /**
     * Creates a DER-encoded signature.
     */
    private static function createDerSignature(string $s, string $x1): string
    {
        $r = $x1;
        $sHex = str_pad($s, 64, '0', STR_PAD_LEFT);

        $rBytes = Hex::toBytes($r);
        $sBytes = Hex::toBytes($sHex);

        $rDer = self::derEncodeInteger($rBytes);
        $sDer = self::derEncodeInteger($sBytes);

        return bin2hex(chr(0x30) . chr(strlen($rDer . $sDer)) . $rDer . $sDer);
    }

    /**
     * Encodes an integer as DER format.
     */
    private static function derEncodeInteger(array $bytes): string
    {
        $length = count($bytes);

        while (count($bytes) > 1 && $bytes[0] === 0) {
            array_shift($bytes);
        }

        if ($bytes[0] > 0x7f) {
            array_unshift($bytes, 0);
        }

        $length = count($bytes);

        if ($length < 128) {
            $lengthBytes = chr($length);
        } elseif ($length < 256) {
            $lengthBytes = chr(0x81) . chr($length);
        } else {
            $lengthBytes = chr(0x82) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }

        return chr(0x02) . $lengthBytes . implode('', array_map('chr', $bytes));
    }

    /**
     * Verifies SM2 signature.
     *
     * @param string $data The signed data
     * @param string $signature The signature to verify
     * @param string $publicKey The public key in hexadecimal format (128 characters)
     * @param SignatureOptions|null $options Signature options
     * @return bool True if signature is valid, false otherwise
     */
    public static function doVerifySignature(string $data, string $signature, string $publicKey, ?SignatureOptions $options = null): bool
    {
        $options = $options ?? new SignatureOptions();

        $der = $options->getDer();
        $hash = $options->getHash();
        $userId = $options->getUserId();

        $x = substr($publicKey, 0, 64);
        $y = substr($publicKey, 64);

        if ($der || strtolower(substr($signature, 0, 2)) === '30') {
            $signatureHex = $signature;

            $offset = 2;
            $seqLen = hexdec(substr($signatureHex, $offset, 2));

            $offset += 2;
            if (substr($signatureHex, $offset, 2) !== '02') {
                return false;
            }
            $offset += 2;
            $rLen = hexdec(substr($signatureHex, $offset, 2));
            $offset += 2;
            $r = substr($signatureHex, $offset, $rLen * 2);
            $offset += $rLen * 2;

            if (strlen($r) > 64 && substr($r, 0, 2) === '00') {
                $r = substr($r, 2);
            }
            if (strlen($r) % 2 !== 0) {
                $r = '0' . $r;
            }
            $x1 = str_pad($r, 64, '0', STR_PAD_LEFT);

            if (substr($signatureHex, $offset, 2) !== '02') {
                return false;
            }
            $offset += 2;
            $sLen = hexdec(substr($signatureHex, $offset, 2));
            $offset += 2;
            $s = substr($signatureHex, $offset, $sLen * 2);

            if (strlen($s) > 64 && substr($s, 0, 2) === '00') {
                $s = substr($s, 2);
            }
            if (strlen($s) % 2 !== 0) {
                $s = '0' . $s;
            }
            $sHex = str_pad($s, 64, '0', STR_PAD_LEFT);
        } else {
            if (strlen($signature) !== 128) {
                return false;
            }
            $x1 = substr($signature, 0, 64);
            $sHex = substr($signature, 64);
        }

        $e = '';
        if ($hash) {
            $userId = is_string($userId) ? $userId : '';
            $z = Sm3::sm3(self::getUserIdHash($userId, $x, $y));
            $dataHex = empty($data) ? '00' : $z . bin2hex($data);
            $e = gmp_init($dataHex, 16);
        } else {
            $dataHex = empty($data) ? '00' : bin2hex($data);
            $e = gmp_init($dataHex, 16);
        }

        $n = gmp_init(self::$eccTable['n'], 16);
        $x1Dec = gmp_init($x1, 16);
        $sDec = gmp_init($sHex, 16);

        if (gmp_cmp($x1Dec, $n) >= 0 || gmp_cmp($sDec, $n) >= 0) {
            return false;
        }

        $t = gmp_mod(gmp_add($x1Dec, $sDec), $n);
        if (gmp_cmp($t, 0) === 0) {
            return false;
        }

        $point1 = self::pointMultiply('', gmp_strval($sDec, 16));
        $point2 = self::pointMultiply($x . $y, gmp_strval($t, 16));

        $p = gmp_init(self::$eccTable['p'], 16);
        $a = gmp_init(self::$eccTable['a'], 16);

        $sum = self::pointAdd(
            gmp_init(substr($point1, 0, 64), 16),
            gmp_init(substr($point1, 64), 16),
            gmp_init(substr($point2, 0, 64), 16),
            gmp_init(substr($point2, 64), 16),
            $p,
            $a
        );

        $x2 = gmp_strval($sum['x'], 16);
        $y2 = gmp_strval($sum['y'], 16);

        $x2Hex = str_pad($x2, 64, '0', STR_PAD_LEFT);
        $y2Hex = str_pad($y2, 64, '0', STR_PAD_LEFT);

        $v = gmp_mod(gmp_add($e, gmp_init($x2, 16)), $n);
        $r = gmp_mod(gmp_init($x1, 16), $n);

        return gmp_strval($v, 16) === gmp_strval($r, 16);
    }

    /**
     * Calculates the hash of user ID for SM2 signature.
     */
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

    /**
     * Converts an integer to hexadecimal string.
     */
    private static function intToHex(int $n): string
    {
        return str_pad(dechex($n), 8, '0', STR_PAD_LEFT);
    }

    /**
     * Key Derivation Function (KDF) for SM2 encryption.
     */
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

    /**
     * Performs point multiplication on the elliptic curve.
     */
    private static function pointMultiply(string $point, ?string $factor = null): string
    {
        $p = gmp_init(self::$eccTable['p'], 16);
        $a = gmp_init(self::$eccTable['a'], 16);

        $Gx = gmp_init(self::$eccTable['gX'], 16);
        $Gy = gmp_init(self::$eccTable['gY'], 16);

        if (strlen($point) > 64) {
            $pointX = gmp_init(substr($point, 0, 64), 16);
            $pointY = gmp_init(substr($point, 64), 16);
        } else {
            $pointX = $Gx;
            $pointY = $Gy;
            if ($factor === null) {
                $factor = $point;
            }
        }

        if ($factor === null) {
            $factor = bin2hex(random_bytes(32));
        }

        $factorDec = gmp_init($factor, 16);
        $factorBin = gmp_strval($factorDec, 2);

        $resultX = null;
        $resultY = null;

        $currentX = $pointX;
        $currentY = $pointY;

        $len = strlen($factorBin);
        for ($i = $len - 1; $i >= 0; $i--) {
            if ($factorBin[$i] === '1') {
                if ($resultX === null) {
                    $resultX = $currentX;
                    $resultY = $currentY;
                } else {
                    $temp = self::pointAdd($resultX, $resultY, $currentX, $currentY, $p, $a);
                    $resultX = $temp['x'];
                    $resultY = $temp['y'];
                }
            }

            $temp = self::pointDouble($currentX, $currentY, $p, $a);
            $currentX = $temp['x'];
            $currentY = $temp['y'];
        }

        if ($resultX === null) {
            return str_pad('', 64, '0') . str_pad('', 64, '0');
        }

        return str_pad(gmp_strval($resultX, 16), 64, '0', STR_PAD_LEFT) .
            str_pad(gmp_strval($resultY, 16), 64, '0', STR_PAD_LEFT);
    }

    /**
     * Adds two points on the elliptic curve.
     */
    private static function pointAdd(\GMP $x1, \GMP $y1, \GMP $x2, \GMP $y2, \GMP $p, \GMP $a): ?array
    {
        if (gmp_cmp($x1, $x2) === 0) {
            if (gmp_cmp($y1, $y2) === 0) {
                return self::pointDouble($x1, $y1, $p, $a);
            }
            return null;
        }

        $t1 = gmp_mod(gmp_sub($y2, $y1), $p);
        $t2 = gmp_mod(gmp_sub($x2, $x1), $p);

        $lambda = gmp_mod(gmp_mul($t1, gmp_invert($t2, $p)), $p);

        $x3 = gmp_mod(gmp_sub(gmp_sub(gmp_pow($lambda, 2), $x1), $x2), $p);

        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x1, $x3)), $y1), $p);

        return [
            'x' => $x3,
            'y' => $y3,
        ];
    }

    /**
     * Doubles a point on the elliptic curve.
     */
    private static function pointDouble(\GMP $x, \GMP $y, \GMP $p, \GMP $a): array
    {
        $x2 = gmp_mod(gmp_pow($x, 2), $p);
        $threeX2 = gmp_mod(gmp_mul(gmp_init(3), $x2), $p);
        $lambda = gmp_mod(gmp_mul(gmp_add($threeX2, $a), gmp_invert(gmp_mul(gmp_init(2), $y), $p)), $p);

        $x3 = gmp_mod(gmp_sub(gmp_pow($lambda, 2), gmp_mul(gmp_init(2), $x)), $p);

        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x, $x3)), $y), $p);

        return [
            'x' => $x3,
            'y' => $y3,
        ];
    }
}
