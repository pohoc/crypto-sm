<?php

declare(strict_types=1);

namespace CryptoSm;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2 as SM2Crypto;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

/**
 * Facade class providing unified access to SM2, SM3, and SM4 operations.
 */
class SmCrypto
{
    /**
     * Generate a new SM2 key pair.
     *
     * @return Keypair Generated key pair
     */
    public static function generateKeyPair(): Keypair
    {
        return SM2Crypto::generateKeyPairHex();
    }

    /**
     * Encrypt data using SM2.
     *
     * @param  string                $data      Plaintext data
     * @param  string                $publicKey 128-char hex string
     * @param  Sm2CipherOptions|null $options   Cipher mode options
     * @return string                Hex-encoded ciphertext
     * @throws InvalidKeyException   If public key is invalid
     * @throws CryptoException       If encryption fails
     */
    public static function encrypt(string $data, string $publicKey, ?Sm2CipherOptions $options = null): string
    {
        return SM2Crypto::doEncrypt($data, $publicKey, $options);
    }

    /**
     * Decrypt data using SM2.
     *
     * @param  string                $data       Hex-encoded ciphertext
     * @param  string                $privateKey 64-char hex string
     * @param  Sm2CipherOptions|null $options    Cipher mode options
     * @return string                Decrypted plaintext
     * @throws InvalidKeyException   If private key or ciphertext is invalid
     * @throws CryptoException       If decryption or verification fails
     */
    public static function decrypt(string $data, string $privateKey, ?Sm2CipherOptions $options = null): string
    {
        return SM2Crypto::doDecrypt($data, $privateKey, $options);
    }

    /**
     * Sign data using SM2.
     *
     * @param  string                $data       Data to sign
     * @param  string                $privateKey 64-char hex string
     * @param  SignatureOptions|null $options    Signature options
     * @return string                Signature string
     * @throws InvalidKeyException   If private key is invalid
     * @throws CryptoException       If signing fails after max retries
     */
    public static function sign(string $data, string $privateKey, ?SignatureOptions $options = null): string
    {
        return SM2Crypto::doSignature($data, $privateKey, $options);
    }

    /**
     * Verify an SM2 signature.
     *
     * @param  string                $data      Original data
     * @param  string                $signature Signature to verify
     * @param  string                $publicKey 128-char hex string
     * @param  SignatureOptions|null $options   Signature options
     * @return bool                  True if valid (never throws; errors return false)
     */
    public static function verify(string $data, string $signature, string $publicKey, ?SignatureOptions $options = null): bool
    {
        return SM2Crypto::doVerifySignature($data, $signature, $publicKey, $options);
    }

    /**
     * Compute SM3 hash.
     *
     * @param  string $data Input data
     * @return string 64-character hex string
     */
    public static function sm3(string $data): string
    {
        return Sm3::sm3($data);
    }

    /**
     * Encrypt data using SM4 (CBC mode with default options).
     *
     * @param  string              $data    Plaintext data
     * @param  string              $key     32-char hex string (128-bit key)
     * @param  Sm4Options|null     $options SM4 options
     * @return string              Hex-encoded ciphertext
     * @throws InvalidKeyException If key or options are invalid
     * @throws CryptoException     If encryption fails
     */
    public static function sm4Encrypt(string $data, string $key, ?Sm4Options $options = null): string
    {
        return Sm4::encrypt($data, $key, $options);
    }

    /**
     * Decrypt data using SM4.
     *
     * @param  string              $data    Hex-encoded ciphertext
     * @param  string              $key     32-char hex string (128-bit key)
     * @param  Sm4Options|null     $options SM4 options
     * @return string              Decrypted plaintext
     * @throws InvalidKeyException If key, ciphertext, or options are invalid
     * @throws CryptoException     If decryption fails
     */
    public static function sm4Decrypt(string $data, string $key, ?Sm4Options $options = null): string
    {
        return Sm4::decrypt($data, $key, $options);
    }
}
