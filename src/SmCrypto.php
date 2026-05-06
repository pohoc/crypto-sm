<?php

declare(strict_types=1);

namespace CryptoSm;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2 as SM2Crypto;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

/**
 * Facade class providing unified access to SM2, SM3, and SM4 operations.
 */
class SmCrypto
{
    // ─── SM2 Key Generation ───────────────────────────────────────────────

    /**
     * Generate a new SM2 key pair.
     *
     * @return Keypair Generated key pair
     */
    public static function generateKeyPair(): Keypair
    {
        return SM2Crypto::generateKeyPairHex();
    }

    // ─── SM2 Encryption/Decryption ────────────────────────────────────────

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

    // ─── SM2 Sign/Verify ──────────────────────────────────────────────────

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

    // ─── SM2 Key Utilities ────────────────────────────────────────────────

    /**
     * Derive the public key from a private key.
     *
     * @param  string $privateKey 64-char hex string
     * @return string 128-char hex uncompressed public key
     */
    public static function getPublicKey(string $privateKey): string
    {
        return SM2Crypto::getPublicKey($privateKey);
    }

    // ─── SM2 PEM Import/Export ────────────────────────────────────────────

    /**
     * Export a private key in SEC 1 PEM format.
     *
     * @param  string $privateKey 64-char hex private key
     * @param  string $publicKey  128-char hex public key (optional)
     * @return string PEM-encoded private key
     */
    public static function exportPrivateKeyPem(string $privateKey, string $publicKey = ''): string
    {
        return Pem::exportPrivateKey($privateKey, $publicKey);
    }

    /**
     * Export a private key in PKCS#8 PEM format.
     *
     * @param  string $privateKey 64-char hex private key
     * @return string PEM-encoded private key
     */
    public static function exportPrivateKeyPkcs8(string $privateKey): string
    {
        return Pem::exportPrivateKeyPkcs8($privateKey);
    }

    /**
     * Export a public key in PEM format.
     *
     * @param  string $publicKey 128-char hex public key
     * @return string PEM-encoded public key
     */
    public static function exportPublicKeyPem(string $publicKey): string
    {
        return Pem::exportPublicKey($publicKey);
    }

    /**
     * Import a private key from PEM format.
     *
     * @param  string                                       $pem PEM-encoded private key (SEC 1 or PKCS#8)
     * @return array{privateKey: string, publicKey: string}
     */
    public static function importPrivateKeyPem(string $pem): array
    {
        return Pem::importPrivateKey($pem);
    }

    /**
     * Import a public key from PEM format.
     *
     * @param  string $pem PEM-encoded public key
     * @return string 128-char hex public key
     */
    public static function importPublicKeyPem(string $pem): string
    {
        return Pem::importPublicKey($pem);
    }

    /**
     * Export a private key in SEC 1 DER format (raw binary).
     *
     * @param  string $privateKey 64-char hex private key
     * @param  string $publicKey  128-char hex public key (optional)
     * @return string DER-encoded binary data
     */
    public static function exportPrivateKeyDer(string $privateKey, string $publicKey = ''): string
    {
        return Pem::exportPrivateKeyDer($privateKey, $publicKey);
    }

    /**
     * Export a private key in PKCS#8 DER format (raw binary).
     *
     * @param  string $privateKey 64-char hex private key
     * @return string DER-encoded binary data
     */
    public static function exportPrivateKeyPkcs8Der(string $privateKey): string
    {
        return Pem::exportPrivateKeyPkcs8Der($privateKey);
    }

    /**
     * Export a public key in DER format (raw binary, SubjectPublicKeyInfo).
     *
     * @param  string $publicKey 128-char hex public key
     * @return string DER-encoded binary data
     */
    public static function exportPublicKeyDer(string $publicKey): string
    {
        return Pem::exportPublicKeyDer($publicKey);
    }

    /**
     * Import a private key from DER binary data.
     *
     * @param  string                                       $der DER-encoded binary data (SEC 1 or PKCS#8)
     * @return array{privateKey: string, publicKey: string}
     */
    public static function importPrivateKeyFromDer(string $der): array
    {
        return Pem::importPrivateKeyFromDer($der);
    }

    /**
     * Import a public key from DER binary data.
     *
     * @param  string $der DER-encoded binary data (SubjectPublicKeyInfo)
     * @return string 128-char hex public key
     */
    public static function importPublicKeyFromDer(string $der): string
    {
        return Pem::importPublicKeyFromDer($der);
    }

    // ─── SM2 Key Exchange ─────────────────────────────────────────────────

    /**
     * Generate an ephemeral keypair for SM2 key exchange.
     *
     * @return Keypair
     */
    public static function generateExchangeKeyPair(): Keypair
    {
        return KeyExchange::generateEphemeralKeyPair();
    }

    /**
     * Compute shared secret key (initiator side).
     *
     * @param  string $dA   Initiator's static private key
     * @param  string $rA   Initiator's ephemeral private key
     * @param  string $PB   Responder's static public key
     * @param  string $RB   Responder's ephemeral public key
     * @param  int    $klen Desired key length in bytes
     * @param  string $ida  Initiator's ID
     * @param  string $idb  Responder's ID
     * @return string Derived key as hex string
     */
    public static function initiatorKeyExchange(
        string $dA,
        string $rA,
        string $PB,
        string $RB,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): string {
        return KeyExchange::initiatorComputeKey($dA, $rA, $PB, $RB, $klen, $ida, $idb);
    }

    /**
     * Compute shared secret key (responder side).
     *
     * @param  string $dB   Responder's static private key
     * @param  string $rB   Responder's ephemeral private key
     * @param  string $PA   Initiator's static public key
     * @param  string $RA   Initiator's ephemeral public key
     * @param  int    $klen Desired key length in bytes
     * @param  string $ida  Initiator's ID
     * @param  string $idb  Responder's ID
     * @return string Derived key as hex string
     */
    public static function responderKeyExchange(
        string $dB,
        string $rB,
        string $PA,
        string $RA,
        int $klen,
        string $ida = '1234567812345678',
        string $idb = '1234567812345678'
    ): string {
        return KeyExchange::responderComputeKey($dB, $rB, $PA, $RA, $klen, $ida, $idb);
    }

    // ─── SM3 Hash ─────────────────────────────────────────────────────────

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
     * Create a new SM3 streaming hasher instance.
     *
     * @return Sm3
     */
    public static function sm3Stream(): Sm3
    {
        return new Sm3();
    }

    // ─── HMAC-SM3 ─────────────────────────────────────────────────────────

    /**
     * Compute HMAC-SM3.
     *
     * @param  string $key  Secret key
     * @param  string $data Data to authenticate
     * @return string 64-character hex string
     */
    public static function hmacSm3(string $key, string $data): string
    {
        return HmacSm3::hmac($key, $data);
    }

    /**
     * Create a streaming HMAC-SM3 instance.
     *
     * @param  string  $key Secret key
     * @return HmacSm3
     */
    public static function hmacSm3Stream(string $key): HmacSm3
    {
        return HmacSm3::create($key);
    }

    // ─── SM4 Encryption ───────────────────────────────────────────────────

    /**
     * Encrypt data using SM4.
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
