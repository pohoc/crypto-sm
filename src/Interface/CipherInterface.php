<?php

declare(strict_types=1);

namespace CryptoSm\Interface;

/**
 * Interface for symmetric/asymmetric cipher implementations.
 */
interface CipherInterface
{
    /**
     * Encrypt data.
     *
     * @param string $data    Data to encrypt
     * @param string $key     Encryption key
     * @param mixed  $options Algorithm-specific options
     * @return string Encrypted data
     */
    public static function encrypt(string $data, string $key, mixed $options = null): string;

    /**
     * Decrypt data.
     *
     * @param string $data    Data to decrypt
     * @param string $key     Decryption key
     * @param mixed  $options Algorithm-specific options
     * @return string Decrypted data
     */
    public static function decrypt(string $data, string $key, mixed $options = null): string;
}
