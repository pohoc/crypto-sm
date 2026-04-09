<?php

declare(strict_types=1);

namespace CryptoSm\Interface;

/**
 * Interface for digital signature implementations.
 */
interface SignerInterface
{
    /**
     * Sign data.
     *
     * @param string $data      Data to sign
     * @param string $privateKey Private key for signing
     * @param mixed  $options   Algorithm-specific options
     * @return string Signature string
     */
    public static function sign(string $data, string $privateKey, mixed $options = null): string;

    /**
     * Verify a signature.
     *
     * @param string $data      Original data
     * @param string $signature Signature to verify
     * @param string $publicKey  Public key for verification
     * @param mixed  $options   Algorithm-specific options
     * @return bool True if the signature is valid
     */
    public static function verify(string $data, string $signature, string $publicKey, mixed $options = null): bool;
}
