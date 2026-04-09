<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

/**
 * Options for SM2 signature operations.
 */
class SignatureOptions
{
    private bool $der = false;
    private bool $hash = false;
    private string $publicKey = '';
    private string $userId = '1234567812345678';

    /**
     * Whether to use DER encoding for the signature.
     */
    public function getDer(): bool
    {
        return $this->der;
    }

    /**
     * Set whether to use DER encoding for the signature.
     *
     * @param bool $der True to encode signature in DER format
     * @return self
     */
    public function setDer(bool $der): self
    {
        $this->der = $der;
        return $this;
    }

    /**
     * Whether to hash the message before signing (SM2 with SM3).
     */
    public function getHash(): bool
    {
        return $this->hash;
    }

    /**
     * Set whether to hash the message before signing.
     *
     * When true, the message is hashed with SM3 along with the user ID
     * and public key per the SM2 standard.
     *
     * @param bool $hash True to enable hashing
     * @return self
     */
    public function setHash(bool $hash): self
    {
        $this->hash = $hash;
        return $this;
    }

    /**
     * Get the public key used for hash computation (128-char hex string).
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Set the public key for hash computation.
     *
     * Required when hash=true. If not set, the public key will be
     * derived from the private key during signing.
     *
     * @param string $publicKey 128-character hex string (uncompressed, without "04" prefix)
     * @return self
     */
    public function setPublicKey(string $publicKey): self
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    /**
     * Get the user ID for SM2 signature hash computation.
     */
    public function getUserId(): string
    {
        return $this->userId;
    }

    /**
     * Set the user ID for SM2 signature hash computation.
     *
     * Default: "1234567812345678" (the standard default ID per GM/T 0003-2012).
     *
     * @param string $userId User ID string
     * @return self
     */
    public function setUserId(string $userId): self
    {
        $this->userId = $userId;
        return $this;
    }
}
