<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

/**
 * Represents an SM2 key pair.
 */
class Keypair implements \JsonSerializable
{
    private string $privateKey;
    private string $publicKey;

    /**
     * @param string $privateKey 64-character hex string
     * @param string $publicKey  128-character hex string (uncompressed, without "04" prefix)
     */
    public function __construct(string $privateKey, string $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * Get the private key.
     *
     * @return string 64-character hex string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    /**
     * Get the public key.
     *
     * @return string 128-character hex string (uncompressed)
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function __toString(): string
    {
        return $this->privateKey . $this->publicKey;
    }

    /**
     * @return array{privateKey: string, publicKey: string}
     */
    public function jsonSerialize(): array
    {
        return ['privateKey' => $this->privateKey, 'publicKey' => $this->publicKey];
    }
}
