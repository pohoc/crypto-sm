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

    /**
     * @return string Public key only; private key is intentionally excluded from string context
     * @deprecated This method leaks the private key into string context (logs, errors, etc.).
     *             Use getPrivateKey() / getPublicKey() explicitly. Will be removed in a future major release.
     */
    public function __toString(): string
    {
        @trigger_error('CryptoSm\SM2\Keypair::__toString is deprecated and will be removed in a future major release. Use getPublicKey() explicitly.', E_USER_DEPRECATED);
        return $this->publicKey;
    }

    /**
     * Controls var_dump output — hides the private key to prevent accidental leakage.
     *
     * @return array{privateKey: string, publicKey: string}
     */
    public function __debugInfo(): array
    {
        return [
            'privateKey' => '***REDACTED***',
            'publicKey'  => $this->publicKey,
        ];
    }

    /**
     * @return array{privateKey: string, publicKey: string}
     */
    public function jsonSerialize(): array
    {
        return ['privateKey' => '***REDACTED***', 'publicKey' => $this->publicKey];
    }
}
