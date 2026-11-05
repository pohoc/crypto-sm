<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Exception\InvalidKeyException;

/**
 * Represents an SM2 key pair.
 */
class Keypair implements \JsonSerializable
{
    /** @var \WeakMap<object, string>|null */
    private static ?\WeakMap $privateKeys = null;
    private object $privateKeyHandle;
    private string $publicKey;

    /** @return \WeakMap<object, string> */
    private static function privateKeys(): \WeakMap
    {
        return self::$privateKeys ??= new \WeakMap();
    }

    /**
     * @param  string              $privateKey 64-character SM2 private or ephemeral scalar
     * @param  string              $publicKey  128-character uncompressed SM2 public point (without "04" prefix)
     * @throws InvalidKeyException If the key material is invalid or does not form a pair
     */
    public function __construct(string $privateKey, string $publicKey)
    {
        Sm2::validateEphemeralScalar($privateKey);
        if (!Sm2::isOnCurve($publicKey)) {
            throw new InvalidKeyException('Public key must be a valid point on the SM2 curve');
        }

        $derivedPublicKey = Sm2::getEphemeralPublicKey($privateKey);
        if (!hash_equals(strtolower($derivedPublicKey), strtolower($publicKey))) {
            throw new InvalidKeyException('SM2 public key does not correspond to the private key');
        }

        $this->privateKeyHandle = new \stdClass();
        self::privateKeys()[$this->privateKeyHandle] = $privateKey;
        $this->publicKey = $publicKey;
    }

    public function __clone()
    {
        $privateKey = $this->getPrivateKey();
        $this->privateKeyHandle = new \stdClass();
        self::privateKeys()[$this->privateKeyHandle] = $privateKey;
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new \LogicException('SM2 key pairs cannot be serialized');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('SM2 key pairs cannot be unserialized');
    }

    /**
     * Get the private key.
     *
     * @return string 64-character hex string
     */
    public function getPrivateKey(): string
    {
        $privateKey = self::privateKeys()[$this->privateKeyHandle] ?? null;
        if ($privateKey === null) {
            throw new \LogicException('SM2 private key is unavailable');
        }
        return $privateKey;
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
