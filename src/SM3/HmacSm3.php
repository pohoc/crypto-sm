<?php

declare(strict_types=1);

namespace CryptoSm\SM3;

use CryptoSm\Utils\Hex;

/**
 * HMAC-SM3 implementation (RFC 2104 with SM3 as the underlying hash).
 *
 * HMAC(K, m) = SM3((K' ⊕ opad) || SM3((K' ⊕ ipad) || m))
 *
 * where K' is the key padded/hashed to the block size (64 bytes for SM3),
 * ipad = 0x36 repeated, opad = 0x5C repeated.
 */
class HmacSm3
{
    /** @var int Block size for SM3 in bytes */
    private const BLOCK_SIZE = 64;

    /**
     * Compute HMAC-SM3 of the given data with the given key.
     *
     * @param  string $key  Secret key (any length; if > 64 bytes it will be hashed per RFC 2104)
     * @param  string $data Data to authenticate
     * @return string 64-character hex string (256-bit HMAC)
     */
    public static function hmac(string $key, string $data): string
    {
        return self::create($key)->update($data)->finalize();
    }

    /**
     * Verify a lowercase or uppercase hexadecimal HMAC-SM3 value.
     *
     * Malformed values are rejected. Valid values are compared with
     * hash_equals() so callers do not need to implement MAC comparison safely.
     */
    public static function verify(string $key, string $data, string $mac): bool
    {
        if (!preg_match('/\\A[0-9a-fA-F]{64}\\z/', $mac)) {
            return false;
        }

        return hash_equals(self::hmac($key, $data), strtolower($mac));
    }

    /**
     * Create a streaming HMAC-SM3 instance.
     *
     * @param  string $key Secret key
     * @return self
     */
    public static function create(string $key): self
    {
        return new self($key);
    }

    /** @var \WeakMap<object, array{innerPad: string, outerPad: string, hasher: Sm3}>|null */
    private static ?\WeakMap $states = null;

    private object $handle;

    /** @return \WeakMap<object, array{innerPad: string, outerPad: string, hasher: Sm3}> */
    private static function states(): \WeakMap
    {
        return self::$states ??= new \WeakMap();
    }

    /** @return array{innerPad: string, outerPad: string, hasher: Sm3} */
    private function state(): array
    {
        $states = self::states();
        if (!isset($states[$this->handle])) {
            throw new \LogicException('HMAC-SM3 context is unavailable');
        }
        return $states[$this->handle];
    }

    private function __construct(string $key)
    {
        if (strlen($key) > self::BLOCK_SIZE) {
            $key = Hex::fromHex(Sm3::sm3($key));
            assert(strlen($key) <= self::BLOCK_SIZE, 'SM3 hash output must fit within HMAC block size');
        }
        $key = str_pad($key, self::BLOCK_SIZE, "\0");

        $innerPad = $key ^ str_repeat(chr(0x36), self::BLOCK_SIZE);
        $outerPad = $key ^ str_repeat(chr(0x5C), self::BLOCK_SIZE);
        $hasher = new Sm3();
        $hasher->update($innerPad);
        $this->handle = new \stdClass();
        self::states()[$this->handle] = ['innerPad' => $innerPad, 'outerPad' => $outerPad, 'hasher' => $hasher];
    }

    /**
     * Feed data into the streaming HMAC computation.
     *
     * @param  string $data Data chunk to process
     * @return self   This instance for method chaining
     */
    public function update(string $data): self
    {
        $this->state()['hasher']->update($data);
        return $this;
    }

    public function __clone()
    {
        $state = $this->state();
        $state['hasher'] = clone $state['hasher'];
        $this->handle = new \stdClass();
        self::states()[$this->handle] = $state;
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['key' => '***REDACTED***', 'state' => '***REDACTED***'];
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new \LogicException('HMAC-SM3 contexts cannot be serialized');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('HMAC-SM3 contexts cannot be unserialized');
    }

    /**
     * Finalize the streaming HMAC and return the result.
     *
     * After finalization, the instance is reset to its initial state (with the
     * same key), allowing additional data to be fed and finalized again.
     * This is useful for computing multiple HMACs with the same key without
     * creating a new instance.
     *
     * @return string 64-character hex string (256-bit HMAC)
     */
    public function finalize(): string
    {
        $state = $this->state();
        $innerResult = $state['hasher']->finalize();

        // Reset inner hasher for potential reuse
        $state['hasher'] = new Sm3();
        $state['hasher']->update($state['innerPad']);
        self::states()[$this->handle] = $state;

        // Outer hash uses one-shot Sm3::sm3() which also leverages OpenSSL
        return Sm3::sm3($state['outerPad'] . Hex::fromHex($innerResult));
    }
}
