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
        if (strlen($key) > self::BLOCK_SIZE) {
            $key = Hex::fromHex(Sm3::sm3($key));
            assert(strlen($key) <= self::BLOCK_SIZE, 'SM3 hash output must fit within HMAC block size');
        }

        $key = str_pad($key, self::BLOCK_SIZE, "\0");

        $iKeyPad = $key ^ str_repeat(chr(0x36), self::BLOCK_SIZE);
        $oKeyPad = $key ^ str_repeat(chr(0x5C), self::BLOCK_SIZE);

        $innerHash = Sm3::sm3($iKeyPad . $data);
        return Sm3::sm3($oKeyPad . Hex::fromHex($innerHash));
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

    private string $iKeyPad;
    private string $oKeyPad;
    private Sm3 $innerHasher;

    private function __construct(string $key)
    {
        if (strlen($key) > self::BLOCK_SIZE) {
            $key = Hex::fromHex(Sm3::sm3($key));
            assert(strlen($key) <= self::BLOCK_SIZE, 'SM3 hash output must fit within HMAC block size');
        }
        $key = str_pad($key, self::BLOCK_SIZE, "\0");

        $this->iKeyPad = $key ^ str_repeat(chr(0x36), self::BLOCK_SIZE);
        $this->oKeyPad = $key ^ str_repeat(chr(0x5C), self::BLOCK_SIZE);

        $this->innerHasher = new Sm3();
        $this->innerHasher->update($this->iKeyPad);
    }

    /**
     * Feed data into the streaming HMAC computation.
     *
     * @param  string $data Data chunk to process
     * @return self   This instance for method chaining
     */
    public function update(string $data): self
    {
        $this->innerHasher->update($data);
        return $this;
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
        $innerResult = $this->innerHasher->finalize();

        // Reset inner hasher for potential reuse
        $this->innerHasher = new Sm3();
        $this->innerHasher->update($this->iKeyPad);

        // Outer hash uses one-shot Sm3::sm3() which also leverages OpenSSL
        return Sm3::sm3($this->oKeyPad . Hex::fromHex($innerResult));
    }
}
