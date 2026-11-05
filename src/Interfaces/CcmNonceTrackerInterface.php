<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically claim an SM4-CCM key/nonce pair before encryption.
 * Implementations used by multi-process applications must share state across
 * every process that encrypts with the same key. Applications must also use
 * one fixed CCM tag length for each key across all processes, as required by
 * NIST SP 800-38C; this interface only coordinates nonce claims. Configure a
 * shared CcmTagLengthTrackerInterface to enforce that profile across workers.
 */
interface CcmNonceTrackerInterface
{
    /**
     * @param  string $key   Raw 16-byte SM4 key
     * @param  string $nonce Raw CCM nonce
     * @return bool   True only when this key/nonce pair has never been claimed
     */
    public function claim(string $key, string $nonce): bool;
}
