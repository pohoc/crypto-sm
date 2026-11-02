<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically claim the fixed authentication-tag length for an SM4-GCM key.
 * Implementations used by multi-process applications must share state across
 * every process that encrypts or decrypts with the same key.
 */
interface GcmTagLengthTrackerInterface
{
    /**
     * @param  string $key       Raw 16-byte SM4 key
     * @param  int    $tagLength Tag length in bytes
     * @return bool   True when this length matches the key's existing profile or initializes it
     */
    public function claimTagLength(string $key, int $tagLength): bool;
}
