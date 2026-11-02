<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically claims an SM4-GCM key/IV pair for applications using shared state.
 *
 * Implementations must coordinate every process that encrypts under the same
 * key. To enforce NIST SP 800-38D §8.3 across workers and restarts, they must
 * also reject claims after 2^32 total GCM encryptions for that key, regardless
 * of IV length. Applications must use one fixed tag length for each key across
 * all processes, as required by NIST SP 800-38D; this interface only coordinates
 * IV claims. Inputs are decoded binary strings, not hex text.
 */
interface GcmIvTrackerInterface
{
    /**
     * Claim a key/IV pair before encryption.
     *
     * @param  string $key 16-byte binary SM4 key
     * @param  string $iv  GCM IV bytes
     * @return bool   True when the pair is new and the per-key invocation limit
     *                has not been reached; false for reuse or an exhausted key
     */
    public function claim(string $key, string $iv): bool;
}
