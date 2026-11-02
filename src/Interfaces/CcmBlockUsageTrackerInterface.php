<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically accounts for SM4 block-cipher invocations used by CCM.
 *
 * Implementations must share a durable count across every process and restart
 * that uses the same key, and reject a claim that would exceed 2^61 total
 * block-cipher invocations as required by NIST SP 800-38C §5.1. Count both
 * encryption and decryption work, including failed authentication attempts.
 */
interface CcmBlockUsageTrackerInterface
{
    /**
     * Atomically reserve CCM block-cipher work before performing it.
     *
     * @param  string $key              Raw 16-byte SM4 key
     * @param  int    $blockInvocations Number of SM4 block-cipher calls to reserve
     * @return bool   True if this claim keeps the key below or at the 2^61 limit
     */
    public function claimBlockInvocations(string $key, int $blockInvocations): bool;
}
