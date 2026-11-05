<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically reserves SM4-CTR counter ranges for shared-key deployments.
 *
 * Implementations must coordinate every process using the same key and reject
 * any range that intersects a range already claimed for that key.
 */
interface Sm4CtrCounterTrackerInterface
{
    /**
     * Atomically reserve a contiguous range of 128-bit big-endian counters.
     *
     * @param  string $key            Raw 16-byte SM4 key
     * @param  string $initialCounter Raw 16-byte first counter block
     * @param  int    $blockCount     Number of counter blocks consumed (always > 0)
     * @return bool   True if no counter block in this range has previously been claimed
     */
    public function claimRange(string $key, string $initialCounter, int $blockCount): bool;
}
