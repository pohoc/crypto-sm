<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically reserves known SM4 block-cipher input ranges.
 *
 * Implementations must coordinate every process and mode using the same key.
 * CTR inputs form a contiguous range and can be reserved in full. CFB/OFB
 * callers reserve each feedback input as a one-block range before encryption.
 * Use distinct keys across SM4 modes when their operations may be
 * attacker-influenced; this interface does not coordinate GCM's counter inputs
 * or block-mode inputs.
 */
interface Sm4StreamBlockTrackerInterface
{
    /**
     * Atomically reserve contiguous 128-bit big-endian block-cipher inputs.
     *
     * @param  string $key        Raw 16-byte SM4 key
     * @param  string $firstBlock Raw 16-byte first input block
     * @param  int    $blockCount Number of blocks reserved (always > 0)
     * @return bool   True if no input block in this range has previously been claimed
     */
    public function claimRange(string $key, string $firstBlock, int $blockCount): bool;
}
