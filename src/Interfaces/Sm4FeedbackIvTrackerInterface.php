<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically claims SM4-CBC/CFB/OFB key and IV pairs for shared-key deployments.
 *
 * Implementations must share claims across every process using the same key.
 * Claims are mode-independent. CBC requires a fresh unpredictable IV; CFB and
 * OFB both begin by encrypting the IV, so reusing their pair repeats keystream.
 */
interface Sm4FeedbackIvTrackerInterface
{
    /**
     * Claim a CBC/CFB/OFB key/IV pair before encryption.
     *
     * @param  string $key Raw 16-byte SM4 key
     * @param  string $iv  Raw 16-byte IV
     * @return bool   True only when this pair has never been claimed
     */
    public function claim(string $key, string $iv): bool;
}
