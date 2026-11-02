<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Atomically pins each SM4 key fingerprint to exactly one cipher mode.
 *
 * Implementations must persist claims across every process and restart that
 * can use the same key. Repeated claims for the same mode must succeed.
 */
interface Sm4KeyModeTrackerInterface
{
    /**
     * Claim the one permitted SM4 mode for a key.
     *
     * @param  string $keyFingerprint Raw 32-byte SHA-256 fingerprint of the SM4 key
     * @param  string $mode           One of the SM4 modes or `raw-block`
     * @return bool   True if this key is unclaimed or already pinned to this mode
     */
    public function claimMode(string $keyFingerprint, string $mode): bool;

    /**
     * Check that a key is already registered for a mode without changing the
     * registry. Decryption must use this read-only operation because its input
     * may be unauthenticated and must not be able to pin a key to a mode.
     * An unregistered key must return false.
     *
     * @return bool True only when the existing registration matches this mode
     */
    public function isModeAllowed(string $keyFingerprint, string $mode): bool;
}
