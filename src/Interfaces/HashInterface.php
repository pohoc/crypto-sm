<?php

declare(strict_types=1);

namespace CryptoSm\Interfaces;

/**
 * Interface for hash algorithm implementations.
 */
interface HashInterface
{
    /**
     * Compute the hash of the given data (instance method).
     *
     * @param  string $data Input data
     * @return string Hash value as hex string
     */
    public function hash(string $data): string;

    /**
     * Compute the hash of the given data (static method).
     *
     * @param  string $data Input data
     * @return string Hash value as hex string
     */
    public static function hashStatic(string $data): string;
}
