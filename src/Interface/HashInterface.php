<?php

declare(strict_types=1);

namespace CryptoSm\Interface;

/**
 * Interface for hash algorithm implementations.
 */
interface HashInterface
{
    /**
     * Compute the hash of the given data.
     *
     * @param  string $data Input data
     * @return string Hash value as hex string
     */
    public function hash(string $data): string;
}
