<?php

declare(strict_types=1);

namespace CryptoSm\Utils;

/** Prevent accidental disclosure of sensitive cryptographic contexts. */
trait SensitiveContext
{
    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['state' => '***REDACTED***'];
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new \LogicException('Cipher contexts cannot be serialized');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('Cipher contexts cannot be unserialized');
    }
}
