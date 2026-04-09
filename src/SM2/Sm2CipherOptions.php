<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Exception\InvalidKeyException;

/**
 * Options for SM2 encryption/decryption operations.
 */
class Sm2CipherOptions
{
    private int $cipherMode = 1;

    public function getCipherMode(): int
    {
        return $this->cipherMode;
    }

    public function setCipherMode(int $cipherMode): self
    {
        if ($cipherMode !== Sm2::CIPHER_MODE_0 && $cipherMode !== Sm2::CIPHER_MODE_1) {
            throw new InvalidKeyException('Cipher mode must be Sm2::CIPHER_MODE_0 or Sm2::CIPHER_MODE_1');
        }
        $this->cipherMode = $cipherMode;
        return $this;
    }
}
