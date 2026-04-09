<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Exception\InvalidKeyException;

/**
 * Options for SM2 encryption/decryption operations.
 */
class Sm2CipherOptions
{
    /** @var int Default cipher mode: C1C3C2 (recommended per GM/T 0003-2012) */
    private int $cipherMode = 1;

    /**
     * Get the cipher output mode.
     *
     * @return int Sm2::CIPHER_MODE_1 (C1C3C2) or Sm2::CIPHER_MODE_0 (C1C2C3)
     */
    public function getCipherMode(): int
    {
        return $this->cipherMode;
    }

    /**
     * Set the cipher output mode.
     *
     * C1C3C2 (mode 1) is recommended per GM/T 0003-2012.
     * C1C2C3 (mode 0) is the older format, kept for backward compatibility.
     *
     * @param int $cipherMode Sm2::CIPHER_MODE_1 or Sm2::CIPHER_MODE_0
     * @return self
     * @throws InvalidKeyException If cipher mode is invalid
     */
    public function setCipherMode(int $cipherMode): self
    {
        if ($cipherMode !== Sm2::CIPHER_MODE_0 && $cipherMode !== Sm2::CIPHER_MODE_1) {
            throw new InvalidKeyException('Cipher mode must be Sm2::CIPHER_MODE_0 or Sm2::CIPHER_MODE_1');
        }
        $this->cipherMode = $cipherMode;
        return $this;
    }
}
