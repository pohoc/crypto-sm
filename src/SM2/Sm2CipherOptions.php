<?php

declare(strict_types=1);

namespace CryptoSm\SM2;

use CryptoSm\Exception\InvalidKeyException;

/**
 * Options for SM2 encryption/decryption operations.
 */
class Sm2CipherOptions
{
    /** @var int Default cipher mode: C1C3C2 (GB/T 32918.4-2016) */
    private int $cipherMode = 1;

    /** Whether encrypted output includes SEC1's 0x04 uncompressed-point prefix. */
    private bool $includePointPrefix = true;

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
     * C1C3C2 (mode 1) is the output order in GB/T 32918.4-2016.
     * C1C2C3 (mode 0) is retained for GM/T 0003.4-2012 interoperability.
     *
     * @param  int                 $cipherMode Sm2::CIPHER_MODE_1 or Sm2::CIPHER_MODE_0
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

    /** Whether encryption emits SEC1's 0x04 prefix before the uncompressed C1 point. */
    public function getIncludePointPrefix(): bool
    {
        return $this->includePointPrefix;
    }

    /**
     * Select whether encrypted output includes the standard SEC1 0x04 point prefix.
     * Disable only for interoperability with existing consumers that expect raw x||y.
     */
    public function setIncludePointPrefix(bool $include): self
    {
        $this->includePointPrefix = $include;
        return $this;
    }
}
