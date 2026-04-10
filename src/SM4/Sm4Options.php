<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

use CryptoSm\Exception\InvalidKeyException;

/**
 * Options for SM4 encryption/decryption operations.
 */
class Sm4Options
{
    private string $padding = 'pkcs5';
    private string $mode = 'cbc';
    private ?string $iv = null;

    public function __construct()
    {
        // IV is lazily initialized on first access for CBC mode
    }

    /**
     * Get the padding mode.
     *
     * @return string Current padding mode ("pkcs5" or "none")
     */
    public function getPadding(): string
    {
        return $this->padding;
    }

    /**
     * Set the padding mode.
     *
     * @param  string              $padding Padding mode: "pkcs5" (default) or "none"
     * @return self
     * @throws InvalidKeyException If padding value is invalid
     */
    public function setPadding(string $padding): self
    {
        if (!in_array($padding, ['pkcs5', 'none'], true)) {
            throw new InvalidKeyException('Padding must be "pkcs5" or "none"');
        }
        $this->padding = $padding;
        return $this;
    }

    /**
     * Get the cipher mode.
     *
     * @return string Current cipher mode ("ecb" or "cbc")
     */
    public function getMode(): string
    {
        return $this->mode;
    }

    /**
     * Set the cipher mode.
     *
     * @param  string              $mode Cipher mode: Sm4::MODE_ECB or Sm4::MODE_CBC
     * @return self
     * @throws InvalidKeyException If mode value is invalid
     */
    public function setMode(string $mode): self
    {
        $mode = strtolower($mode);
        if (!in_array($mode, [Sm4::MODE_ECB, Sm4::MODE_CBC], true)) {
            throw new InvalidKeyException('Mode must be Sm4::MODE_ECB or Sm4::MODE_CBC');
        }
        $this->mode = $mode;
        return $this;
    }

    /**
     * Get the initialization vector (IV) as hex string.
     * Lazily generates a random IV for CBC mode if not explicitly set.
     *
     * @return string 32-character hex string (128 bits)
     */
    public function getIv(): string
    {
        if ($this->iv === null) {
            $this->iv = bin2hex(random_bytes(16));
        }
        return $this->iv;
    }

    /**
     * Set the initialization vector (IV).
     *
     * @param  string              $iv 32-character hex string (128 bits)
     * @return self
     * @throws InvalidKeyException If IV format is invalid
     */
    public function setIv(string $iv): self
    {
        if (!preg_match('/^[0-9a-fA-F]{32}$/', $iv)) {
            throw new InvalidKeyException('IV must be 128 bits (32 hex chars)');
        }
        $this->iv = $iv;
        return $this;
    }
}
