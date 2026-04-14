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

    /** @var string Additional Authenticated Data for GCM mode */
    private string $aad = '';

    /** @var int Authentication tag length in bytes for GCM mode (default 16) */
    private int $tagLength = 16;

    public function __construct()
    {
        // IV is lazily initialized on first access for CBC mode
    }

    /**
     * Get the padding mode.
     *
     * @return string Current padding mode
     */
    public function getPadding(): string
    {
        return $this->padding;
    }

    /**
     * Set the padding mode.
     *
     * @param  string              $padding Padding mode: "pkcs5" (default), "pkcs7", "zero", "iso10126", "ansix923", or "none"
     * @return self
     * @throws InvalidKeyException If padding value is invalid
     */
    public function setPadding(string $padding): self
    {
        $valid = ['pkcs5', 'pkcs7', 'zero', 'iso10126', 'ansix923', 'none'];
        if (!in_array($padding, $valid, true)) {
            throw new InvalidKeyException('Padding must be one of: ' . implode(', ', $valid));
        }
        $this->padding = $padding;
        return $this;
    }

    /**
     * Get the cipher mode.
     *
     * @return string Current cipher mode
     */
    public function getMode(): string
    {
        return $this->mode;
    }

    /**
     * Set the cipher mode.
     *
     * @param  string              $mode Cipher mode: Sm4::MODE_ECB, Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR, or Sm4::MODE_GCM
     * @return self
     * @throws InvalidKeyException If mode value is invalid
     */
    public function setMode(string $mode): self
    {
        $mode = strtolower($mode);
        $valid = [Sm4::MODE_ECB, Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR, Sm4::MODE_GCM];
        if (!in_array($mode, $valid, true)) {
            throw new InvalidKeyException('Mode must be one of: ' . implode(', ', $valid));
        }
        $this->mode = $mode;
        return $this;
    }

    /**
     * Get the initialization vector (IV) as hex string.
     * Lazily generates a random IV for modes that require it if not explicitly set.
     *
     * @return string 32-character hex string (128 bits) for ECB/CBC/CFB/OFB/CTR, or variable-length hex for GCM
     */
    public function getIv(): string
    {
        if ($this->iv === null) {
            // GCM mode supports variable-length IV (typically 12 bytes = 96 bits)
            if ($this->mode === Sm4::MODE_GCM) {
                $this->iv = bin2hex(random_bytes(12));
            } else {
                $this->iv = bin2hex(random_bytes(16));
            }
        }
        return $this->iv;
    }

    /**
     * Set the initialization vector (IV).
     *
     * @param  string              $iv Hex string (32 chars = 128 bits for most modes, or 24 chars = 96 bits recommended for GCM)
     * @return self
     * @throws InvalidKeyException If IV format is invalid
     */
    public function setIv(string $iv): self
    {
        if ($this->mode === Sm4::MODE_GCM) {
            // GCM allows variable IV length, minimum 1 byte
            if (!preg_match('/^[0-9a-fA-F]+$/', $iv) || strlen($iv) < 2 || strlen($iv) % 2 !== 0) {
                throw new InvalidKeyException('GCM IV must be valid hex with at least 1 byte');
            }
        } else {
            if (!preg_match('/^[0-9a-fA-F]{32}$/', $iv)) {
                throw new InvalidKeyException('IV must be 128 bits (32 hex chars)');
            }
        }
        $this->iv = $iv;
        return $this;
    }

    /**
     * Get the Additional Authenticated Data (AAD) for GCM mode.
     */
    public function getAad(): string
    {
        return $this->aad;
    }

    /**
     * Set the Additional Authenticated Data (AAD) for GCM mode.
     *
     * @param  string $aad AAD binary string
     * @return self
     */
    public function setAad(string $aad): self
    {
        $this->aad = $aad;
        return $this;
    }

    /**
     * Get the authentication tag length in bytes for GCM mode.
     */
    public function getTagLength(): int
    {
        return $this->tagLength;
    }

    /**
     * Set the authentication tag length for GCM mode.
     *
     * @param  int                 $tagLength Tag length in bytes (4, 8, 12, 13, 14, 15, or 16; default 16)
     * @return self
     * @throws InvalidKeyException If tag length is invalid
     */
    public function setTagLength(int $tagLength): self
    {
        $valid = [4, 8, 12, 13, 14, 15, 16];
        if (!in_array($tagLength, $valid, true)) {
            throw new InvalidKeyException('GCM tag length must be one of: ' . implode(', ', $valid));
        }
        $this->tagLength = $tagLength;
        return $this;
    }
}
