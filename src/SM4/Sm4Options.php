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
     * WARNING: "zero" padding cannot preserve trailing null bytes in data.
     * If your data may end with \0 bytes, use "pkcs5" or "pkcs7" instead.
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
        if ($mode === Sm4::MODE_ECB) {
            @trigger_error('SM4 ECB mode is not recommended — it does not provide data confidentiality for repeated patterns. Use CBC or GCM instead.', E_USER_DEPRECATED);
        }
        $this->mode = $mode;
        $this->iv = null;
        return $this;
    }

    /**
     * Get the initialization vector (IV) as hex string.
     * Lazily generates a random IV for modes that require it if not explicitly set.
     *
     * IMPORTANT: The auto-generated IV is cached within this instance only.
     * For decryption, you MUST explicitly set the same IV that was used during
     * encryption by calling setIv(). Creating a new Sm4Options instance will
     * generate a different random IV, causing decryption to fail.
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
        if ($iv !== '' && !preg_match('/^[0-9a-fA-F]+$/', $iv)) {
            throw new InvalidKeyException('IV must be a valid hex string');
        }
        if ($iv !== '' && strlen($iv) % 2 !== 0) {
            throw new InvalidKeyException('IV must have even length (complete bytes)');
        }
        if ($iv !== '' && $this->mode !== Sm4::MODE_GCM && strlen($iv) !== 32) {
            throw new InvalidKeyException('IV must be 32 hex chars (16 bytes) for ' . strtoupper($this->mode) . ' mode');
        }
        if ($iv !== '' && $this->mode === Sm4::MODE_GCM && strlen($iv) < 24) {
            throw new InvalidKeyException('IV must be at least 24 hex chars (12 bytes) for GCM mode');
        }
        if ($iv === '' && $this->mode === Sm4::MODE_GCM) {
            throw new InvalidKeyException('IV is required for GCM mode');
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
