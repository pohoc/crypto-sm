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
    private string $iv = '';

    public function getPadding(): string
    {
        return $this->padding;
    }

    public function setPadding(string $padding): self
    {
        if (!in_array($padding, ['pkcs5', 'none'], true)) {
            throw new InvalidKeyException('Padding must be "pkcs5" or "none"');
        }
        $this->padding = $padding;
        return $this;
    }

    public function getMode(): string
    {
        return $this->mode;
    }

    public function setMode(string $mode): self
    {
        $mode = strtolower($mode);
        if (!in_array($mode, [Sm4::MODE_ECB, Sm4::MODE_CBC], true)) {
            throw new InvalidKeyException('Mode must be Sm4::MODE_ECB or Sm4::MODE_CBC');
        }
        $this->mode = $mode;
        return $this;
    }

    public function getIv(): string
    {
        return $this->iv;
    }

    public function setIv(string $iv): self
    {
        $this->iv = $iv;
        return $this;
    }
}
