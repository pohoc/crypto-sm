<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

use CryptoSm\Crypto\Gcm;
use CryptoSm\Exception\InvalidKeyException;

/**
 * Options for SM4 encryption/decryption operations.
 */
class Sm4Options
{
    private string $padding = 'pkcs5';
    private string $mode = Sm4::MODE_GCM;
    private ?string $iv = null;

    private bool $ivExplicitlySet = false;

    private bool $generatedIvUsedForEncryption = false;

    /** @var string Additional Authenticated Data for GCM mode */
    private string $aad = '';

    /** @var int Authentication tag length in bytes for GCM mode (default 16) */
    private int $tagLength = 16;

    public function __construct()
    {
        // IV is lazily initialized on first access for the selected mode.
    }

    public function __clone()
    {
        // A generated nonce is owned by one options instance. Copying it to a
        // clone before first use would let both instances encrypt under the
        // same key/IV pair while each still considers the nonce unused.
        if (!$this->ivExplicitlySet) {
            $this->iv = null;
            $this->generatedIvUsedForEncryption = false;
        }
    }

    /**
     * Prevent copying generated-IV ownership state through PHP serialization.
     *
     * @return array<string, never>
     */
    public function __serialize(): array
    {
        throw new \LogicException('SM4 options cannot be serialized because generated IV state must remain instance-local');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('SM4 options cannot be unserialized because generated IV state must remain instance-local');
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
     * Set the padding mode.
     *
     * Padding modes: "pkcs5" (default), "pkcs7", "zero" (deprecated, ambiguous
     * for plaintext ending in null bytes), "iso10126" (deprecated, withdrawn by
     * ISO 2007 and unverifiable on decryption), "ansix923", or "none"
     *
     * @param  string              $padding Padding mode
     * @return self
     * @throws InvalidKeyException If padding value is invalid
     */
    public function setPadding(string $padding): self
    {
        $valid = ['pkcs5', 'pkcs7', 'zero', 'iso10126', 'ansix923', 'none'];
        if (!in_array($padding, $valid, true)) {
            throw new InvalidKeyException('Padding must be one of: ' . implode(', ', $valid));
        }
        if ($padding === 'zero') {
            @trigger_error('SM4 zero padding is ambiguous for plaintext ending in null bytes. Use pkcs5/pkcs7 or an authenticated mode such as GCM instead.', E_USER_DEPRECATED);
        }
        if ($padding === 'iso10126') {
            // ISO 10126 已于 2007 年被 ISO 撤销；填充随机字节无法在解密侧校验，
            // 计划在未来大版本移除
            @trigger_error('SM4 ISO 10126 padding cannot be verified on decryption and has been withdrawn by ISO. Use pkcs5/pkcs7 or an authenticated mode such as GCM instead.', E_USER_DEPRECATED);
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
     * Setting the SAME mode again is a no-op and preserves any cached IV.
     * Changing to a DIFFERENT mode resets the IV because IV length rules
     * differ between modes (see setIv()).
     *
     * @param  string              $mode Cipher mode: Sm4::MODE_ECB, Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR, or Sm4::MODE_GCM
     * @return self
     * @throws InvalidKeyException If mode value is invalid
     */
    public function setMode(string $mode): self
    {
        $mode = strtolower($mode);
        if ($mode === $this->mode) {
            return $this;
        }
        $valid = [Sm4::MODE_ECB, Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR, Sm4::MODE_GCM];
        if (!in_array($mode, $valid, true)) {
            throw new InvalidKeyException('Mode must be one of: ' . implode(', ', $valid));
        }
        if ($mode === Sm4::MODE_ECB) {
            @trigger_error('SM4 ECB mode is not recommended — it does not provide data confidentiality for repeated patterns. Use CBC or GCM instead.', E_USER_DEPRECATED);
        }
        $this->mode = $mode;
        $this->resetIv();
        return $this;
    }

    /**
     * Get the initialization vector (IV) as hex string.
     * Lazily generates a random IV for modes that require it if not explicitly set.
     *
     * Automatically generated IVs are refreshed when an options instance is
     * reused for encryption. Explicit IVs remain fixed. Their security
     * requirements depend on the mode: CBC/CFB require unpredictable IVs for
     * each encryption; OFB requires a unique IV; CTR requires that no counter
     * block repeat under the same key. The caller is responsible for these
     * requirements when supplying an IV explicitly. For decryption, you MUST
     * explicitly set the same IV that was used during encryption.
     * Automatically generated GCM IVs use the reserved 16-byte SM4R namespace.
     *
     * @return string 32-character hex string (128 bits) for ECB/CBC/CFB/OFB/CTR, or variable-length hex for GCM
     */
    public function getIv(): string
    {
        if ($this->iv === null) {
            $this->iv = $this->mode === Sm4::MODE_GCM
                ? bin2hex('SM4R' . random_bytes(12))
                : bin2hex(random_bytes(16));
        }
        return $this->iv;
    }

    /**
     * Whether an IV is already available (explicitly set or previously materialized).
     *
     * Unlike getIv(), this never generates a random IV. Decryption MUST have a
     * concrete IV: silently generating one would produce garbage plaintext, so
     * Sm4::decrypt() rejects options whose IV has not been set.
     */
    public function hasIv(): bool
    {
        return $this->iv !== null;
    }

    /** Whether the current IV was supplied by the caller rather than generated. */
    public function hasExplicitIv(): bool
    {
        return $this->ivExplicitlySet;
    }

    /**
     * Reset the cached IV so that the next getIv() call generates a fresh random IV.
     *
     * Call this when you need a new IV before an encryption. SM4 refreshes
     * automatically generated IVs after their first use, but never changes an
     * explicitly supplied IV.
     *
     * @return self
     */
    public function resetIv(): self
    {
        $this->iv = null;
        $this->ivExplicitlySet = false;
        $this->generatedIvUsedForEncryption = false;
        return $this;
    }

    /** Refresh an automatically generated IV after its first encryption use. */
    public function prepareIvForEncryption(): void
    {
        if (!$this->ivExplicitlySet && $this->generatedIvUsedForEncryption) {
            $this->resetIv();
        }
    }

    /** Reserve the current automatically generated IV against accidental reuse. */
    public function markIvUsedForEncryption(): void
    {
        if (!$this->ivExplicitlySet) {
            $this->generatedIvUsedForEncryption = true;
        }
    }

    /** @internal Materialize and consume a reserved random GCM IV for one encryption. */
    public function consumeGeneratedGcmIvForEncryption(): string
    {
        if ($this->mode !== Sm4::MODE_GCM || $this->ivExplicitlySet) {
            throw new InvalidKeyException('Only an automatically generated GCM IV can be consumed');
        }
        if ($this->generatedIvUsedForEncryption) {
            $this->resetIv();
        }

        $iv = $this->getIv();
        if (!preg_match('/\A534d3452[0-9a-fA-F]{24}\z/i', $iv)) {
            throw new InvalidKeyException('Generated GCM IV must use the reserved 16-byte format');
        }
        $this->generatedIvUsedForEncryption = true;

        $ivBin = hex2bin($iv);
        if ($ivBin === false) {
            throw new InvalidKeyException('Invalid generated GCM IV');
        }
        return $ivBin;
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
        if ($iv !== '' && !preg_match('/\A[0-9a-fA-F]+\z/', $iv)) {
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
        $this->ivExplicitlySet = $iv !== '';
        $this->generatedIvUsedForEncryption = false;
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
     * @param  int                 $tagLength Tag length in bytes (12, 13, 14, 15, or 16; default 16)
     * @return self
     * @throws InvalidKeyException If tag length is invalid
     */
    public function setTagLength(int $tagLength): self
    {
        if (!in_array($tagLength, Gcm::VALID_TAG_LENGTHS, true)) {
            throw new InvalidKeyException('GCM tag length must be one of: ' . implode(', ', Gcm::VALID_TAG_LENGTHS));
        }
        $this->tagLength = $tagLength;
        return $this;
    }
}
