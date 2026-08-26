<?php

declare(strict_types=1);

namespace CryptoSm\Crypto;

/**
 * @deprecated Use CryptoSm\Crypto\Gcm instead. This class will be removed in a future major release.
 */
class GcmPure extends Gcm
{
    public function __construct(string $keyBin)
    {
        @trigger_error('CryptoSm\Crypto\GcmPure is deprecated and will be removed in a future major release. Use CryptoSm\Crypto\Gcm instead.', E_USER_DEPRECATED);
        parent::__construct($keyBin);
    }
}
