<?php

declare(strict_types=1);

namespace CryptoSm;

use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2 as SM2Crypto;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

class SmCrypto
{
    public static function generateKeyPair(): Keypair
    {
        return SM2Crypto::generateKeyPairHex();
    }

    public static function encrypt(string $data, string $publicKey, ?Sm2CipherOptions $options = null): string
    {
        return SM2Crypto::doEncrypt($data, $publicKey, $options);
    }

    public static function decrypt(string $data, string $privateKey, ?Sm2CipherOptions $options = null): string
    {
        return SM2Crypto::doDecrypt($data, $privateKey, $options);
    }

    public static function sign(string $data, string $privateKey, ?SignatureOptions $options = null): string
    {
        return SM2Crypto::doSignature($data, $privateKey, $options);
    }

    public static function verify(string $data, string $signature, string $publicKey, ?SignatureOptions $options = null): bool
    {
        return SM2Crypto::doVerifySignature($data, $signature, $publicKey, $options);
    }

    public static function sm3(string $data): string
    {
        return Sm3::sm3($data);
    }

    public static function sm4Encrypt(string $data, string $key, ?Sm4Options $options = null): string
    {
        return Sm4::encrypt($data, $key, $options);
    }

    public static function sm4Decrypt(string $data, string $key, ?Sm4Options $options = null): string
    {
        return Sm4::decrypt($data, $key, $options);
    }
}
