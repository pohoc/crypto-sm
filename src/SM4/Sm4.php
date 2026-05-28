<?php

declare(strict_types=1);

namespace CryptoSm\SM4;

use CryptoSm\Crypto\Gcm;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Interfaces\CipherInterface;

/**
 * SM4 block cipher implementation (GM/T 0002-2012).
 *
 * Supports ECB, CBC, CFB, OFB, CTR, and GCM modes with configurable padding.
 * CBC mode is the default; ECB is not recommended for new applications.
 * GCM mode provides authenticated encryption with associated data (AEAD).
 */
class Sm4 implements CipherInterface
{
    /**
     * @var string Electronic Codebook mode
     * @deprecated ECB mode does not provide data confidentiality for repeated patterns. Use CBC or GCM instead.
     */
    public const MODE_ECB = 'ecb';

    /** @var string Cipher Block Chaining mode (default, recommended) */
    public const MODE_CBC = 'cbc';

    /** @var string Cipher Feedback mode (stream-like, no padding needed) */
    public const MODE_CFB = 'cfb';

    /** @var string Output Feedback mode (stream-like, no padding needed) */
    public const MODE_OFB = 'ofb';

    /** @var string Counter mode (stream-like, no padding needed) */
    public const MODE_CTR = 'ctr';

    /** @var string Galois/Counter mode (authenticated encryption) */
    public const MODE_GCM = 'gcm';

    /** @var array<int,string> Modes that don't require padding (stream-like) */
    private const STREAM_MODES = [self::MODE_CFB, self::MODE_OFB, self::MODE_CTR, self::MODE_GCM];

    /**
     * Encrypt data using SM4.
     *
     * @param  string              $data    Plaintext data to encrypt
     * @param  string              $key     32-character hex string (128-bit key)
     * @param  mixed               $options Sm4Options instance or null for defaults
     * @return string              Hex-encoded ciphertext; when options are null, returns IV hex + ciphertext hex
     * @throws InvalidKeyException If key or options are invalid
     * @throws CryptoException     If encryption fails
     */
    public static function encrypt(string $data, string $key, mixed $options = null): string
    {
        if ($options !== null && !$options instanceof Sm4Options) {
            throw new InvalidKeyException('SM4 options must be an instance of Sm4Options');
        }
        return self::crypt($data, $key, true, $options, $options === null);
    }

    /**
     * Decrypt data using SM4.
     *
     * @param  string              $data    Hex-encoded ciphertext; when options are null, expects IV hex + ciphertext hex
     * @param  string              $key     32-character hex string (128-bit key)
     * @param  mixed               $options Sm4Options instance or null for defaults
     * @return string              Decrypted plaintext
     * @throws InvalidKeyException If key, ciphertext, or options are invalid
     * @throws CryptoException     If decryption fails
     */
    public static function decrypt(string $data, string $key, mixed $options = null): string
    {
        if ($options !== null && !$options instanceof Sm4Options) {
            throw new InvalidKeyException('SM4 options must be an instance of Sm4Options');
        }
        return self::crypt($data, $key, false, $options, $options === null);
    }

    /**
     * Encrypt data into a structured self-contained payload.
     *
     * This API always generates a fresh IV for IV-based modes and stores the
     * IV/tag metadata beside the ciphertext, preventing the common mistake of
     * losing or reusing IVs when using explicit Sm4Options.
     *
     * @return array{version: int, algorithm: string, mode: string, ciphertext: string, padding?: string, iv?: string, aad?: string, tagLength?: int, tag?: string}
     */
    public static function encryptPayload(string $data, string $key, ?Sm4Options $options = null): array
    {
        $options = $options === null ? new Sm4Options() : clone $options;
        $mode = strtolower($options->getMode());

        if ($mode !== self::MODE_ECB) {
            $options->resetIv();
        }

        $payload = [
            'version' => 1,
            'algorithm' => 'SM4',
            'mode' => $mode,
        ];

        if ($mode === self::MODE_GCM) {
            $encrypted = self::encrypt($data, $key, $options);
            $tagLength = $options->getTagLength();
            $tagHexLength = $tagLength * 2;

            $payload['iv'] = $options->getIv();
            $payload['aad'] = bin2hex($options->getAad());
            $payload['tagLength'] = $tagLength;
            $payload['ciphertext'] = substr($encrypted, 0, -$tagHexLength);
            $payload['tag'] = substr($encrypted, -$tagHexLength);

            return $payload;
        }

        $padding = strtolower($options->getPadding());
        if ($padding === 'zero') {
            throw new InvalidKeyException('Zero padding is ambiguous and is not supported by encryptPayload(); use pkcs5/pkcs7 or the legacy encrypt() API');
        }

        if ($mode !== self::MODE_ECB) {
            $payload['iv'] = $options->getIv();
        }
        $payload['padding'] = $padding;
        $payload['ciphertext'] = self::encrypt($data, $key, $options);

        return $payload;
    }

    /**
     * Decrypt a structured SM4 payload produced by encryptPayload().
     *
     * @param array<string, mixed> $payload
     */
    public static function decryptPayload(array $payload, string $key): string
    {
        $version = self::payloadInt($payload, 'version');
        $algorithm = self::payloadString($payload, 'algorithm');
        $mode = strtolower(self::payloadString($payload, 'mode'));

        if ($version !== 1 || strtoupper($algorithm) !== 'SM4') {
            throw new InvalidKeyException('Unsupported SM4 payload');
        }

        $options = (new Sm4Options())->setMode($mode);

        if ($mode === self::MODE_GCM) {
            $iv = self::payloadString($payload, 'iv');
            self::validatePayloadHex($iv, 'IV', false);
            $options->setIv($iv);

            $tagLength = self::payloadInt($payload, 'tagLength');
            $options->setTagLength($tagLength);

            $aadHex = self::payloadString($payload, 'aad');
            self::validatePayloadHex($aadHex, 'AAD', true);
            $aad = $aadHex === '' ? '' : hex2bin($aadHex);
            if ($aad === false) {
                throw new InvalidKeyException('Invalid SM4 payload AAD hex');
            }
            $options->setAad($aad);

            $ciphertext = self::payloadString($payload, 'ciphertext');
            $tag = self::payloadString($payload, 'tag');
            self::validatePayloadHex($ciphertext, 'ciphertext', true);
            self::validatePayloadHex($tag, 'tag', false);

            return self::decrypt($ciphertext . $tag, $key, $options);
        }

        $validModes = [self::MODE_ECB, self::MODE_CBC, self::MODE_CFB, self::MODE_OFB, self::MODE_CTR];
        if (!in_array($mode, $validModes, true)) {
            throw new InvalidKeyException('Unsupported SM4 payload mode: ' . $mode);
        }

        if ($mode !== self::MODE_ECB) {
            $iv = self::payloadString($payload, 'iv');
            self::validatePayloadHex($iv, 'IV', false);
            $options->setIv($iv);
        }

        $padding = strtolower(self::payloadString($payload, 'padding'));
        if ($padding === 'zero') {
            throw new InvalidKeyException('Zero padding is ambiguous and is not supported by decryptPayload()');
        }
        $options->setPadding($padding);

        $ciphertext = self::payloadString($payload, 'ciphertext');
        self::validatePayloadHex($ciphertext, 'ciphertext', true);

        return self::decrypt($ciphertext, $key, $options);
    }

    /** @var bool|null Cached availability of OpenSSL SM4 cipher support */
    private static ?bool $openSslSm4Available = null;

    /**
     * Check whether the OpenSSL extension provides SM4 cipher support.
     */
    public static function openSslSm4Available(): bool
    {
        if (self::$openSslSm4Available === null) {
            self::$openSslSm4Available = extension_loaded('openssl')
                && in_array('SM4-ECB', openssl_get_cipher_methods(), true);
        }
        return self::$openSslSm4Available;
    }

    private static function crypt(string $data, string $key, bool $encrypt, ?Sm4Options $options = null, bool $selfContainedDefault = false): string
    {
        $options ??= new Sm4Options();
        $mode = strtolower($options->getMode());
        $padding = strtolower($options->getPadding());

        self::validateHexKey($key);

        if ($mode === self::MODE_GCM) {
            return self::cryptGcm($data, $key, $encrypt, $options);
        }

        // Validate mode
        $validModes = [self::MODE_ECB, self::MODE_CBC, self::MODE_CFB, self::MODE_OFB, self::MODE_CTR];
        if (!in_array($mode, $validModes, true)) {
            throw new InvalidKeyException('Unsupported SM4 mode: ' . $mode);
        }

        if ($selfContainedDefault && $mode === self::MODE_CBC && !$encrypt) {
            if (!preg_match('/^[0-9a-fA-F]+$/', $data) || strlen($data) < 64 || strlen($data) % 2 !== 0) {
                throw new InvalidKeyException('Invalid self-contained CBC ciphertext');
            }
            $options->setIv(substr($data, 0, 32));
            $data = substr($data, 32);
        }

        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }

        // Try OpenSSL first, fall back to pure PHP if unavailable
        if (self::openSslSm4Available()) {
            $result = self::cryptOpenSsl($data, $keyBin, $encrypt, $mode, $padding, $options);
        } else {
            $result = self::cryptPurePhp($data, $keyBin, $encrypt, $mode, $padding, $options);
        }

        if ($selfContainedDefault && $mode === self::MODE_CBC && $encrypt) {
            return $options->getIv() . $result;
        }

        return $result;
    }

    /**
     * Encrypt/decrypt using OpenSSL.
     */
    private static function cryptOpenSsl(string $data, string $keyBin, bool $encrypt, string $mode, string $padding, Sm4Options $options): string
    {
        $opensslCipher = self::getOpenSSLMethodName($mode);
        $isStreamMode = in_array($mode, self::STREAM_MODES, true);
        $needsIv = $mode !== self::MODE_ECB;

        $ivBin = '';
        if ($needsIv) {
            $iv = $options->getIv();
            self::validateHexKey($iv, 'IV');
            $ivBin = hex2bin($iv);
            if ($ivBin === false) {
                throw new InvalidKeyException('Invalid IV hex');
            }
        }

        if ($encrypt) {
            $input = $isStreamMode ? $data : self::maybePad($data, $padding);
            $cipher = openssl_encrypt(
                $input,
                $opensslCipher,
                $keyBin,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $needsIv ? $ivBin : ''
            );
            if ($cipher === false) {
                throw new CryptoException('SM4 encryption failed: ' . openssl_error_string());
            }
            return bin2hex($cipher);
        }

        // Decrypt
        if (($data !== '' && !preg_match('/^[0-9a-fA-F]+$/', $data)) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = $data === '' ? '' : hex2bin($data);
        if ($cipher === false) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        if (!$isStreamMode && strlen($cipher) % 16 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length not multiple of block size');
        }

        $plain = openssl_decrypt(
            $cipher,
            $opensslCipher,
            $keyBin,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $needsIv ? $ivBin : ''
        );
        if ($plain === false) {
            throw new CryptoException('SM4 decryption failed: ' . openssl_error_string());
        }

        return $isStreamMode ? $plain : self::maybeUnpad($plain, $padding);
    }

    /**
     * Encrypt/decrypt ECB using the pure PHP SM4 block engine.
     */
    private static function cryptEcbPurePhp(string $data, string $keyBin, bool $encrypt, string $padding): string
    {
        $engine = new Sm4PurePhp();
        $engine->setKey($keyBin);

        if ($encrypt) {
            $input = self::maybePad($data, $padding);
            $result = '';
            for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
                $result .= $engine->encryptBlock(substr($input, $i, 16));
            }
            return bin2hex($result);
        }

        // Decrypt
        if (!preg_match('/^[0-9a-fA-F]+$/', $data) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = hex2bin($data);
        if ($cipher === false) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        if (strlen($cipher) % 16 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length not multiple of block size');
        }

        $result = '';
        for ($i = 0, $len = strlen($cipher); $i < $len; $i += 16) {
            $result .= $engine->decryptBlock(substr($cipher, $i, 16));
        }

        return self::maybeUnpad($result, $padding);
    }

    private static function cryptPurePhp(string $data, string $keyBin, bool $encrypt, string $mode, string $padding, Sm4Options $options): string
    {
        if ($mode === self::MODE_ECB) {
            return self::cryptEcbPurePhp($data, $keyBin, $encrypt, $padding);
        }

        $iv = $options->getIv();
        self::validateHexKey($iv, 'IV');
        $ivBin = hex2bin($iv);
        if ($ivBin === false) {
            throw new InvalidKeyException('Invalid IV hex');
        }

        $engine = new Sm4PurePhp();
        $engine->setKey($keyBin);

        return match ($mode) {
            self::MODE_CBC => self::cryptCbcPurePhp($engine, $data, $encrypt, $padding, $ivBin),
            self::MODE_CFB => self::cryptCfbPurePhp($engine, $data, $encrypt, $ivBin),
            self::MODE_OFB => self::cryptOfbPurePhp($engine, $data, $encrypt, $ivBin),
            self::MODE_CTR => self::cryptCtrPurePhp($engine, $data, $encrypt, $ivBin),
            default => throw new InvalidKeyException('Unsupported SM4 mode: ' . $mode),
        };
    }

    private static function cryptCbcPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $padding, string $ivBin): string
    {
        if ($encrypt) {
            $input = self::maybePad($data, $padding);
            $result = '';
            $previous = $ivBin;
            for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
                $block = substr($input, $i, 16) ^ $previous;
                $previous = $engine->encryptBlock($block);
                $result .= $previous;
            }
            return bin2hex($result);
        }

        $cipher = self::decodeBlockCiphertext($data);
        $result = '';
        $previous = $ivBin;
        for ($i = 0, $len = strlen($cipher); $i < $len; $i += 16) {
            $block = substr($cipher, $i, 16);
            $result .= $engine->decryptBlock($block) ^ $previous;
            $previous = $block;
        }

        return self::maybeUnpad($result, $padding);
    }

    private static function cryptCfbPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $ivBin): string
    {
        $input = $encrypt ? $data : self::decodeStreamCiphertext($data);
        $result = '';
        $feedback = $ivBin;
        for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
            $chunk = substr($input, $i, 16);
            $keyStream = $engine->encryptBlock($feedback);
            $out = $chunk ^ substr($keyStream, 0, strlen($chunk));
            $result .= $out;
            $feedback = $encrypt
                ? str_pad($out, 16, "\0")
                : str_pad($chunk, 16, "\0");
        }

        return $encrypt ? bin2hex($result) : $result;
    }

    private static function cryptOfbPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $ivBin): string
    {
        $input = $encrypt ? $data : self::decodeStreamCiphertext($data);
        $result = '';
        $feedback = $ivBin;
        for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
            $feedback = $engine->encryptBlock($feedback);
            $chunk = substr($input, $i, 16);
            $result .= $chunk ^ substr($feedback, 0, strlen($chunk));
        }

        return $encrypt ? bin2hex($result) : $result;
    }

    private static function cryptCtrPurePhp(Sm4PurePhp $engine, string $data, bool $encrypt, string $ivBin): string
    {
        $input = $encrypt ? $data : self::decodeStreamCiphertext($data);
        $result = '';
        $counter = $ivBin;
        for ($i = 0, $len = strlen($input); $i < $len; $i += 16) {
            $keyStream = $engine->encryptBlock($counter);
            $chunk = substr($input, $i, 16);
            $result .= $chunk ^ substr($keyStream, 0, strlen($chunk));
            $counter = self::incrementCounter($counter);
        }

        return $encrypt ? bin2hex($result) : $result;
    }

    private static function decodeBlockCiphertext(string $data): string
    {
        $cipher = self::decodeStreamCiphertext($data);
        if (strlen($cipher) % 16 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext: length not multiple of block size');
        }
        return $cipher;
    }

    private static function decodeStreamCiphertext(string $data): string
    {
        if ($data === '') {
            return '';
        }
        if (!preg_match('/^[0-9a-fA-F]+$/', $data) || strlen($data) % 2 !== 0) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        $cipher = hex2bin($data);
        if ($cipher === false) {
            throw new InvalidKeyException('Invalid ciphertext hex');
        }
        return $cipher;
    }

    private static function incrementCounter(string $counter): string
    {
        $c = $counter;
        for ($i = 15; $i >= 0; $i--) {
            $byte = ord($c[$i]) + 1;
            $c[$i] = chr($byte & 0xFF);
            if ($byte <= 0xFF) {
                break;
            }
        }
        return $c;
    }

    /** @var array<string, Gcm> Cached GCM instances keyed by hex key */
    private static array $gcmCache = [];

    public static function warmupGcm(string $key): void
    {
        self::validateHexKey($key);
        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }
        if (!isset(self::$gcmCache[$key])) {
            if (count(self::$gcmCache) > 8) {
                array_shift(self::$gcmCache);
            }
            self::$gcmCache[$key] = Gcm::fromKey($keyBin);
        }
        self::$gcmCache[$key]->warmup();
    }

    private static function cryptGcm(string $data, string $key, bool $encrypt, Sm4Options $options): string
    {
        $iv = $options->getIv();
        if (!preg_match('/^[0-9a-fA-F]+$/', $iv) || strlen($iv) < 2 || strlen($iv) % 2 !== 0) {
            throw new InvalidKeyException('GCM mode requires a valid IV (at least 1 byte)');
        }
        $ivBin = hex2bin($iv);
        if ($ivBin === false) {
            throw new InvalidKeyException('Invalid GCM IV hex');
        }

        self::validateHexKey($key);
        $keyBin = hex2bin($key);
        if ($keyBin === false) {
            throw new InvalidKeyException('Invalid key hex');
        }

        if (!isset(self::$gcmCache[$key])) {
            if (count(self::$gcmCache) > 8) {
                array_shift(self::$gcmCache);
            }
            self::$gcmCache[$key] = Gcm::fromKey($keyBin);
        }
        $gcm = self::$gcmCache[$key];

        $aad = $options->getAad();
        $tagLength = $options->getTagLength();

        if ($encrypt) {
            $result = $gcm->encrypt($data, $ivBin, $aad, $tagLength);
            return bin2hex($result['ciphertext']) . bin2hex($result['tag']);
        }

        if (strlen($data) < $tagLength * 2 || strlen($data) % 2 !== 0) {
            throw new CryptoException('Invalid GCM ciphertext or tag length');
        }

        $tagHex = substr($data, -$tagLength * 2);
        $cipherHex = substr($data, 0, -$tagLength * 2);

        if (($cipherHex !== '' && !preg_match('/^[0-9a-fA-F]+$/', $cipherHex)) || strlen($cipherHex) % 2 !== 0) {
            throw new CryptoException('Invalid GCM ciphertext hex');
        }
        if (!preg_match('/^[0-9a-fA-F]+$/', $tagHex) || strlen($tagHex) % 2 !== 0) {
            throw new CryptoException('Invalid GCM tag hex');
        }

        $cipherBin = hex2bin($cipherHex);
        $tagBin = hex2bin($tagHex);
        if ($cipherBin === false || $tagBin === false) {
            throw new CryptoException('Invalid GCM ciphertext or tag');
        }

        return $gcm->decrypt($cipherBin, $tagBin, $ivBin, $aad, $tagLength);
    }

    /**
     * Get the OpenSSL cipher method name for the given SM4 mode.
     */
    private static function getOpenSSLMethodName(string $mode): string
    {
        return match ($mode) {
            self::MODE_ECB => 'SM4-ECB',
            self::MODE_CBC => 'SM4-CBC',
            self::MODE_CFB => 'SM4-CFB',
            self::MODE_OFB => 'SM4-OFB',
            self::MODE_CTR => 'SM4-CTR',
            default => throw new InvalidKeyException('Unsupported SM4 mode: ' . $mode),
        };
    }

    private static function validateHexKey(string $hex, string $label = 'Key'): void
    {
        if (!preg_match('/^[0-9a-fA-F]{32}$/', $hex)) {
            $msg = $label === 'IV' ? 'IV must be 128 bits (32 hex chars)' : 'Key must be 128 bits (32 hex chars)';
            throw new InvalidKeyException($msg);
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function payloadString(array $payload, string $key): string
    {
        if (!array_key_exists($key, $payload) || !is_string($payload[$key])) {
            throw new InvalidKeyException('Invalid SM4 payload: missing string field ' . $key);
        }
        return $payload[$key];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function payloadInt(array $payload, string $key): int
    {
        if (!array_key_exists($key, $payload) || !is_int($payload[$key])) {
            throw new InvalidKeyException('Invalid SM4 payload: missing integer field ' . $key);
        }
        return $payload[$key];
    }

    private static function validatePayloadHex(string $hex, string $label, bool $allowEmpty): void
    {
        if ($hex === '') {
            if ($allowEmpty) {
                return;
            }
            throw new InvalidKeyException('Invalid SM4 payload ' . $label . ': empty value');
        }
        if (!preg_match('/^[0-9a-fA-F]+$/', $hex) || strlen($hex) % 2 !== 0) {
            throw new InvalidKeyException('Invalid SM4 payload ' . $label . ' hex');
        }
    }

    private static function maybePad(string $data, string $padding): string
    {
        if ($padding === 'none') {
            if (strlen($data) % 16 !== 0) {
                throw new InvalidKeyException('Data length must be multiple of 16 when padding=none');
            }
            return $data;
        }

        $block = 16;
        $remainder = strlen($data) % $block;
        $padLen = $remainder === 0 ? $block : $block - $remainder;

        return match ($padding) {
            'pkcs5', 'pkcs7' => $data . str_repeat(chr($padLen), $padLen),
            'zero' => $data . str_repeat("\0", $padLen),
            'iso10126' => $data . ($padLen > 1 ? random_bytes($padLen - 1) : '') . chr($padLen),
            'ansix923' => $data . str_repeat("\0", $padLen - 1) . chr($padLen),
            default => throw new InvalidKeyException('Unsupported padding: ' . $padding),
        };
    }

    private static function maybeUnpad(string $data, string $padding): string
    {
        if ($padding === 'none') {
            return $data;
        }
        $len = strlen($data);
        if ($len === 0 || $len % 16 !== 0) {
            throw new CryptoException('Decryption failed');
        }

        if ($padding === 'zero') {
            return rtrim($data, "\0");
        }

        $pad = ord($data[$len - 1]);

        if ($padding === 'pkcs5' || $padding === 'pkcs7') {
            if ($pad < 1 || $pad > 16 || substr($data, -$pad) !== str_repeat(chr($pad), $pad)) {
                throw new CryptoException('Decryption failed');
            }
        } elseif ($padding === 'ansix923') {
            if ($pad < 1 || $pad > 16) {
                throw new CryptoException('Decryption failed');
            }
            $padBytes = substr($data, -$pad, $pad - 1);
            if ($padBytes !== str_repeat("\0", $pad - 1)) {
                throw new CryptoException('Decryption failed');
            }
        } else {
            if ($pad < 1 || $pad > 16) {
                throw new CryptoException('Decryption failed');
            }
        }

        return substr($data, 0, $len - $pad);
    }
}
