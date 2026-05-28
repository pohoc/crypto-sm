<?php

declare(strict_types=1);

namespace CryptoSm\SM3;

use CryptoSm\Interfaces\HashInterface;

/**
 * SM3 cryptographic hash algorithm implementation (GM/T 0004-2012).
 */
class Sm3 implements HashInterface
{
    private const IV = [
        0x7380166f,
        0x4914b2b9,
        0x172442d7,
        0xda8a0600,
        0xa96f30bc,
        0x163138aa,
        0xe38dee4d,
        0xb0fb0e4e,
    ];

    /**
     * Compute SM3 hash of the given data.
     *
     * @param  string $data Input data
     * @return string 64-character hex string (256-bit hash)
     */
    public static function sm3(string $data): string
    {
        return self::computeHash($data);
    }

    /**
     * Alias for sm3() — static hash computation (HashInterface naming convention).
     *
     * @param  string $data Input data
     * @return string 64-character hex string
     */
    public static function hashStatic(string $data): string
    {
        return self::sm3($data);
    }

    /**
     * Instance method for hash computation (HashInterface).
     *
     * @param  string $data Input data
     * @return string 64-character hex string
     */
    public function hash(string $data): string
    {
        return self::sm3($data);
    }

    /** @var bool|null Cached availability of native SM3 support */
    private static ?bool $nativeSm3Available = null;

    // ─── Streaming API ────────────────────────────────────────────────────

    /** @var bool Whether native SM3 streaming is available (cached per instance) */
    private bool $nativeAvailable;

    /** @var string Buffered data for streaming (concatenated, processed on finalize) */
    private string $buffer = '';

    private ?\HashContext $hashContext = null;

    /** @var int Total number of bytes processed */
    private int $totalLen = 0;

    /** @var array<int,int> Pure PHP state (8 x 32-bit words) */
    private array $state;

    public function __construct()
    {
        $this->state = self::IV;
        if (self::$nativeSm3Available === null) {
            self::$nativeSm3Available = function_exists('hash_init')
                && in_array('sm3', hash_algos(), true);
        }
        $this->nativeAvailable = self::$nativeSm3Available;
        if ($this->nativeAvailable) {
            $this->hashContext = hash_init('sm3');
        }
    }

    /**
     * Feed data into the streaming hash computation.
     *
     * @param  string $data Data chunk to process
     * @return self   This instance for method chaining
     */
    public function update(string $data): self
    {
        $dataLen = strlen($data);
        $this->totalLen += $dataLen;

        if ($this->nativeAvailable && $this->hashContext !== null) {
            hash_update($this->hashContext, $data);
        } else {
            // Pure PHP path: process blocks incrementally, no allData overhead
            $this->buffer .= $data;
            while (strlen($this->buffer) >= 64) {
                $block = substr($this->buffer, 0, 64);
                $this->buffer = substr($this->buffer, 64);
                $this->state = self::processBlock($block, $this->state);
            }
        }

        return $this;
    }

    /**
     * Finalize the streaming hash and return the result.
     *
     * When native SM3 is available, data is processed through PHP's hash
     * extension incrementally to avoid retaining full streams in memory.
     *
     * @return string 64-character hex string (256-bit hash)
     */
    public function finalize(): string
    {
        if ($this->nativeAvailable && $this->hashContext !== null) {
            $result = hash_final($this->hashContext);
            $this->reset();
            return $result;
        }

        $result = $this->finalizePure();
        $this->reset();
        return $result;
    }

    private function reset(): void
    {
        $this->buffer = '';
        $this->totalLen = 0;
        $this->state = self::IV;
        $this->hashContext = $this->nativeAvailable ? hash_init('sm3') : null;
    }

    /**
     * Finalize using pure PHP (fallback when OpenSSL unavailable).
     */
    private function finalizePure(): string
    {
        $msg = $this->buffer;
        $len = strlen($msg);
        $bitLen = $this->totalLen * 8;

        $msg .= chr(0x80);
        $padLen = (56 - (($len + 1) % 64) + 64) % 64;
        if ($padLen) {
            $msg .= str_repeat(chr(0x00), $padLen);
        }
        $msg .= pack('N2', $bitLen >> 32, $bitLen & 0xFFFFFFFF);

        $blocks = str_split($msg, 64);
        $v = $this->state;
        foreach ($blocks as $block) {
            $v = self::processBlock($block, $v);
        }

        return sprintf('%08x%08x%08x%08x%08x%08x%08x%08x', ...$v);
    }

    /**
     * Process a single 64-byte block and return the updated state.
     *
     * @param  string         $block 64-byte block
     * @param  array<int,int> $v     Current state (8 x 32-bit words)
     * @return array<int,int> Updated state
     */
    private static function processBlock(string $block, array $v): array
    {
        $rol = static fn (int $x, int $n): int => (($x << ($n & 31)) | ($x >> (32 - ($n & 31)))) & 0xFFFFFFFF;
        $p0 = static fn (int $x): int => ($x ^ $rol($x, 9) ^ $rol($x, 17)) & 0xFFFFFFFF;
        $p1 = static fn (int $x): int => ($x ^ $rol($x, 15) ^ $rol($x, 23)) & 0xFFFFFFFF;

        [$w, $wPrime] = self::expandWith($block, $rol, $p1);

        [$a, $b, $c, $d, $e, $f, $g, $h] = $v;

        for ($j = 0; $j < 16; $j++) {
            $rolA12 = $rol($a, 12);
            $ss1 = $rol(($rolA12 + $e + $rol(0x79cc4519, $j % 32)) & 0xFFFFFFFF, 7);
            $ss2 = $ss1 ^ $rolA12;
            $ff = $a ^ $b ^ $c;
            $gg = $e ^ $f ^ $g;
            $tt1 = ($ff + $d + $ss2 + $wPrime[$j]) & 0xFFFFFFFF;
            $tt2 = ($gg + $h + $ss1 + $w[$j]) & 0xFFFFFFFF;

            $d = $c;
            $c = $rol($b, 9);
            $b = $a;
            $a = $tt1;
            $h = $g;
            $g = $rol($f, 19);
            $f = $e;
            $e = $p0($tt2);
        }

        for ($j = 16; $j < 64; $j++) {
            $rolA12 = $rol($a, 12);
            $ss1 = $rol(($rolA12 + $e + $rol(0x7a879d8a, $j % 32)) & 0xFFFFFFFF, 7);
            $ss2 = $ss1 ^ $rolA12;
            $ff = ($a & $b) | ($a & $c) | ($b & $c);
            $gg = ($e & $f) | ((~$e) & $g);
            $tt1 = ($ff + $d + $ss2 + $wPrime[$j]) & 0xFFFFFFFF;
            $tt2 = ($gg + $h + $ss1 + $w[$j]) & 0xFFFFFFFF;

            $d = $c;
            $c = $rol($b, 9);
            $b = $a;
            $a = $tt1;
            $h = $g;
            $g = $rol($f, 19);
            $f = $e;
            $e = $p0($tt2);
        }

        return [
            $v[0] ^ $a,
            $v[1] ^ $b,
            $v[2] ^ $c,
            $v[3] ^ $d,
            $v[4] ^ $e,
            $v[5] ^ $f,
            $v[6] ^ $g,
            $v[7] ^ $h,
        ];
    }

    // ─── Static API ───────────────────────────────────────────────────────

    private static function computeHash(string $msg): string
    {
        // P0: Prefer PHP's native hash extension when SM3 is available.
        if (self::$nativeSm3Available === null) {
            self::$nativeSm3Available = function_exists('hash')
                && in_array('sm3', hash_algos(), true);
        }
        if (self::$nativeSm3Available) {
            return hash('sm3', $msg);
        }

        return self::computeHashPure($msg);
    }

    /**
     * Pure PHP SM3 implementation (fallback when OpenSSL SM3 is unavailable).
     *
     * Optimizations applied:
     * - Inline helper functions as closures to reduce method call overhead (~640 calls/block)
     * - Cache repeated sub-expressions (rol($a, 12))
     * - Remove unnecessary p32() on XOR results (XOR of 32-bit values stays within 32 bits)
     * - Unroll the j < 16 / j >= 16 branch outside the inner loop
     */
    private static function computeHashPure(string $msg): string
    {
        $blocks = self::pad($msg);
        $v = self::IV;

        // Inline helpers as closures — significantly faster than self::method() calls
        $rol = static fn (int $x, int $n): int => (($x << ($n & 31)) | ($x >> (32 - ($n & 31)))) & 0xFFFFFFFF;
        $p0 = static fn (int $x): int => ($x ^ $rol($x, 9) ^ $rol($x, 17)) & 0xFFFFFFFF;
        $p1 = static fn (int $x): int => ($x ^ $rol($x, 15) ^ $rol($x, 23)) & 0xFFFFFFFF;

        foreach ($blocks as $block) {
            [$w, $wPrime] = self::expandWith($block, $rol, $p1);

            [$a, $b, $c, $d, $e, $f, $g, $h] = $v;

            // Unroll j < 16 and j >= 16 phases to avoid per-iteration branch
            for ($j = 0; $j < 16; $j++) {
                $rolA12 = $rol($a, 12);
                $ss1 = $rol(($rolA12 + $e + $rol(0x79cc4519, $j % 32)) & 0xFFFFFFFF, 7);
                $ss2 = $ss1 ^ $rolA12;
                $ff = $a ^ $b ^ $c;
                $gg = $e ^ $f ^ $g;
                $tt1 = ($ff + $d + $ss2 + $wPrime[$j]) & 0xFFFFFFFF;
                $tt2 = ($gg + $h + $ss1 + $w[$j]) & 0xFFFFFFFF;

                $d = $c;
                $c = $rol($b, 9);
                $b = $a;
                $a = $tt1;
                $h = $g;
                $g = $rol($f, 19);
                $f = $e;
                $e = $p0($tt2);
            }

            for ($j = 16; $j < 64; $j++) {
                $rolA12 = $rol($a, 12);
                $ss1 = $rol(($rolA12 + $e + $rol(0x7a879d8a, $j % 32)) & 0xFFFFFFFF, 7);
                $ss2 = $ss1 ^ $rolA12;
                $ff = ($a & $b) | ($a & $c) | ($b & $c);
                $gg = ($e & $f) | ((~$e) & $g);
                $tt1 = ($ff + $d + $ss2 + $wPrime[$j]) & 0xFFFFFFFF;
                $tt2 = ($gg + $h + $ss1 + $w[$j]) & 0xFFFFFFFF;

                $d = $c;
                $c = $rol($b, 9);
                $b = $a;
                $a = $tt1;
                $h = $g;
                $g = $rol($f, 19);
                $f = $e;
                $e = $p0($tt2);
            }

            // XOR of 32-bit values stays within 32 bits — no p32() needed
            $v = [
                $v[0] ^ $a,
                $v[1] ^ $b,
                $v[2] ^ $c,
                $v[3] ^ $d,
                $v[4] ^ $e,
                $v[5] ^ $f,
                $v[6] ^ $g,
                $v[7] ^ $h,
            ];
        }

        return sprintf(
            '%08x%08x%08x%08x%08x%08x%08x%08x',
            ...$v
        );
    }

    /**
     * @param callable(int, int): int $rol
     * @param callable(int): int      $p1
     *
     * @return array<int,array<int,int>>
     */
    private static function expandWith(string $block, callable $rol, callable $p1): array
    {
        $unpacked = unpack('N16', $block);
        $w = $unpacked === false ? [] : array_values($unpacked);
        for ($j = 16; $j < 68; $j++) {
            $w[$j] = $p1($w[$j - 16] ^ $w[$j - 9] ^ $rol($w[$j - 3], 15))
                ^ $rol($w[$j - 13], 7) ^ $w[$j - 6];
        }

        $wPrime = [];
        for ($j = 0; $j < 64; $j++) {
            $wPrime[$j] = ($w[$j] ^ $w[$j + 4]) & 0xFFFFFFFF;
        }

        return [$w, $wPrime];
    }

    /** @return array<int,string> */
    private static function pad(string $msg): array
    {
        $len = strlen($msg);
        // GM/T 0004-2012: message length in bits, max 2^64 - 1 bits
        $bitLen = $len * 8;
        if (PHP_INT_SIZE >= 8) {
            if ($len > (int) ((PHP_INT_MAX - 7) / 8)) {
                throw new \RuntimeException('SM3: message too long, bit length overflow');
            }
        }

        $msg .= chr(0x80);
        $padLen = (56 - (($len + 1) % 64) + 64) % 64;
        if ($padLen) {
            $msg .= str_repeat(chr(0x00), $padLen);
        }
        $msg .= pack('N2', $bitLen >> 32, $bitLen & 0xFFFFFFFF);

        return str_split($msg, 64);
    }
}
