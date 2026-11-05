<?php

declare(strict_types=1);

namespace CryptoSm\SM3;

use CryptoSm\Interfaces\HashInterface;
use CryptoSm\Utils\SensitiveContext;

/**
 * SM3 cryptographic hash algorithm implementation (GM/T 0004-2012).
 */
class Sm3 implements HashInterface
{
    use SensitiveContext;

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

    /** @var array{0: callable(int, int): int, 1: callable(int): int, 2: callable(int): int}|null Cached [rol, p0, p1] helpers */
    private static ?array $roundHelpers = null;

    /** @var array<int, int>|null Precomputed rotated Tj constants indexed by round number (GM/T 0004-2012) */
    private static ?array $rotatedConstants = null;

    /**
     * Rotated Tj round constants, computed once per process.
     *
     * The per-round expression rol(Tj, j mod 32) only depends on the round
     * index, so it can be tabulated instead of re-evaluated 64 times per block.
     *
 * @return array<int, int>
     */
    private static function rotatedConstants(): array
    {
        if (self::$rotatedConstants === null) {
            // Runs once per process; a local closure keeps types inferable
            $rol = static fn (int $x, int $n): int => (($x << ($n & 31)) | ($x >> (32 - ($n & 31)))) & 0xFFFFFFFF;
            /** @var array<int, int> $table */
            $table = [];
            for ($j = 0; $j < 16; $j++) {
                $table[$j] = $rol(0x79cc4519, $j);
            }
            for ($j = 16; $j < 64; $j++) {
                $table[$j] = $rol(0x7a879d8a, $j % 32);
            }
            self::$rotatedConstants = $table;
        }
        return self::$rotatedConstants;
    }

    /**
     * Shared round-function helpers, allocated once per process.
     *
     * Building these closures on every call dominated small-message latency
     * (a ~200 µs floor); caching them removes that fixed cost while keeping
     * closure-invocation speed for the ~640 calls per block.
     *
     * @return array{0: callable(int, int): int, 1: callable(int): int, 2: callable(int): int} [rol, p0, p1]
     */
    private static function roundHelpers(): array
    {
        if (self::$roundHelpers === null) {
            $rol = static fn (int $x, int $n): int => (($x << ($n & 31)) | ($x >> (32 - ($n & 31)))) & 0xFFFFFFFF;
            self::$roundHelpers = [
                $rol,
                static fn (int $x): int => ($x ^ $rol($x, 9) ^ $rol($x, 17)) & 0xFFFFFFFF,
                static fn (int $x): int => ($x ^ $rol($x, 15) ^ $rol($x, 23)) & 0xFFFFFFFF,
            ];
        }
        return self::$roundHelpers;
    }

    // ─── Streaming API ────────────────────────────────────────────────────

    /** @var bool Whether native SM3 streaming is available (cached per instance) */
    private bool $nativeAvailable;

    /** @var string Buffered data for streaming (concatenated, processed on finalize) */
    private string $buffer = '';

    private ?\HashContext $hashContext = null;

    /** @var string Total number of bytes processed as an unsigned 64-bit big-endian byte count */
    private string $totalLengthBytes = "\0\0\0\0\0\0\0\0";

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
        if (!$this->nativeAvailable) {
            self::assertPurePhpSupported();
        }
        if ($this->nativeAvailable) {
            $this->hashContext = hash_init('sm3');
        }
    }

    public function __clone()
    {
        if ($this->hashContext !== null) {
            $this->hashContext = hash_copy($this->hashContext);
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
        if (!$this->nativeAvailable) {
            self::assertPurePhpSupported();
        }
        $dataLen = strlen($data);
        $this->addToTotalLength($dataLen);

        if ($this->nativeAvailable && $this->hashContext !== null) {
            hash_update($this->hashContext, $data);
        } else {
            $offset = 0;
            if ($this->buffer !== '') {
                $take = min(64 - strlen($this->buffer), $dataLen);
                $this->buffer .= substr($data, 0, $take);
                $offset = $take;
                if (strlen($this->buffer) === 64) {
                    $this->state = self::processBlock($this->buffer, $this->state);
                    $this->buffer = '';
                }
            }
            while ($offset + 64 <= $dataLen) {
                $this->state = self::processBlock(substr($data, $offset, 64), $this->state);
                $offset += 64;
            }
            if ($offset < $dataLen) {
                $this->buffer .= substr($data, $offset);
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
        $this->totalLengthBytes = "\0\0\0\0\0\0\0\0";
        $this->state = self::IV;
        $this->hashContext = $this->nativeAvailable ? hash_init('sm3') : null;
    }

    /**
     * Finalize using pure PHP (fallback when OpenSSL unavailable).
     */
    private function finalizePure(): string
    {
        self::assertPurePhpSupported();
        $msg = $this->buffer;
        $len = strlen($msg);

        $msg .= chr(0x80);
        $padLen = (56 - (($len + 1) % 64) + 64) % 64;
        if ($padLen) {
            $msg .= str_repeat(chr(0x00), $padLen);
        }
        $msg .= self::encodeBitLengthHex(bin2hex($this->totalLengthBytes));

        $blocks = str_split($msg, 64);
        $v = $this->state;
        foreach ($blocks as $block) {
            $v = self::processBlock($block, $v);
        }

        return sprintf('%08x%08x%08x%08x%08x%08x%08x%08x', ...$v);
    }

    /** The PHP-integer round arithmetic requires a signed 64-bit runtime. */
    private static function assertPurePhpSupported(): void
    {
        if (PHP_INT_SIZE < 8) {
            throw new \RuntimeException('Pure PHP SM3 requires a 64-bit PHP runtime; native SM3 support is required on 32-bit platforms');
        }
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
        [$rol, $p0, $p1] = self::roundHelpers();

        [$w, $wPrime] = self::expandWith($block, $rol, $p1);

        [$a, $b, $c, $d, $e, $f, $g, $h] = $v;
        $tRot = self::rotatedConstants();

        for ($j = 0; $j < 16; $j++) {
            $rolA12 = $rol($a, 12);
            $ss1 = $rol(($rolA12 + $e + $tRot[$j]) & 0xFFFFFFFF, 7);
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
            $ss1 = $rol(($rolA12 + $e + $tRot[$j]) & 0xFFFFFFFF, 7);
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
     * - Round-function closures cached per process (see roundHelpers()) to
     *   avoid per-call allocation while keeping closure-call speed (~640 calls/block)
     * - Cache repeated sub-expressions (rol($a, 12))
     * - Remove unnecessary p32() on XOR results (XOR of 32-bit values stays within 32 bits)
     * - Unroll the j < 16 / j >= 16 branch outside the inner loop
     */
    private static function computeHashPure(string $msg): string
    {
        self::assertPurePhpSupported();
        $blocks = self::pad($msg);
        $v = self::IV;

        [$rol, $p0, $p1] = self::roundHelpers();

        foreach ($blocks as $block) {
            [$w, $wPrime] = self::expandWith($block, $rol, $p1);

            [$a, $b, $c, $d, $e, $f, $g, $h] = $v;
            $tRot = self::rotatedConstants();

            // Unroll j < 16 and j >= 16 phases to avoid per-iteration branch
            for ($j = 0; $j < 16; $j++) {
                $rolA12 = $rol($a, 12);
                $ss1 = $rol(($rolA12 + $e + $tRot[$j]) & 0xFFFFFFFF, 7);
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
                $ss1 = $rol(($rolA12 + $e + $tRot[$j]) & 0xFFFFFFFF, 7);
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

    /** @return \Generator<int, string> */
    private static function pad(string $msg): \Generator
    {
        $len = strlen($msg);
        $fullLength = $len - ($len % 64);

        for ($offset = 0; $offset < $fullLength; $offset += 64) {
            yield substr($msg, $offset, 64);
        }

        $tail = substr($msg, $fullLength) . chr(0x80);
        $padLen = (56 - (strlen($tail) % 64) + 64) % 64;
        if ($padLen) {
            $tail .= str_repeat(chr(0x00), $padLen);
        }
        $tail .= self::encodeBitLength($len);

        for ($offset = 0, $tailLength = strlen($tail); $offset < $tailLength; $offset += 64) {
            yield substr($tail, $offset, 64);
        }
    }

    /** Encode a byte length as the 64-bit big-endian bit length required by GM/T 0004-2012. */
    private static function encodeBitLength(int $byteLength): string
    {
        if ($byteLength < 0) {
            throw new \RuntimeException('SM3: message length must not be negative');
        }

        // Shift the fixed-width hexadecimal representation nibble by nibble so
        // this remains safe on 32-bit PHP, where byteLength * 8 can overflow.
        return self::encodeBitLengthHex(sprintf('%016x', $byteLength));
    }

    private static function encodeBitLengthHex(string $hex): string
    {
        $bitLengthHex = '';
        $carry = 0;
        for ($i = 15; $i >= 0; $i--) {
            $value = hexdec($hex[$i]) * 8 + $carry;
            $bitLengthHex = dechex($value & 0x0F) . $bitLengthHex;
            $carry = $value >> 4;
        }

        if ($carry !== 0) {
            throw new \RuntimeException('SM3: message too long, bit length exceeds 64 bits');
        }

        return pack('H*', $bitLengthHex);
    }

    private function addToTotalLength(int $byteLength): void
    {
        if ($byteLength < 0) {
            throw new \RuntimeException('SM3: update length must not be negative');
        }

        $total = $this->totalLengthBytes;
        $carry = $byteLength;
        for ($i = 7; $i >= 0; $i--) {
            $sum = ord($total[$i]) + ($carry % 256);
            $carry = intdiv($carry, 256) + ($sum >> 8);
            $total[$i] = chr($sum & 0xFF);
        }

        // The 64-bit SM3 trailer stores a bit count, so a byte count may use at
        // most 61 bits. Reject overflow before accepting this update.
        if ($carry !== 0 || ord($total[0]) > 0x1F) {
            throw new \RuntimeException('SM3: message too long, bit length exceeds 64 bits');
        }

        $this->totalLengthBytes = $total;
    }
}
