<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Interfaces\Sm4KeyModeTrackerInterface;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use PHPUnit\Framework\TestCase;

class Sm4KeyModeTrackerTest extends TestCase
{
    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSharedTrackerReceivesKeyFingerprintAndModeClaims(): void
    {
        $claims = [];
        Sm4::setKeyModeTracker(new class ($claims) implements Sm4KeyModeTrackerInterface {
            /** @var list<array{fingerprint: string, mode: string}> */
            public array $claims;

            /** @param list<array{fingerprint: string, mode: string}> $claims */
            public function __construct(array &$claims)
            {
                $this->claims = &$claims;
            }

            public function claimMode(string $keyFingerprint, string $mode): bool
            {
                $this->claims[] = ['fingerprint' => $keyFingerprint, 'mode' => $mode];
                return true;
            }

            public function isModeAllowed(string $keyFingerprint, string $mode): bool
            {
                return true;
            }
        });

        $keyBytes = str_repeat("\xab", 16);
        $key = bin2hex($keyBytes);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv(str_repeat('00', 16));
        $ciphertext = Sm4::encrypt(
            str_repeat('x', 16),
            $key,
            $options
        );
        $this->assertSame(str_repeat('x', 16), Sm4::decrypt($ciphertext, $key, $options));

        $this->assertNotEmpty($claims);
        foreach ($claims as $claim) {
            $this->assertSame(hash('sha256', $keyBytes, true), $claim['fingerprint']);
            $this->assertSame(Sm4::MODE_CTR, $claim['mode']);
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRejectedSharedModeClaimFailsClosedAndLocksConfiguration(): void
    {
        Sm4::setKeyModeTracker(new class () implements Sm4KeyModeTrackerInterface {
            public function claimMode(string $keyFingerprint, string $mode): bool
            {
                return false;
            }

            public function isModeAllowed(string $keyFingerprint, string $mode): bool
            {
                return false;
            }
        });

        try {
            Sm4::encrypt(
                'payload',
                str_repeat('ab', 16),
                (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv(str_repeat('12', 16))
            );
            $this->fail('A rejected shared mode claim must stop encryption');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('key-mode tracker rejected', $exception->getMessage());
        }

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('key-mode tracker cannot be changed');
        Sm4::setKeyModeTracker(null);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSharedModeTrackerRejectsCrossModeKeyReuse(): void
    {
        $modesByKey = [];
        Sm4::setKeyModeTracker(new class ($modesByKey) implements Sm4KeyModeTrackerInterface {
            /** @var array<string, string> */
            public array $modesByKey;

            /** @param array<string, string> $modesByKey */
            public function __construct(array &$modesByKey)
            {
                $this->modesByKey = &$modesByKey;
            }

            public function claimMode(string $keyFingerprint, string $mode): bool
            {
                $key = bin2hex($keyFingerprint);
                $configured = $this->modesByKey[$key] ?? null;
                if ($configured !== null && $configured !== $mode) {
                    return false;
                }
                $this->modesByKey[$key] = $mode;
                return true;
            }

            public function isModeAllowed(string $keyFingerprint, string $mode): bool
            {
                return ($this->modesByKey[bin2hex($keyFingerprint)] ?? null) === $mode;
            }
        });

        $key = str_repeat('ab', 16);
        Sm4::encrypt(
            str_repeat('x', 16),
            $key,
            (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv(str_repeat('00', 16))
        );

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('key-mode tracker rejected');
        Sm4::encrypt(
            str_repeat('x', 16),
            $key,
            (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv(str_repeat('00', 16))
        );
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testUnauthenticatedDecryptCannotPinSharedKeyMode(): void
    {
        $modesByKey = [];
        $tracker = new class ($modesByKey) implements Sm4KeyModeTrackerInterface {
            /** @var array<string, string> */
            public array $modesByKey;

            /** @param array<string, string> $modesByKey */
            public function __construct(array &$modesByKey)
            {
                $this->modesByKey = &$modesByKey;
            }

            public function claimMode(string $keyFingerprint, string $mode): bool
            {
                $key = bin2hex($keyFingerprint);
                $configured = $this->modesByKey[$key] ?? null;
                if ($configured !== null && $configured !== $mode) {
                    return false;
                }
                $this->modesByKey[$key] = $mode;
                return true;
            }

            public function isModeAllowed(string $keyFingerprint, string $mode): bool
            {
                return ($this->modesByKey[bin2hex($keyFingerprint)] ?? null) === $mode;
            }
        };
        Sm4::setKeyModeTracker($tracker);

        $key = str_repeat('ab', 16);
        Sm4::registerKeyMode($key, Sm4::MODE_CTR);
        $before = $tracker->modesByKey;

        try {
            Sm4::decrypt(
                str_repeat('00', 16),
                $key,
                (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv(str_repeat('12', 16))
            );
            $this->fail('Unregistered decryption mode must fail before processing unauthenticated input');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('not registered for this decryption mode', $exception->getMessage());
        }

        $this->assertSame($before, $tracker->modesByKey);
    }
}
