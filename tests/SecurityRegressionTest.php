<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Asn1;
use CryptoSm\Crypto\Ccm;
use CryptoSm\Crypto\Gcm;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Interfaces\CcmNonceTrackerInterface;
use CryptoSm\Interfaces\CcmTagLengthTrackerInterface;
use CryptoSm\Interfaces\GcmIvTrackerInterface;
use CryptoSm\Interfaces\GcmTagLengthTrackerInterface;
use CryptoSm\Interfaces\Sm4CtrCounterTrackerInterface;
use CryptoSm\Interfaces\Sm4FeedbackIvTrackerInterface;
use CryptoSm\Interfaces\Sm4StreamBlockTrackerInterface;
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use CryptoSm\SM4\Sm4PurePhp;
use CryptoSm\SmCrypto;
use PHPUnit\Framework\TestCase;

final class GcmTrackerClaimCounter
{
    public int $count = 0;
}

final class GcmTagProfileRegistry
{
    /** @var array<string, int> */
    public array $profiles = [];
}

/**
 * 安全加固回归测试
 *
 * 覆盖以下修复点：
 * 1. ISO 10126 填充在 padLen=1 时不再触发 random_bytes(0) 崩溃
 * 2. 解密缺少 IV 时显式报错而非静默返回乱码
 * 3. SM2 用户 ID 超过 ENTL 16 位上限时按 GM/T 0003-2012 拒绝
 * 4. GCM IV 重用检测默认开启，支持重置与关闭
 * 5. GCM tagLength 在 Sm4Options 与 Gcm 层校验一致
 * 6. setMode 相同模式为幂等操作（不重置已设置的 IV）
 * 7. PEM BEGIN/END 标签必须匹配
 * 8. 密钥交换 klen 上界保护
 */
class SecurityRegressionTest extends TestCase
{
    public function testSm2KeyExchangeRejectsAllZeroKdfOutput(): void
    {
        $reject = new \ReflectionMethod(KeyExchange::class, 'rejectAllZeroDerivedKey');

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('KDF derived an all-zero key');
        $reject->invoke(null, "\0\0\0\0");
    }

    public function testSm2KeyExchangeAcceptsNonZeroKdfOutput(): void
    {
        $reject = new \ReflectionMethod(KeyExchange::class, 'rejectAllZeroDerivedKey');

        $this->assertNull($reject->invoke(null, "\0\x01\0\0"));
    }

    public function testDerIntegerEncodingNormalizesLongZeroPrefixes(): void
    {
        $prefix = str_repeat('00', 4096);
        $this->assertSame("\x02\x01\x00", Asn1::encodeInteger($prefix));
        $this->assertSame("\x02\x02\x00\x80", Asn1::encodeInteger($prefix . '80'));
        $this->assertSame("\x02\x01\x7f", Asn1::encodeInteger($prefix . '7f'));
    }

    public function testSm2PointAdditionRejectsOffCurveAndOutOfFieldPoints(): void
    {
        $valid = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $p = str_pad(gmp_strval(Sm2::gmpParamPublic('p'), 16), 64, '0', STR_PAD_LEFT);
        foreach ([str_repeat('0', 128), $p . substr($valid, 64)] as $invalid) {
            $this->assertNull(Sm2::pointAddPublic($invalid, $valid));
            $this->assertNull(Sm2::pointAddPublic($valid, $invalid));
        }
        $this->assertSame(
            Sm2::getPublicKey(str_pad('2', 64, '0', STR_PAD_LEFT)),
            Sm2::pointAddPublic($valid, $valid)
        );
    }

    public function testSm2InterfacesRejectWrongOptionTypes(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $publicKey = Sm2::getPublicKey($privateKey);
        foreach ([
            static fn () => Sm2::encrypt('message', $publicKey, new SignatureOptions()),
            static fn () => Sm2::decrypt('invalid', $privateKey, new SignatureOptions()),
            static fn () => Sm2::sign('message', $privateKey, new \stdClass()),
        ] as $operation) {
            try {
                $operation();
                $this->fail('Invalid options must not silently select defaults');
            } catch (InvalidKeyException $e) {
                $this->assertStringContainsString('options must be an instance', $e->getMessage());
            }
        }
        $signature = Sm2::sign('message', $privateKey);
        $this->assertTrue(Sm2::verify('message', $signature, $publicKey));
        $this->assertFalse(Sm2::verify('message', $signature, $publicKey, new \stdClass()));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSecretContextsReleaseWeakMapEntriesAfterLastClone(): void
    {
        $key = str_repeat('k', 16);
        $contexts = [
            [static function (): Keypair {
                $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
                return new Keypair($privateKey, Sm2::getPublicKey($privateKey));
            }, Keypair::class, 'privateKeys'],
            [static fn () => HmacSm3::create($key), HmacSm3::class, 'states'],
            [static function () use ($key): Sm4PurePhp {
                $engine = new Sm4PurePhp();
                $engine->setKey($key);
                return $engine;
            }, Sm4PurePhp::class, 'keyStates'],
            [static fn () => new Gcm($key), Gcm::class, 'secretStates'],
            [static fn () => new Ccm($key), Ccm::class, 'keys'],
        ];

        foreach ($contexts as [$factory, $class, $property]) {
            $context = $factory();
            $store = (new \ReflectionProperty($class, $property))->getValue();
            $this->assertInstanceOf(\WeakMap::class, $store);
            $this->assertCount(1, $store);
            $clone = clone $context;
            $this->assertCount(2, $store);
            unset($context);
            $this->assertCount(1, $store);
            unset($clone);
            $this->assertCount(0, $store);
        }
    }

    public function testKeypairExportDoesNotExposePrivateKeyAndCloneRetainsIt(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $keypair = new Keypair($privateKey, Sm2::getPublicKey($privateKey));
        $copy = clone $keypair;
        $this->assertStringNotContainsString($privateKey, var_export($keypair, true));
        $this->assertSame($privateKey, $copy->getPrivateKey());
        $this->assertSame($keypair->getPublicKey(), $copy->getPublicKey());

        $this->expectException(\LogicException::class);
        serialize($keypair);
    }

    public function testSm4CipherContextsDoNotExposeKeyMaterial(): void
    {
        $key = '0123456789abcdef';
        $engine = new Sm4PurePhp();
        $engine->setKey($key);
        foreach ([new Gcm($key), new Ccm($key), $engine] as $context) {
            ob_start();
            var_dump($context);
            $output = ob_get_clean();
            $this->assertIsString($output);
            $this->assertStringNotContainsString($key, $output);
            $this->assertStringNotContainsString('roundKeys', $output);
            try {
                serialize($context);
                $this->fail('Cipher context serialization must be rejected');
            } catch (\LogicException $e) {
                $this->assertStringContainsString('cannot be serialized', $e->getMessage());
            }
        }
    }

    public function testSm4EngineExportHidesKeysAndCloneCanRekeyIndependently(): void
    {
        $key = '0123456789abcdef';
        $block = str_repeat('x', 16);
        $engine = new Sm4PurePhp();
        $engine->setKey($key);
        $expected = $engine->encryptBlock($block);
        $copy = clone $engine;
        $copy->setKey(str_repeat('z', 16));

        $this->assertSame($expected, $engine->encryptBlock($block));
        $this->assertNotSame($expected, $copy->encryptBlock($block));
        $this->assertSame($block, $copy->decryptBlock($copy->encryptBlock($block)));
        $this->assertStringNotContainsString('roundKeys', var_export($engine, true));
    }

    public function testSm2DecryptRejectsNonHexCiphertextBeforeDecoding(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $point = Sm2::getPublicKey($privateKey);
        $ciphertext = $point . str_repeat('00', 32) . 'zz';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected hexadecimal encoding');
        Sm2::doDecrypt($ciphertext, $privateKey);
    }

    public function testSm2DecryptValidatesPrefixedCiphertextBeforeCopyingIt(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $point = Sm2::getPublicKey($privateKey);
        $ciphertext = '04' . $point . str_repeat('00', 32) . 'zz';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('expected hexadecimal encoding');
        Sm2::doDecrypt($ciphertext, $privateKey);
    }

    public function testPemPublicKeyExportRejectsOffCurvePoint(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('not on SM2 curve');
        Pem::exportPublicKey(str_repeat('0', 128));
    }

    public function testDerPublicKeyExportRejectsOffCurvePoint(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('not on SM2 curve');
        Pem::exportPublicKeyDer(str_repeat('0', 128));
    }

    public function testCcmCounterIncrementCarriesAcrossCompleteQByteField(): void
    {
        $increment = new \ReflectionMethod(Ccm::class, 'incrementCounterField');

        // q = 8: low 32-bit carry must propagate into the high four bytes.
        $counter = "\x07" . str_repeat("\0", 7) . "\x00\x00\x00\x01\xff\xff\xff\xff";
        $this->assertSame(
            "\x07" . str_repeat("\0", 7) . "\x00\x00\x00\x02\x00\x00\x00\x00",
            $increment->invoke(null, $counter)
        );

        // q = 2: wrap is confined to the two-byte counter, not the nonce.
        $counter = "\x01" . str_repeat("\0", 13) . "\xff\xff";
        $this->assertSame("\x01" . str_repeat("\0", 15), $increment->invoke(null, $counter));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRejectedCcmNonceDoesNotLockTagLengthProfile(): void
    {
        $key = random_bytes(16);
        $rejectedNonce = random_bytes(12);
        $usedNonces = new \ReflectionProperty(Ccm::class, 'usedNonces');
        $usedNonces->setValue(null, [hash('sha256', $key . $rejectedNonce, true) => true]);

        try {
            Ccm::fromKey($key)->encrypt('rejected', $rejectedNonce, '', 12);
            $this->fail('A previously claimed CCM nonce must be rejected');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('nonce reuse detected', $exception->getMessage());
        }

        $result = Ccm::fromKey($key)->encrypt('accepted', random_bytes(12), '', 16);
        $this->assertSame(16, strlen($result['tag']));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRejectedCcmTrackerClaimReleasesTagLengthReservation(): void
    {
        $tracker = new class () implements CcmNonceTrackerInterface {
            private int $claims = 0;

            public function claim(string $key, string $nonce): bool
            {
                return ++$this->claims > 1;
            }
        };
        Ccm::setNonceTracker($tracker);
        $key = random_bytes(16);

        try {
            Ccm::fromKey($key)->encrypt('rejected', random_bytes(12), '', 12);
            $this->fail('The first CCM tracker claim must be rejected');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('nonce reuse detected', $exception->getMessage());
        }

        $result = Ccm::fromKey($key)->encrypt('accepted', random_bytes(12), '', 16);
        $this->assertSame(16, strlen($result['tag']));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testCcmTrackerExceptionFailsClosedBeforeEncryption(): void
    {
        Ccm::setNonceTracker(new class () implements CcmNonceTrackerInterface {
            public function claim(string $key, string $nonce): bool
            {
                throw new \RuntimeException('shared CCM store unavailable');
            }
        });

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('shared CCM store unavailable');
        Ccm::fromKey(random_bytes(16))->encrypt('must not encrypt', random_bytes(12));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSharedCcmTagLengthTrackerRejectsDifferentEncryptionProfile(): void
    {
        /** @var \ArrayObject<string, int> $profiles */
        $profiles = new \ArrayObject();
        $tracker = new class ($profiles) implements CcmTagLengthTrackerInterface {
            /** @param \ArrayObject<string, int> $profiles */
            public function __construct(private \ArrayObject $profiles)
            {
            }

            public function claimTagLength(string $key, int $tagLength): bool
            {
                $id = hash('sha256', $key);
                if ($this->profiles->offsetExists($id)) {
                    return $this->profiles->offsetGet($id) === $tagLength;
                }
                $this->profiles->offsetSet($id, $tagLength);
                return true;
            }
        };

        $key = random_bytes(16);
        $profiles->offsetSet(hash('sha256', $key), 16);
        Ccm::setTagLengthTracker($tracker);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tag length must remain fixed');
        Ccm::fromKey($key)->encrypt('different profile', random_bytes(12), '', 12);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testConcurrentCcmClaimsCannotSelectDifferentTagLengths(): void
    {
        $this->configureFiberStackSize();
        Ccm::setNonceTracker(new class () implements CcmNonceTrackerInterface {
            public function claim(string $key, string $nonce): bool
            {
                \Fiber::suspend();
                return true;
            }
        });

        $key = random_bytes(16);
        $successes = [];
        $failures = [];
        $runEncryption = static function (int $tagLength, string $nonce) use ($key, &$successes, &$failures): void {
            try {
                $successes[] = Ccm::fromKey($key)->encrypt('fiber', $nonce, '', $tagLength);
            } catch (CryptoException $exception) {
                $failures[] = $exception->getMessage();
            }
        };

        $shortTagFiber = new \Fiber(static fn () => $runEncryption(12, random_bytes(12)));
        $fullTagFiber = new \Fiber(static fn () => $runEncryption(16, random_bytes(12)));
        $shortTagFiber->start();
        $fullTagFiber->start();
        if ($shortTagFiber->isSuspended()) {
            $shortTagFiber->resume();
        }
        if ($fullTagFiber->isSuspended()) {
            $fullTagFiber->resume();
        }

        $this->assertCount(1, $successes);
        $this->assertCount(1, $failures);
        $this->assertStringContainsString('tag length must remain fixed', $failures[0]);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testCcmDecryptionBindsAndEnforcesTheKeyTagLength(): void
    {
        $key = random_bytes(16);
        $keyId = hash('sha256', $key);
        $nonce = random_bytes(12);
        $profiles = new \ReflectionProperty(Ccm::class, 'tagLengthByKey');

        $shortTagResult = Ccm::fromKey($key)->encrypt('short-tag record', $nonce, '', 4);

        // Model a decryption-only process receiving a valid record first.
        $profiles->setValue(null, []);
        $ccm = Ccm::fromKey($key);
        $this->assertSame(
            'short-tag record',
            $ccm->decrypt($shortTagResult['ciphertext'], $shortTagResult['tag'], $nonce, '', 4)
        );
        $profileMap = $profiles->getValue();
        if (!is_array($profileMap)) {
            throw new \LogicException('CCM tag length profile map is unavailable');
        }
        $this->assertSame(4, $profileMap[$keyId] ?? null);

        // Model another worker that has established a 16-byte profile for this key.
        $profiles->setValue(null, [$keyId => 16]);
        try {
            $ccm->decrypt($shortTagResult['ciphertext'], $shortTagResult['tag'], $nonce, '', 4);
            $this->fail('CCM must reject a tag length that differs from the established key profile');
        } catch (CryptoException $exception) {
            $this->assertSame('SM4-CCM: authentication failed', $exception->getMessage());
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testConcurrentCcmClaimsWithSameTagLengthSucceed(): void
    {
        $this->configureFiberStackSize();
        Ccm::setNonceTracker(new class () implements CcmNonceTrackerInterface {
            public function claim(string $key, string $nonce): bool
            {
                \Fiber::suspend();
                return true;
            }
        });

        $key = random_bytes(16);
        $successes = [];
        $runEncryption = static function (string $nonce) use ($key, &$successes): void {
            $successes[] = Ccm::fromKey($key)->encrypt('fiber', $nonce, '', 16);
        };
        $first = new \Fiber(static fn () => $runEncryption(random_bytes(12)));
        $second = new \Fiber(static fn () => $runEncryption(random_bytes(12)));
        $first->start();
        $second->start();
        $first->resume();
        $second->resume();

        $this->assertCount(2, $successes);
    }

    public function testSm2DecryptDoesNotExposeAllZeroKdfAsDistinctFailure(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $allZeroC1 = Sm2::getPublicKey(str_pad(dechex(351), 64, '0', STR_PAD_LEFT));
        $kdfXor = new \ReflectionMethod(Sm2::class, 'kdfXor');
        $allZeroStream = $kdfXor->invoke(null, $allZeroC1, "\0");
        if (
            !is_array($allZeroStream)
            || !isset($allZeroStream['data'], $allZeroStream['allZero'])
            || !is_string($allZeroStream['data'])
            || !is_bool($allZeroStream['allZero'])
        ) {
            throw new \LogicException('SM2 KDF XOR must return data and allZero fields');
        }
        $this->assertSame("\0", $allZeroStream['data']);
        $this->assertTrue($allZeroStream['allZero']);

        $allZeroCiphertext = $allZeroC1 . str_repeat('0', 64) . '00';
        $ordinaryInvalidCiphertext = Sm2::getPublicKey($privateKey) . str_repeat('0', 64) . '00';

        $decryptError = static function (string $ciphertext) use ($privateKey): string {
            try {
                Sm2::doDecrypt($ciphertext, $privateKey);
            } catch (CryptoException $exception) {
                return $exception->getMessage();
            }

            self::fail('Expected invalid SM2 ciphertext to be rejected');
        };

        $this->assertSame($decryptError($ordinaryInvalidCiphertext), $decryptError($allZeroCiphertext));
        $this->assertSame('SM2 decryption failed: ciphertext verification failed', $decryptError($allZeroCiphertext));
    }

    public function testSm2HexRangeKdfMatchesBinaryKdfForBothCipherLayouts(): void
    {
        $kdfXor = new \ReflectionMethod(Sm2::class, 'kdfXor');
        $kdfXorHexRange = new \ReflectionMethod(Sm2::class, 'kdfXorHexRange');
        $seed = str_repeat('12', 32);
        $c2 = random_bytes(97);
        $prefix = 'deadbeef';
        $suffix = 'cafebabe';

        $expected = $kdfXor->invoke(null, $seed, $c2);
        $actual = $kdfXorHexRange->invoke(null, $seed, $prefix . bin2hex($c2) . $suffix, strlen($prefix), strlen($c2) * 2);

        $this->assertIsArray($expected);
        $this->assertIsArray($actual);
        $this->assertSame($expected['data'], $actual['data']);
        $this->assertSame($expected['allZero'], $actual['allZero']);
    }

    public function testSm2VerifierReturnsFalseForMalformedRawSignatures(): void
    {
        $publicKey = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));

        foreach ([
            '',
            'zz',
            str_repeat('0', 126),
            str_repeat('0', 130),
            str_repeat('g', 128),
        ] as $signature) {
            $this->assertFalse(
                Sm2::doVerifySignature('malformed signature input', $signature, $publicKey),
                'Malformed raw signatures must fail verification without throwing'
            );
        }
    }

    public function testSm2VerifierReturnsFalseForDerSignatureWithTrailingNewline(): void
    {
        $publicKey = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $options = (new SignatureOptions())->setDer(true);

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            $this->assertFalse(
                Sm2::doVerifySignature('malformed DER signature input', "3006020101020101\n", $publicKey, $options),
                'Malformed DER signatures must fail verification without leaking hex2bin warnings'
            );
        } finally {
            restore_error_handler();
        }
    }

    public function testSm2DefaultSignatureDoesNotAliasLeadingNullMessage(): void
    {
        $privateKey = str_pad('1', 64, '0', STR_PAD_LEFT);
        $publicKey = Sm2::getPublicKey($privateKey);
        $message = 'PAY:100';
        $signature = Sm2::doSignature($message, $privateKey);

        $this->assertTrue(Sm2::doVerifySignature($message, $signature, $publicKey));
        $this->assertFalse(Sm2::doVerifySignature("\0" . $message, $signature, $publicKey));
    }

    public function testSm2VerifierRejectsDerScalarWiderThanCurveOrder(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $message = 'SM2 DER scalar range regression';
        $rawSignature = Sm2::doSignature($message, $keypair->getPrivateKey());
        $r = substr($rawSignature, 0, 64);
        $s = substr($rawSignature, 64);
        $options = (new SignatureOptions())->setDer(true);

        $validDer = Asn1::encodeDerSignature($r, $s);
        $this->assertTrue(Sm2::doVerifySignature($message, $validDer, $keypair->getPublicKey(), $options));

        // Build malformed-but-bounded DER directly because the SM2 signature
        // encoder correctly refuses scalars outside the curve-order range.
        $outOfRangeDer = bin2hex(Asn1::encodeSequence(
            Asn1::encodeInteger($r) . Asn1::encodeInteger(str_repeat('f', 64))
        ));
        $this->assertLessThanOrEqual(72, intdiv(strlen($outOfRangeDer), 2));
        $this->assertFalse(Sm2::doVerifySignature($message, $outOfRangeDer, $keypair->getPublicKey(), $options));
    }

    // ─── ISO 10126 填充边界 ───────────────────────────────────────────────

    /**
     * 数据长度 ≡ 15 (mod 16) 时 padLen=1，此前会调用 random_bytes(0) 抛出 ValueError。
     */
    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testIso10126PaddingWithSinglePadByte(): void
    {
        $key = str_repeat('ab', 16);

        // 15 字节 → padLen=1；以及所有 mod 16 余数都应正常往返
        foreach ([15, 31, 47] as $index => $len) {
            $data = str_repeat('A', $len - 1) . 'B';
            $iterationIv = str_repeat(sprintf('%02x', $index), 16);
            $options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setPadding('iso10126')->setIv($iterationIv);
            $ciphertext = Sm4::encrypt($data, $key, $options);
            $this->assertSame($data, Sm4::decrypt($ciphertext, $key, $options));
        }
    }

    // ─── 解密缺少 IV 必须显式失败 ─────────────────────────────────────────

    public function testDecryptWithoutExplicitIvThrows(): void
    {
        foreach ([Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR] as $mode) {
            $key = substr(hash('sha256', 'missing-iv-' . $mode), 0, 32);
            $ivByte = substr(hash('sha256', $mode), 0, 2);
            $encOptions = (new Sm4Options())->setMode($mode)->setIv(str_repeat($ivByte, 16));
            $ciphertext = Sm4::encrypt('secret', $key, $encOptions);

            try {
                // 新建 options 且未设置 IV：必须拒绝而不是随机生成 IV 返回乱码
                Sm4::decrypt($ciphertext, $key, (new Sm4Options())->setMode($mode));
                $this->fail("Expected InvalidKeyException for mode {$mode}");
            } catch (InvalidKeyException $e) {
                $this->assertStringContainsString('IV is required', $e->getMessage());
            }
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CtrRejectsCounterWrapAndAcceptsLastAvailableCounter(): void
    {
        $key = str_repeat('ab', 16);
        $maxIv = str_repeat('ff', 16);

        $maxCounterOptions = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($maxIv);
        $ciphertext = Sm4::encrypt(str_repeat('x', 16), $key, $maxCounterOptions);
        $this->assertSame(str_repeat('x', 16), Sm4::decrypt($ciphertext, $key, $maxCounterOptions));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('counter would wrap');
        Sm4::encrypt(str_repeat('x', 17), $key, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($maxIv));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CtrChecksCounterWrapDuringDecryptionAndAtExactBoundary(): void
    {
        $key = bin2hex(random_bytes(16));
        $iv = str_repeat('ff', 15) . 'fe';
        $options = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv);

        $ciphertext = Sm4::encrypt(str_repeat('x', 32), $key, $options);
        $this->assertSame(str_repeat('x', 32), Sm4::decrypt($ciphertext, $key, $options));

        try {
            Sm4::encrypt(str_repeat('x', 33), $key, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv));
            $this->fail('Expected encryption to reject counter wrap');
        } catch (InvalidKeyException $exception) {
            $this->assertStringContainsString('counter would wrap', $exception->getMessage());
        }

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('counter would wrap');
        Sm4::decrypt(str_repeat('00', 17), $key, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv(str_repeat('ff', 16)));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4FeedbackModesRejectReusedKeyIvAcrossCfbAndOfb(): void
    {
        $key = str_repeat('ab', 16);
        $iv = str_repeat('12', 16);
        $cfb = (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv);
        $ciphertext = Sm4::encrypt('first message', $key, $cfb);
        $this->assertSame('first message', Sm4::decrypt($ciphertext, $key, $cfb));

        try {
            Sm4::encrypt('second message', $key, (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv));
            $this->fail('CFB must reject a reused IV under one key');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('IV reuse detected', $exception->getMessage());
        }

        $freshIv = str_repeat('13', 16);
        $freshCfb = (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($freshIv);
        $freshCiphertext = Sm4::encrypt('second message', $key, $freshCfb);
        $this->assertSame('second message', Sm4::decrypt($freshCiphertext, $key, $freshCfb));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4FeedbackModesUseSharedBinaryIvTracker(): void
    {
        $claims = [];
        Sm4::setFeedbackIvTracker(new class ($claims) implements Sm4FeedbackIvTrackerInterface {
            /** @var list<array{key: string, iv: string}> */
            public array $claims;

            /** @param list<array{key: string, iv: string}> $claims */
            public function __construct(array &$claims)
            {
                $this->claims = &$claims;
            }

            public function claim(string $key, string $iv): bool
            {
                $this->claims[] = ['key' => $key, 'iv' => $iv];
                return true;
            }
        });

        $keyHex = str_repeat('ab', 16);
        $ivHex = str_repeat('12', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($ivHex);
        $ciphertext = Sm4::encrypt('tracked', $keyHex, $options);
        $this->assertSame('tracked', Sm4::decrypt($ciphertext, $keyHex, $options));
        $this->assertSame([[
            'key' => hex2bin($keyHex),
            'iv' => hex2bin($ivHex),
        ]], $claims);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CbcRejectsReusedExplicitKeyIvPair(): void
    {
        $key = str_repeat('ab', 16);
        $iv = str_repeat('12', 16);
        $makeOptions = fn (): Sm4Options => (new Sm4Options())
            ->setMode(Sm4::MODE_CBC)
            ->setIv($iv);

        Sm4::encrypt('first message', $key, $makeOptions());

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('SM4-CBC IV reuse detected');
        Sm4::encrypt('second message', $key, $makeOptions());
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CbcUsesSharedFeedbackIvTracker(): void
    {
        $claims = [];
        Sm4::setFeedbackIvTracker(new class ($claims) implements Sm4FeedbackIvTrackerInterface {
            /** @var list<array{key: string, iv: string}> */
            public array $claims;

            /** @param list<array{key: string, iv: string}> $claims */
            public function __construct(array &$claims)
            {
                $this->claims = &$claims;
            }

            public function claim(string $key, string $iv): bool
            {
                $this->claims[] = ['key' => $key, 'iv' => $iv];
                return true;
            }
        });

        $keyHex = str_repeat('ab', 16);
        $ivHex = str_repeat('12', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setIv($ivHex);
        Sm4::encrypt('tracked CBC', $keyHex, $options);

        $this->assertSame([[
            'key' => hex2bin($keyHex),
            'iv' => hex2bin($ivHex),
        ]], $claims);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4StreamModesRequireSeparateKeys(): void
    {
        $iv = str_repeat('00', 16);
        $options = static fn (string $mode, string $counter): Sm4Options => (new Sm4Options())
            ->setMode($mode)
            ->setIv($counter);

        $ctrKey = str_repeat('ab', 16);
        Sm4::encrypt('first CTR block!', $ctrKey, $options(Sm4::MODE_CTR, $iv));
        try {
            Sm4::encrypt('first CFB block!', $ctrKey, $options(Sm4::MODE_CFB, $iv));
            $this->fail('CFB must not share a key with CTR');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('separate keys', $exception->getMessage());
        }

        $feedbackKey = str_repeat('cd', 16);
        Sm4::encrypt('first OFB block!', $feedbackKey, $options(Sm4::MODE_OFB, $iv));
        try {
            Sm4::encrypt(str_repeat('x', 16), $feedbackKey, $options(Sm4::MODE_CTR, $iv));
            $this->fail('CTR must not share a key with OFB');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('separate keys', $exception->getMessage());
        }

        $overlapKey = str_repeat('ef', 16);
        Sm4::encrypt(str_repeat('x', 32), $overlapKey, $options(Sm4::MODE_CTR, $iv));
        try {
            Sm4::encrypt('partial overlap', $overlapKey, $options(Sm4::MODE_OFB, str_repeat('00', 15) . '01'));
            $this->fail('OFB must not share a key with CTR');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('separate keys', $exception->getMessage());
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4StreamBlockTrackerReceivesCtrAndFeedbackRanges(): void
    {
        $claims = [];
        Sm4::setStreamBlockTracker(new class ($claims) implements Sm4StreamBlockTrackerInterface {
            /** @var list<array{key: string, firstBlock: string, count: int}> */
            public array $claims;

            /** @param list<array{key: string, firstBlock: string, count: int}> $claims */
            public function __construct(array &$claims)
            {
                $this->claims = &$claims;
            }

            public function claimRange(string $key, string $firstBlock, int $blockCount): bool
            {
                $this->claims[] = ['key' => $key, 'firstBlock' => $firstBlock, 'count' => $blockCount];
                return true;
            }
        });

        $keyHex = str_repeat('ab', 16);
        $feedbackKeyHex = str_repeat('cd', 16);
        $ctrIv = str_repeat('12', 16);
        $feedbackIv = str_repeat('34', 16);
        Sm4::encrypt(str_repeat('x', 17), $keyHex, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($ctrIv));
        Sm4::encrypt('feedback', $feedbackKeyHex, (new Sm4Options())->setMode(Sm4::MODE_OFB)->setIv($feedbackIv));

        $this->assertSame([
            ['key' => hex2bin($keyHex), 'firstBlock' => hex2bin($ctrIv), 'count' => 2],
            ['key' => hex2bin($feedbackKeyHex), 'firstBlock' => hex2bin($feedbackIv), 'count' => 1],
        ], $claims);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testUnifiedStreamTrackerTakesPrecedenceOverDedicatedTrackers(): void
    {
        $streamTracker = new class implements Sm4StreamBlockTrackerInterface {
            /** @var list<array{key: string, firstBlock: string, count: int}> */
            public array $claims = [];

            public function claimRange(string $key, string $firstBlock, int $blockCount): bool
            {
                $this->claims[] = ['key' => $key, 'firstBlock' => $firstBlock, 'count' => $blockCount];
                return true;
            }
        };
        $ctrTracker = new class implements Sm4CtrCounterTrackerInterface {
            /** @var list<array{key: string, counter: string, count: int}> */
            public array $claims = [];

            public function claimRange(string $key, string $initialCounter, int $blockCount): bool
            {
                $this->claims[] = ['key' => $key, 'counter' => $initialCounter, 'count' => $blockCount];
                return true;
            }
        };
        $feedbackTracker = new class implements Sm4FeedbackIvTrackerInterface {
            /** @var list<array{key: string, iv: string}> */
            public array $claims = [];

            public function claim(string $key, string $iv): bool
            {
                $this->claims[] = ['key' => $key, 'iv' => $iv];
                return true;
            }
        };
        Sm4::setStreamBlockTracker($streamTracker);
        Sm4::setCtrCounterTracker($ctrTracker);
        Sm4::setFeedbackIvTracker($feedbackTracker);

        Sm4::encrypt('ctr payload', str_repeat('12', 16), (new Sm4Options())
            ->setMode(Sm4::MODE_CTR)->setIv(str_repeat('00', 16)));
        Sm4::encrypt('ofb payload', str_repeat('34', 16), (new Sm4Options())
            ->setMode(Sm4::MODE_OFB)->setIv(str_repeat('56', 16)));

        self::assertCount(2, $streamTracker->claims);
        self::assertSame([], $ctrTracker->claims);
        self::assertSame([], $feedbackTracker->claims);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CtrRejectsOverlappingCounterRangesButAllowsDisjointRanges(): void
    {
        $key = str_repeat('ab', 16);
        $start = str_repeat('00', 15) . '00';
        $options = static fn (string $iv): Sm4Options => (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv);

        $first = Sm4::encrypt(str_repeat('A', 32), $key, $options($start));
        $this->assertSame(str_repeat('A', 32), Sm4::decrypt($first, $key, $options($start)));

        try {
            // Start at block 1, which overlaps the second counter block used above.
            Sm4::encrypt('B', $key, $options(str_repeat('00', 15) . '01'));
            $this->fail('Overlapping CTR counter ranges under one key must be rejected');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('counter range reuse detected', $exception->getMessage());
        }

        $disjoint = Sm4::encrypt('C', $key, $options(str_repeat('00', 15) . '02'));
        $this->assertSame('C', Sm4::decrypt($disjoint, $key, $options(str_repeat('00', 15) . '02')));
        $otherKey = str_repeat('cd', 16);
        $this->assertNotEmpty(Sm4::encrypt('D', $otherKey, $options($start)));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CtrCounterRangeIndexHandlesReverseOrderedClaims(): void
    {
        $claim = new \ReflectionMethod(Sm4::class, 'claimStreamBlockRange');
        $key = random_bytes(16);

        // Descending, disjoint ranges are a worst case for a linear history scan.
        for ($counter = 4095; $counter >= 0; $counter--) {
            $claim->invoke(null, $key, str_repeat("\0", 12) . pack('N', $counter * 2), 1, Sm4::MODE_CTR);
        }

        // Odd counters remain available between the claimed even counters.
        $claim->invoke(null, $key, str_repeat("\0", 12) . pack('N', 8191), 1, Sm4::MODE_CTR);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('counter range reuse detected');
        $claim->invoke(null, $key, str_repeat("\0", 12) . pack('N', 8190), 2, Sm4::MODE_CTR);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CtrSharedTrackerReceivesBinaryCounterRanges(): void
    {
        $claims = [];
        Sm4::setCtrCounterTracker(new class ($claims) implements Sm4CtrCounterTrackerInterface {
            /** @var list<array{key: string, counter: string, count: int}> */
            public array $claims;

            /** @param list<array{key: string, counter: string, count: int}> $claims */
            public function __construct(array &$claims)
            {
                $this->claims = &$claims;
            }

            public function claimRange(string $key, string $initialCounter, int $blockCount): bool
            {
                $this->claims[] = ['key' => $key, 'counter' => $initialCounter, 'count' => $blockCount];
                return true;
            }
        });

        $keyHex = str_repeat('ab', 16);
        $keyBin = hex2bin($keyHex);
        $counter = hex2bin(str_repeat('12', 16));
        self::assertIsString($keyBin);
        self::assertIsString($counter);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv(bin2hex($counter));
        $ciphertext = Sm4::encrypt(str_repeat('x', 17), $keyHex, $options);

        $this->assertNotEmpty($ciphertext);
        $this->assertSame(str_repeat('x', 17), Sm4::decrypt($ciphertext, $keyHex, $options));
        $this->assertSame([['key' => $keyBin, 'counter' => $counter, 'count' => 2]], $claims);
        $this->assertSame(
            0,
            (new \ReflectionProperty(Sm4::class, 'trackedCtrCounterRangeCount'))->getValue(),
            'A dedicated shared CTR tracker must replace the bounded local range history'
        );
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm4CtrRejectedSharedTrackerClaimFailsClosedAndLocksConfiguration(): void
    {
        Sm4::setCtrCounterTracker(new class () implements Sm4CtrCounterTrackerInterface {
            public function claimRange(string $key, string $initialCounter, int $blockCount): bool
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
            $this->fail('Rejected shared CTR counter-range claims must fail encryption');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('counter range reuse detected', $exception->getMessage());
        }

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('counter tracker cannot be changed');
        Sm4::setCtrCounterTracker(null);
    }

    public function testSm4OptionsRejectsGcmIvWithTrailingNewline(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('a', 23) . "\n");
    }

    public function testSm4RejectsTrailingNewlineInHexKeyBeforeDecoding(): void
    {
        set_error_handler(static function (int $severity, string $message): bool {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            $this->expectException(InvalidKeyException::class);
            $this->expectExceptionMessage('Key must be 128 bits');
            Sm4::encrypt('payload', str_repeat('ab', 16) . "\n", (new Sm4Options())->setMode(Sm4::MODE_CBC));
        } finally {
            restore_error_handler();
        }
    }

    public function testSm4RejectsTrailingNewlineInHexCiphertextBeforeDecoding(): void
    {
        set_error_handler(static function (int $severity, string $message): bool {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            $this->expectException(InvalidKeyException::class);
            $this->expectExceptionMessage('Invalid ciphertext hex');
            Sm4::decrypt(
                str_repeat('a', 31) . "\n",
                str_repeat('ab', 16),
                (new Sm4Options())->setMode(Sm4::MODE_CBC)->setIv(str_repeat('00', 16))
            );
        } finally {
            restore_error_handler();
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmDecryptWithoutExplicitIvThrows(): void
    {
        $key = str_repeat('ef', 16);
        $encOptions = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(bin2hex(random_bytes(12)));
        $ciphertext = Sm4::encrypt('secret', $key, $encOptions);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('IV is required');
        Sm4::decrypt($ciphertext, $key, (new Sm4Options())->setMode(Sm4::MODE_GCM));
    }

    public function testSelfContainedCbcDecryptStillWorksWithoutOptions(): void
    {
        $key = str_repeat('9a', 16);
        $ciphertext = Sm4::encrypt('self contained', $key);
        $this->assertSame('self contained', Sm4::decrypt($ciphertext, $key));
    }

    public function testTamperedSelfContainedGcmMarkerIsRejected(): void
    {
        $key = str_repeat('af', 16);
        $ciphertext = Sm4::encrypt(str_repeat('x', 13), $key);
        $ciphertext[0] = $ciphertext[0] === '0' ? '1' : '0';

        $this->expectException(InvalidKeyException::class);
        Sm4::decrypt($ciphertext, $key);
    }

    public function testStructuredGcmPayloadCannotDowngradeToCbc(): void
    {
        $key = str_repeat('ae', 16);
        $payload = Sm4::encryptPayload(str_repeat('x', 16), $key);
        $payload['mode'] = Sm4::MODE_CBC;
        $payload['iv'] = str_repeat('00', 16);
        $payload['padding'] = 'none';

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('does not match expected mode');
        Sm4::decryptPayload($payload, $key);
    }

    public function testStructuredPayloadChecksTrustedModeBeforeUntrustedModeSideEffects(): void
    {
        $key = str_repeat('ae', 16);
        $payload = [
            'version' => 1,
            'algorithm' => 'SM4',
            'mode' => Sm4::MODE_ECB,
        ];
        set_error_handler(static function (int $severity, string $message): never {
            throw new \RuntimeException($message);
        });

        try {
            $this->expectException(InvalidKeyException::class);
            $this->expectExceptionMessage('does not match expected mode');
            Sm4::decryptPayload($payload, $key);
        } finally {
            restore_error_handler();
        }
    }

    public function testStructuredPayloadRejectsIso10126BeforeDeprecationSideEffect(): void
    {
        $key = str_repeat('ad', 16);
        $payload = [
            'version' => 1,
            'algorithm' => 'SM4',
            'mode' => Sm4::MODE_CBC,
            'iv' => str_repeat('00', 16),
            'padding' => 'iso10126',
            'ciphertext' => '',
        ];
        set_error_handler(static function (int $severity, string $message): never {
            throw new \RuntimeException($message);
        });

        try {
            $this->expectException(InvalidKeyException::class);
            $this->expectExceptionMessage('ISO 10126 padding is unverifiable');
            Sm4::decryptPayload($payload, $key, Sm4::MODE_CBC);
        } finally {
            restore_error_handler();
        }
    }

    public function testStructuredGcmPayloadRejectsTagLengthDowngrade(): void
    {
        $key = str_repeat('af', 16);
        $payload = Sm4::encryptPayload('authenticated', $key);
        $payload['tagLength'] = 12;
        $tag = $payload['tag'] ?? '';
        $this->assertSame(32, strlen($tag));
        $payload['tag'] = substr($tag, 0, 24);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('does not match expected length');
        Sm4::decryptPayload($payload, $key);
    }

    public function testStructuredGcmPayloadRequiresExpectedAadContext(): void
    {
        $key = str_repeat('ac', 16);
        $payload = Sm4::encryptPayload('tenant A data', $key, (new Sm4Options())->setAad('tenant A'));
        $this->assertSame('tenant A data', Sm4::decryptPayload($payload, $key, Sm4::MODE_GCM, 16, 'tenant A'));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('AAD does not match expected context');
        Sm4::decryptPayload($payload, $key, Sm4::MODE_GCM, 16, 'tenant B');
    }

    public function testStructuredGcmPayloadRejectsTagFieldLengthMismatch(): void
    {
        $key = str_repeat('af', 16);
        $payload = Sm4::encryptPayload('authenticated', $key);
        $tag = $payload['tag'] ?? '';
        $this->assertSame(32, strlen($tag));
        $payload['tag'] = substr($tag, 2);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('tag length mismatch');
        Sm4::decryptPayload($payload, $key);
    }

    public function testRoundTripReusingSameOptionsObjectStillWorks(): void
    {
        $key = str_repeat('bc', 16);
        $options = (new Sm4Options())->setIv(str_repeat('22', 16));

        $ciphertext = Sm4::encrypt('roundtrip', $key, $options);
        $this->assertSame('roundtrip', Sm4::decrypt($ciphertext, $key, $options));
    }

    // ─── SM2 用户 ID 长度限制 (GM/T 0003-2012 附录 A) ─────────────────────

    public function testUserIdLongerThanEntlLimitIsRejected(): void
    {
        $method = new \ReflectionMethod(Sm2::class, 'getUserIdHash');
        $method->setAccessible(true);
        $x = str_pad('1', 64, '0');
        $y = str_pad('2', 64, '0');

        // 8192 字节 = 65536 bit > ENTL 上限
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('ENTL is a 16-bit field');
        $method->invoke(null, str_repeat('u', 8192), $x, $y);
    }

    public function testUserIdAtEntlLimitIsAccepted(): void
    {
        $method = new \ReflectionMethod(Sm2::class, 'getUserIdHash');
        $method->setAccessible(true);
        $x = str_pad('1', 64, '0');
        $y = str_pad('2', 64, '0');

        // 8191 字节 = 65528 bit，恰好在上限内；ENTL 前缀必须是 4 个 hex 字符
        $hash = $method->invoke(null, str_repeat('u', 8191), $x, $y);
        if (!is_string($hash)) {
            $this->fail('getUserIdHash must return a string');
        }
        $this->assertSame('fff8', substr($hash, 0, 4));
        $this->assertMatchesRegularExpression('/^[0-9a-fA-F]{4}[0-9a-fA-F]+$/', $hash);
    }

    public function testVerifyReturnsFalseForUserIdBeyondEntlLimit(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $message = 'verify invalid user id';
        $signature = Sm2::doSignature($message, $keypair->getPrivateKey());
        $options = (new SignatureOptions())->setUserId(str_repeat('u', 8192));

        $this->assertFalse(Sm2::doVerifySignature($message, $signature, $keypair->getPublicKey(), $options));
        $this->assertFalse(SmCrypto::verify($message, $signature, $keypair->getPublicKey(), $options));
    }

    public function testSignRejectsUserIdBeyondEntlLimit(): void
    {
        $keypair = Sm2::generateKeyPairHex();
        $options = (new SignatureOptions())->setUserId(str_repeat('u', 8192));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('16-bit ENTL limit');
        Sm2::doSignature('message', $keypair->getPrivateKey(), $options);
    }

    // ─── GCM IV 重用检测 ──────────────────────────────────────────────────

    public function testGcmIvReuseDetectedByDefault(): void
    {
        $key = str_repeat('77', 16);
        $iv = bin2hex(random_bytes(12));
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv);

        Sm4::enableGcmIvTracking();
        Sm4::encrypt('first', $key, $options);
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('GCM IV reuse detected');
        Sm4::encrypt('second', $key, $options);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmIvReuseDetectionNormalizesHexCase(): void
    {
        $key = str_repeat('ab', 16);
        $iv = 'abcdef0123456789abcdef01';
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv);

        Sm4::enableGcmIvTracking();
        Sm4::encrypt('first', $key, $options);
        $options->setIv(strtoupper($iv));
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('GCM IV reuse detected');
        Sm4::encrypt('second', strtoupper($key), $options);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRejectedGcmIvDoesNotLockTagLengthProfile(): void
    {
        $key = random_bytes(16);
        $rejectedIv = random_bytes(12);
        $usedIvPairs = new \ReflectionProperty(Gcm::class, 'usedIvPairs');
        $usedIvPairs->setValue(null, [hash('sha256', $key . $rejectedIv) => true]);

        try {
            Gcm::fromKey($key)->encrypt('rejected', $rejectedIv, '', 12);
            $this->fail('A previously claimed GCM IV must be rejected');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('GCM IV reuse detected', $exception->getMessage());
        }

        Gcm::setTagLengthTracker(new class () implements GcmTagLengthTrackerInterface {
            public function claimTagLength(string $key, int $tagLength): bool
            {
                return true;
            }
        });

        $result = Gcm::fromKey($key)->encrypt('accepted', random_bytes(12), '', 16);
        $this->assertSame(16, strlen($result['tag']));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRejectedGcmTrackerClaimReleasesTagLengthReservation(): void
    {
        $tracker = new class () implements GcmIvTrackerInterface {
            private int $claims = 0;

            public function claim(string $key, string $iv): bool
            {
                return ++$this->claims > 1;
            }
        };
        Gcm::setIvTracker($tracker);
        $key = random_bytes(16);

        try {
            Gcm::fromKey($key)->encrypt('rejected', random_bytes(12), '', 12);
            $this->fail('The first GCM tracker claim must be rejected');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('tracker rejected the claim', $exception->getMessage());
        }

        $result = Gcm::fromKey($key)->encrypt('accepted', random_bytes(12), '', 16);
        $this->assertSame(16, strlen($result['tag']));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRejectedGcmTrackerClaimStillLocksTrackerConfiguration(): void
    {
        Gcm::setIvTracker(new class () implements GcmIvTrackerInterface {
            public function claim(string $key, string $iv): bool
            {
                return false;
            }
        });

        try {
            Gcm::fromKey(random_bytes(16))->encrypt('rejected', random_bytes(12));
            $this->fail('A rejected shared tracker claim must fail encryption');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('tracker rejected the claim', $exception->getMessage());
        }

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tracker cannot be changed');
        Gcm::setIvTracker(null);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmTrackerExceptionFailsClosedBeforeEncryption(): void
    {
        Gcm::setIvTracker(new class () implements GcmIvTrackerInterface {
            public function claim(string $key, string $iv): bool
            {
                throw new \RuntimeException('shared GCM store unavailable');
            }
        });

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('shared GCM store unavailable');
        Gcm::fromKey(random_bytes(16))->encrypt('must not encrypt', random_bytes(12));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testConcurrentGcmClaimsCannotSelectDifferentTagLengths(): void
    {
        $this->configureFiberStackSize();
        Gcm::setIvTracker(new class () implements GcmIvTrackerInterface {
            public function claim(string $key, string $iv): bool
            {
                \Fiber::suspend();
                return true;
            }
        });

        $key = random_bytes(16);
        $successes = [];
        $failures = [];
        $runEncryption = static function (int $tagLength, string $iv) use ($key, &$successes, &$failures): void {
            try {
                $successes[] = Gcm::fromKey($key)->encrypt('fiber', $iv, '', $tagLength);
            } catch (CryptoException $exception) {
                $failures[] = $exception->getMessage();
            }
        };

        $shortTagFiber = new \Fiber(static fn () => $runEncryption(12, random_bytes(12)));
        $fullTagFiber = new \Fiber(static fn () => $runEncryption(16, random_bytes(12)));
        $shortTagFiber->start();
        $fullTagFiber->start();
        if ($shortTagFiber->isSuspended()) {
            $shortTagFiber->resume();
        }
        if ($fullTagFiber->isSuspended()) {
            $fullTagFiber->resume();
        }

        $this->assertCount(1, $successes);
        $this->assertCount(1, $failures);
        $this->assertStringContainsString('tag length must remain fixed', $failures[0]);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testConcurrentGcmClaimsWithSameTagLengthSucceed(): void
    {
        $this->configureFiberStackSize();
        Gcm::setIvTracker(new class () implements GcmIvTrackerInterface {
            public function claim(string $key, string $iv): bool
            {
                \Fiber::suspend();
                return true;
            }
        });

        $key = random_bytes(16);
        $successes = [];
        $runEncryption = static function (string $iv) use ($key, &$successes): void {
            $successes[] = Gcm::fromKey($key)->encrypt('fiber', $iv, '', 16);
        };
        $first = new \Fiber(static fn () => $runEncryption(random_bytes(12)));
        $second = new \Fiber(static fn () => $runEncryption(random_bytes(12)));
        $first->start();
        $second->start();
        $first->resume();
        $second->resume();

        $this->assertCount(2, $successes);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testLowLevelGcmRejectsDuplicateKeyIvAcrossContexts(): void
    {
        $key = random_bytes(16);
        $iv = random_bytes(12);
        Gcm::fromKey($key)->encrypt('first', $iv);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('GCM IV reuse detected');
        Gcm::fromKey($key)->encrypt('second', $iv);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testPublicGcmFacadeBridgeEnforcesIvReuseTracking(): void
    {
        $key = random_bytes(16);
        $iv = random_bytes(12);
        $gcm = Gcm::fromKey($key);
        $gcm->encryptFromFacade('first', $iv);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('GCM IV reuse detected');
        $gcm->encryptFromFacade('second', $iv);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGeneratedGcmIvCannotBeReusedThroughLowLevelEncryption(): void
    {
        $key = random_bytes(16);
        $gcm = Gcm::fromKey($key);
        $generated = $gcm->encryptWithRandomIvFromFacade('first');

        $this->assertSame(16, strlen($generated['iv']));
        $this->assertSame('SM4R', substr($generated['iv'], 0, 4));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('reserved internally generated IV namespace');
        $gcm->encrypt('second', $generated['iv']);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testFacadeGeneratedGcmIvUsesReservedNamespaceAndRoundTrips(): void
    {
        $key = random_bytes(16);
        $options = new Sm4Options();
        $ciphertext = Sm4::encrypt('reserved nonce format', bin2hex($key), $options);
        $iv = hex2bin($options->getIv());
        $this->assertIsString($iv);
        $this->assertSame(16, strlen($iv));
        $this->assertSame('SM4R', substr($iv, 0, 4));

        $this->assertSame('reserved nonce format', Sm4::decrypt($ciphertext, bin2hex($key), $options));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('reserved internally generated IV namespace');
        Gcm::fromKey($key)->encrypt('reused through low-level API', $iv);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testLegacySelfContainedGcmV1PayloadRemainsDecryptable(): void
    {
        $key = random_bytes(16);
        $iv = random_bytes(12);
        $result = Gcm::fromKey($key)->encrypt('legacy self-contained GCM', $iv);
        $payload = '534d3447434d31' . bin2hex($iv)
            . bin2hex($result['ciphertext']) . bin2hex($result['tag']);

        $this->assertSame('legacy self-contained GCM', Sm4::decrypt($payload, bin2hex($key)));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testLowLevelAndFacadeShareExplicitIvReuseProtection(): void
    {
        $key = random_bytes(16);
        $iv = random_bytes(12);
        Gcm::fromKey($key)->encrypt('direct', $iv);

        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(bin2hex($iv));
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('GCM IV reuse detected');
        Sm4::encrypt('facade', bin2hex($key), $options);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testConfiguredGcmIvTrackerClaimsExplicitPairs(): void
    {
        $key = str_repeat('ab', 16);
        $iv = 'abcdef0123456789abcdef01';
        $tracker = new class () implements GcmIvTrackerInterface {
            /** @var array<string, true> */
            private array $seen = [];

            public function claim(string $key, string $iv): bool
            {
                $id = hash('sha256', $key . $iv);
                if (isset($this->seen[$id])) {
                    return false;
                }
                $this->seen[$id] = true;
                return true;
            }
        };
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv);

        Sm4::setGcmIvTracker($tracker);
        Sm4::encrypt('first', $key, $options);
        $options->setIv(strtoupper($iv));
        try {
            Sm4::encrypt('second', strtoupper($key), $options);
            $this->fail('The configured tracker must reject a repeated key and IV');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('GCM IV reuse detected', $exception->getMessage());
        }

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tracker cannot be changed');
        Sm4::setGcmIvTracker(null);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testConfiguredGcmIvTrackerClaimsGeneratedIvs(): void
    {
        $claims = new GcmTrackerClaimCounter();
        $tracker = new class ($claims) implements GcmIvTrackerInterface {
            /** @var array<string, true> */
            private array $seen = [];

            public function __construct(private GcmTrackerClaimCounter $claims)
            {
            }

            public function claim(string $key, string $iv): bool
            {
                $id = hash('sha256', $key . $iv);
                if (isset($this->seen[$id])) {
                    return false;
                }
                $this->seen[$id] = true;
                $this->claims->count++;
                return true;
            }
        };

        Sm4::setGcmIvTracker($tracker);
        $options = new Sm4Options();
        $options->getIv();
        Sm4::encrypt('first', str_repeat('ab', 16), $options);
        Sm4::encrypt('second', str_repeat('ab', 16), $options);
        $key = hex2bin(str_repeat('ab', 16));
        self::assertIsString($key);
        Gcm::fromKey($key)->encrypt('direct GCM', random_bytes(12));

        $this->assertSame(3, $claims->count);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSharedGcmTagTrackerAvoidsLocalProfileCapacity(): void
    {
        $tagProfiles = new GcmTagProfileRegistry();
        Gcm::setIvTracker(new class () implements GcmIvTrackerInterface {
            public function claim(string $key, string $iv): bool
            {
                return true;
            }
        });
        Gcm::setTagLengthTracker(new class ($tagProfiles) implements GcmTagLengthTrackerInterface {
            public function __construct(private GcmTagProfileRegistry $state)
            {
            }

            public function claimTagLength(string $key, int $tagLength): bool
            {
                $id = hash('sha256', $key);
                if (isset($this->state->profiles[$id])) {
                    return $this->state->profiles[$id] === $tagLength;
                }
                $this->state->profiles[$id] = $tagLength;
                return true;
            }
        });

        $profiles = [];
        for ($i = 0; $i < 65536; $i++) {
            $profiles[hash('sha256', 'existing-key-' . $i)] = 16;
        }
        $localProfiles = new \ReflectionProperty(Gcm::class, 'tagLengthByKey');
        $localProfiles->setValue(null, $profiles);

        $key = random_bytes(16);
        $iv = random_bytes(12);
        $gcm = Gcm::fromKey($key);
        $result = $gcm->encrypt('shared profile path', $iv);

        $this->assertSame('shared profile path', $gcm->decrypt($result['ciphertext'], $result['tag'], $iv));
        $storedProfiles = $localProfiles->getValue();
        self::assertIsArray($storedProfiles);
        $this->assertCount(65536, $storedProfiles);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testFailedGcmAuthenticationDoesNotClaimSharedTagProfile(): void
    {
        $tagProfiles = new GcmTagProfileRegistry();
        Gcm::setTagLengthTracker(new class ($tagProfiles) implements GcmTagLengthTrackerInterface {
            public function __construct(private GcmTagProfileRegistry $state)
            {
            }

            public function claimTagLength(string $key, int $tagLength): bool
            {
                $id = hash('sha256', $key);
                if (isset($this->state->profiles[$id])) {
                    return $this->state->profiles[$id] === $tagLength;
                }
                $this->state->profiles[$id] = $tagLength;
                return true;
            }
        });

        $key = random_bytes(16);
        try {
            Gcm::fromKey($key)->decrypt(str_repeat("\0", 16), str_repeat("\0", 12), random_bytes(12), '', 12);
            $this->fail('Invalid GCM authentication must fail');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('authentication tag mismatch', $exception->getMessage());
        }
        $this->assertSame([], $tagProfiles->profiles);

        $result = Gcm::fromKey($key)->encrypt('valid profile initialization', random_bytes(12), '', 16);
        $this->assertSame(16, strlen($result['tag']));
        $this->assertSame([hash('sha256', $key) => 16], $tagProfiles->profiles);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmInvocationLimitCountsExplicitAndGeneratedIvsPerKey(): void
    {
        $key = str_repeat('cd', 16);
        $keyBin = hex2bin($key);
        self::assertIsString($keyBin);

        $maxInvocations = (new \ReflectionClass(Gcm::class))->getConstant('MAX_INVOCATIONS_PER_KEY');
        self::assertIsInt($maxInvocations);
        $counts = new \ReflectionProperty(Gcm::class, 'invocationCounts');
        $counts->setValue(null, [hash('sha256', $keyBin) => $maxInvocations - 2]);

        $explicit = (new Sm4Options())
            ->setMode(Sm4::MODE_GCM)
            ->setIv(bin2hex(random_bytes(12)));
        Sm4::encrypt('explicit IV', $key, $explicit);

        Gcm::fromKey($keyBin)->encrypt('direct GCM', random_bytes(12));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('per-key encryption limit reached');
        Sm4::encrypt('over limit', $key, new Sm4Options());
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmLocalInvocationCountersRejectExcessDistinctKeys(): void
    {
        $reflection = new \ReflectionClass(Gcm::class);
        $maxTrackedKeys = $reflection->getConstant('MAX_TRACKED_KEYS');
        self::assertIsInt($maxTrackedKeys);

        $counts = [];
        for ($i = 0; $i < $maxTrackedKeys; $i++) {
            $counts[hash('sha256', 'tracked-key-' . $i)] = 1;
        }
        $invocationCounts = new \ReflectionProperty(Gcm::class, 'invocationCounts');
        $invocationCounts->setValue(null, $counts);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('process-local key tracking table is full');
        Gcm::fromKey(random_bytes(16))->encrypt('new key', random_bytes(12));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSharedGcmTrackerDoesNotGrowProcessLocalKeyCounterTable(): void
    {
        $reflection = new \ReflectionClass(Gcm::class);
        $maxTrackedKeys = $reflection->getConstant('MAX_TRACKED_KEYS');
        self::assertIsInt($maxTrackedKeys);

        $counts = [];
        for ($i = 0; $i < $maxTrackedKeys; $i++) {
            $counts[hash('sha256', 'tracked-key-' . $i)] = 1;
        }
        $invocationCounts = new \ReflectionProperty(Gcm::class, 'invocationCounts');
        $invocationCounts->setValue(null, $counts);

        $tracker = new class () implements GcmIvTrackerInterface {
            public int $claims = 0;

            public function claim(string $key, string $iv): bool
            {
                $this->claims++;
                return true;
            }
        };
        Gcm::setIvTracker($tracker);

        $key = random_bytes(16);
        Gcm::fromKey($key)->encrypt('shared tracker', random_bytes(12));

        $localCounts = $invocationCounts->getValue();
        if (!is_array($localCounts)) {
            throw new \LogicException('GCM invocation counters must remain an array');
        }
        $this->assertSame(1, $tracker->claims);
        $this->assertCount($maxTrackedKeys, $localCounts);
        $this->assertArrayNotHasKey(hash('sha256', $key), $localCounts);
    }

    public function testOpenSslSm4DetectionIsCaseInsensitive(): void
    {
        $methods = array_map('strtolower', openssl_get_cipher_methods());
        $probe = @openssl_encrypt(
            str_repeat("\0", 16),
            'SM4-ECB',
            str_repeat("\0", 16),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );
        $operational = in_array('sm4-ecb', $methods, true) && is_string($probe) && strlen($probe) === 16;
        $this->assertSame($operational, Sm4::openSslSm4Available());
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testOpenSslAndPurePhpSm4BackendsMatchAcrossModes(): void
    {
        if (!Sm4::openSslSm4Available()) {
            $this->markTestSkipped('Native OpenSSL SM4 is unavailable on this platform');
        }

        $key = '0123456789abcdeffedcba9876543210';
        $plaintext = hex2bin('00112233445566778899aabbccddeeff102030405060708090a0b0c0d0e0f001ff');
        self::assertIsString($plaintext);
        $backendFlag = new \ReflectionProperty(Sm4PurePhp::class, 'openSslSm4Available');
        $modeAvailability = new \ReflectionProperty(Sm4::class, 'openSslModeAvailability');
        $gcmBackendFlag = new \ReflectionProperty(Gcm::class, 'openSslGcmAvailable');
        $gcmProbe = new \ReflectionMethod(Gcm::class, 'openSslGcmAvailable');
        $nativeGcmAvailable = $gcmProbe->invoke(null);

        Sm4::setGcmIvTracker(new class () implements GcmIvTrackerInterface {
            public function claim(string $key, string $iv): bool
            {
                return true;
            }
        });

        $modes = [Sm4::MODE_ECB, Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR];
        if ($nativeGcmAvailable) {
            $modes[] = Sm4::MODE_GCM;
        }

        foreach ($modes as $mode) {
            $modeKey = substr(hash('sha256', $key . $mode), 0, 32);
            $pureOptions = (new Sm4Options())->setMode($mode);
            $nativeOptions = (new Sm4Options())->setMode($mode);
            if ($mode !== Sm4::MODE_ECB) {
                $ivLength = $mode === Sm4::MODE_GCM ? 12 : 16;
                $pureOptions->setIv(bin2hex(random_bytes($ivLength)));
                $nativeOptions->setIv(bin2hex(random_bytes($ivLength)));
            }

            // Reset per-mode dispatch caches as well as the primitive probe flag;
            // otherwise the first pure-PHP probe would pin every later call to PHP.
            $backendFlag->setValue(null, false);
            $modeAvailability->setValue(null, []);
            if ($mode === Sm4::MODE_GCM) {
                $gcmBackendFlag->setValue(null, false);
            }
            $pureCiphertext = Sm4::encrypt($plaintext, $modeKey, $pureOptions);
            $backendFlag->setValue(null, true);
            $modeAvailability->setValue(null, []);
            if ($mode === Sm4::MODE_GCM) {
                $gcmBackendFlag->setValue(null, true);
            }
            $nativeCiphertext = Sm4::encrypt($plaintext, $modeKey, $nativeOptions);

            $backendFlag->setValue(null, false);
            $modeAvailability->setValue(null, []);
            if ($mode === Sm4::MODE_GCM) {
                $gcmBackendFlag->setValue(null, false);
            }
            $purePlaintext = Sm4::decrypt($nativeCiphertext, $modeKey, clone $nativeOptions);
            $backendFlag->setValue(null, true);
            $modeAvailability->setValue(null, []);
            if ($mode === Sm4::MODE_GCM) {
                $gcmBackendFlag->setValue(null, true);
            }
            $nativePlaintext = Sm4::decrypt($pureCiphertext, $modeKey, clone $pureOptions);
            $this->assertSame($plaintext, $purePlaintext, $mode . ' pure-PHP decryption mismatch');
            $this->assertSame($plaintext, $nativePlaintext, $mode . ' OpenSSL decryption mismatch');
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testPurePhpEcbDecryptAcceptsEmptyNoPaddingCiphertext(): void
    {
        $backendFlag = new \ReflectionProperty(Sm4PurePhp::class, 'openSslSm4Available');
        $modeAvailability = new \ReflectionProperty(Sm4::class, 'openSslModeAvailability');
        $backendFlag->setValue(null, false);
        $modeAvailability->setValue(null, []);

        $key = '0123456789abcdeffedcba9876543210';
        $options = (new Sm4Options())->setMode(Sm4::MODE_ECB)->setPadding('none');
        $ciphertext = Sm4::encrypt('', $key, $options);

        $this->assertSame('', $ciphertext);
        $this->assertSame('', Sm4::decrypt($ciphertext, $key, $options));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmFacadeKeyCacheRespectsEightEntryLimit(): void
    {
        $cache = new \ReflectionProperty(Sm4::class, 'gcmCache');
        $this->assertSame([], $cache->getValue());

        for ($i = 0; $i < 10; $i++) {
            Sm4::encrypt('cache bound', str_pad(dechex($i + 1), 32, '0', STR_PAD_LEFT));
        }

        $cachedContexts = $cache->getValue();
        $this->assertCount(8, $cachedContexts);
    }

    public function testSm2KeyConfirmationDirectionsMatchGmtProtocol(): void
    {
        $alice = Sm2::generateKeyPairHex();
        $aliceEphemeral = Sm2::generateKeyPairHex();
        $bob = Sm2::generateKeyPairHex();
        $bobEphemeral = Sm2::generateKeyPairHex();

        $aliceResult = KeyExchange::initiatorComputeKeyWithConfirmation(
            $alice->getPrivateKey(),
            $aliceEphemeral->getPrivateKey(),
            $bob->getPublicKey(),
            $bobEphemeral->getPublicKey(),
            16
        );
        $bobResult = KeyExchange::responderComputeKeyWithConfirmation(
            $bob->getPrivateKey(),
            $bobEphemeral->getPrivateKey(),
            $alice->getPublicKey(),
            $aliceEphemeral->getPublicKey(),
            16
        );

        $this->assertSame($aliceResult['key'], $bobResult['key']);
        $this->assertSame($aliceResult['s1'], $bobResult['sb']);
        $this->assertSame($aliceResult['sa'], $bobResult['s2']);
        $this->assertNotSame($aliceResult['s1'], $aliceResult['sa']);
        $this->assertTrue(KeyExchange::verifyResponderConfirmationForInitiator($aliceResult['s1'], $bobResult['sb']));
        $this->assertTrue(KeyExchange::verifyInitiatorConfirmationForResponder($bobResult['s2'], $aliceResult['sa']));
        $this->assertFalse(KeyExchange::verifyResponderConfirmationForInitiator($aliceResult['s1'], $bobResult['s2']));
        $this->assertFalse(KeyExchange::verifyInitiatorConfirmationForResponder($bobResult['s2'], $aliceResult['s1']));
        $this->assertFalse(KeyExchange::verifyResponderConfirmationForInitiator($aliceResult['s1'], 'not-hex'));
    }

    public function testSm2PointMultiplicationRejectsTrailingNewlineInScalars(): void
    {
        foreach ([
            static fn () => Sm2::pointMultiplyPublic("1\n"),
            static fn () => Sm2::pointMultiplyPublic('1', "1\n"),
        ] as $operation) {
            try {
                $operation();
                $this->fail('SM2 multiplication scalars must reject trailing newlines');
            } catch (InvalidKeyException $exception) {
                $this->assertInstanceOf(InvalidKeyException::class, $exception);
            }
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm2VariableBasePrecomputationCacheHonorsCapacity(): void
    {
        $cache = new \ReflectionProperty(Sm2::class, 'windowTableCache');
        $cache->setValue(null, array_fill_keys(array_map(
            static fn (int $i): string => sprintf('cached-point-%02d', $i),
            range(0, 15)
        ), []));

        $point = Sm2::getPublicKey(str_pad('2', 64, '0', STR_PAD_LEFT));
        $this->assertSame($point, Sm2::pointMultiplyPublic($point, '1'));
        $cacheValue = $cache->getValue();
        $this->assertIsArray($cacheValue);
        $this->assertCount(16, $cacheValue);
    }

    public function testSm2CompressedKeyRejectsCoordinateWithTrailingNewline(): void
    {
        $this->expectException(CryptoException::class);
        Sm2::decompressPublicKey(str_repeat('a', 63) . "a\n", 0x02);
    }

    public function testSm2CurveCheckRejectsPublicKeyWithTrailingNewline(): void
    {
        $publicKey = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $this->assertTrue(Sm2::isOnCurve($publicKey));
        $this->assertFalse(Sm2::isOnCurve($publicKey . "\n"));
    }

    public function testSm2InternalPointParserRejectsTrailingNewline(): void
    {
        $publicKey = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $parsePoint = new \ReflectionMethod(Sm2::class, 'parsePoint');

        $this->assertNull($parsePoint->invoke(null, $publicKey . "\n"));
    }

    public function testSm2KeyConfirmationRejectsTrailingNewline(): void
    {
        $malformed = str_repeat('a', 64) . "\n";
        $this->assertFalse(KeyExchange::verifyResponderConfirmationForInitiator($malformed, $malformed));
        $this->assertFalse(KeyExchange::verifyInitiatorConfirmationForResponder($malformed, $malformed));
    }

    public function testSm2KeyExchangeAcceptsMaximumEphemeralScalar(): void
    {
        $n = gmp_init('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);
        $rA = str_pad(gmp_strval(gmp_sub($n, 1), 16), 64, '0', STR_PAD_LEFT);
        $alice = Sm2::generateKeyPairHex();
        $bob = Sm2::generateKeyPairHex();
        $bobEphemeral = KeyExchange::generateEphemeralKeyPair();
        $aliceEphemeralPublic = Sm2::getEphemeralPublicKey($rA);

        $keyA = KeyExchange::initiatorComputeKey(
            $alice->getPrivateKey(),
            $rA,
            $bob->getPublicKey(),
            $bobEphemeral->getPublicKey(),
            16
        );
        $keyB = KeyExchange::responderComputeKey(
            $bob->getPrivateKey(),
            $bobEphemeral->getPrivateKey(),
            $alice->getPublicKey(),
            $aliceEphemeralPublic,
            16
        );

        $this->assertSame($keyA, $keyB);
        $this->assertSame(Sm2::getEphemeralPublicKey($rA), $aliceEphemeralPublic);
    }

    public function testSm2KeyConfirmationRejectsMalformedPoints(): void
    {
        $point = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $arguments = [
            substr($point, 0, 64),
            substr($point, 64),
            'ida',
            'idb',
            $point,
            $point,
            $point,
            $point,
        ];

        foreach ([0, 1, 4, 5, 6, 7] as $index) {
            $invalidArguments = $arguments;
            $invalidArguments[$index] = $index === 0 ? '1' : substr($point, 0, -1);

            try {
                KeyExchange::computeInitiatorConfirmation(...$invalidArguments);
                $this->fail('Malformed confirmation point must be rejected');
            } catch (InvalidKeyException $exception) {
                $this->assertStringContainsString('Invalid SM2 key confirmation point', $exception->getMessage());
            }
        }
    }

    public function testSm2KeyConfirmationRejectsAmbiguousCoordinateBoundary(): void
    {
        $point = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('V coordinates must each be 64');
        KeyExchange::computeInitiatorConfirmation(
            substr($point, 0, 63),
            substr($point, 63),
            'ida',
            'idb',
            $point,
            $point,
            $point,
            $point
        );
    }

    public function testSm2PointMultiplyRejectsMalformedPointShapes(): void
    {
        foreach ([str_repeat('1', 65), str_repeat('1', 127), str_repeat('1', 129)] as $malformed) {
            $this->assertInvalidPointMultiplication(fn () => Sm2::pointMultiplyPublic($malformed));
        }

        $this->assertInvalidPointMultiplication(fn () => Sm2::pointMultiplyPublic('1', '2'));

        $this->assertInvalidPointMultiplication(fn () => Sm2::pointMultiplyPublic('zz'));

        $point = Sm2::getPublicKey(str_pad('1', 64, '0', STR_PAD_LEFT));
        foreach (['zz', str_repeat('1', 65)] as $malformedFactor) {
            $this->assertInvalidPointMultiplication(fn () => Sm2::pointMultiplyPublic($point, $malformedFactor));
        }
    }

    private function assertInvalidPointMultiplication(callable $operation): void
    {
        $this->expectException(\CryptoSm\Exception\InvalidKeyException::class);
        $operation();
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmIvTrackingHistoryCannotBeResetAfterEncryption(): void
    {
        $key = str_repeat('78', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('33', 12));

        Sm4::enableGcmIvTracking();
        Sm4::encrypt('a', $key, $options);
        try {
            Sm4::resetGcmIvTracking();
            $this->fail('Tracking history must not be cleared after encryption starts');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('history cannot be reset', $exception->getMessage());
        }
        Sm4::enableGcmIvTracking(true);
        try {
            Sm4::encrypt('b', $key, $options);
            $this->fail('A recorded key and IV pair must remain unavailable');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('GCM IV reuse detected', $exception->getMessage());
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmIvTrackingCannotBeDisabledAfterEncryptionStarts(): void
    {
        $key = str_repeat('79', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('44', 12));

        Sm4::encrypt('a', $key, $options);
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('cannot be disabled');
        Sm4::enableGcmIvTracking(false);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmIvTrackingCannotBeDisabledBeforeFirstEncryption(): void
    {
        $key = str_repeat('79', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(str_repeat('45', 12));

        try {
            Sm4::enableGcmIvTracking(false);
            $this->fail('GCM IV reuse tracking must not be disabled');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('cannot be disabled', $exception->getMessage());
        }
        Sm4::encrypt('a', $key, $options);
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('GCM IV reuse detected');
        Sm4::encrypt('b', $key, $options);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testLocalGcmIvTrackingTreatsHexCaseAsEquivalent(): void
    {
        $key = str_repeat('7b', 16);
        $iv = 'abcdef0123456789abcdef01';
        Sm4::encrypt('first', $key, (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('GCM IV reuse detected');
        Sm4::encrypt(
            'second',
            strtoupper($key),
            (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(strtoupper($iv))
        );
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testInternalFacadeTrackingConfigurationCannotDisableGuard(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('cannot be disabled');
        Gcm::configureFacadeIvTracking(false);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testEncryptPayloadNeverTriggersIvReuseDetection(): void
    {
        $key = str_repeat('7a', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM);

        $p1 = Sm4::encryptPayload('same data', $key, $options);
        $p2 = Sm4::encryptPayload('same data', $key, $options);
        $iv1 = is_string($p1['iv'] ?? null) ? $p1['iv'] : null;
        $iv2 = is_string($p2['iv'] ?? null) ? $p2['iv'] : null;
        $this->assertNotNull($iv1);
        $this->assertNotNull($iv2);
        $this->assertNotSame($iv1, $iv2);
        $this->assertSame('same data', Sm4::decryptPayload($p1, $key));
        $this->assertSame('same data', Sm4::decryptPayload($p2, $key));
    }

    public function testGeneratedGcmIvRefreshesWhenOptionsObjectIsReused(): void
    {
        $key = str_repeat('ac', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM);

        Sm4::encrypt('first', $key, $options);
        $firstIv = $options->getIv();
        Sm4::encrypt('second', $key, $options);

        $this->assertNotSame($firstIv, $options->getIv());
        $this->assertFalse($options->hasExplicitIv());
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testClonedOptionsDoNotReuseMaterializedGeneratedGcmIv(): void
    {
        $key = str_repeat('b0', 16);
        $options = new Sm4Options();
        $firstIv = $options->getIv();
        $clone = clone $options;

        Sm4::encrypt('original options', $key, $options);
        Sm4::encrypt('cloned options', $key, $clone);

        $this->assertSame($firstIv, $options->getIv());
        $this->assertNotSame($options->getIv(), $clone->getIv());
    }

    public function testReusedOptionsRefreshGeneratedIvForEveryIvMode(): void
    {
        foreach ([Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR] as $mode) {
            $key = substr(hash('sha256', 'reused-options-' . $mode), 0, 32);
            $options = (new Sm4Options())->setMode($mode);
            $firstIv = $options->getIv();
            $firstCiphertext = Sm4::encrypt('first plaintext', $key, $options);

            $secondCiphertext = Sm4::encrypt('other plaintext', $key, $options);
            $secondIv = $options->getIv();

            $this->assertNotSame($firstIv, $secondIv, $mode . ' must refresh a generated IV on reuse');
            $this->assertSame(
                'first plaintext',
                Sm4::decrypt($firstCiphertext, $key, (new Sm4Options())->setMode($mode)->setIv($firstIv)),
                $mode . ' first ciphertext must remain decryptable with its original IV'
            );
            $this->assertSame(
                'other plaintext',
                Sm4::decrypt($secondCiphertext, $key, (new Sm4Options())->setMode($mode)->setIv($secondIv)),
                $mode . ' second ciphertext must remain decryptable with its refreshed IV'
            );
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGeneratedGcmIvsDoNotAccumulateInExplicitIvReuseTable(): void
    {
        $key = str_repeat('ae', 16);
        $usedIvs = new \ReflectionProperty(Gcm::class, 'usedIvPairs');
        $this->assertSame([], $usedIvs->getValue());

        for ($i = 0; $i < 128; $i++) {
            Sm4::encrypt('generated nonce', $key, new Sm4Options());
        }

        $this->assertCount(0, $this->readReflectedArray($usedIvs));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testMaterializedGeneratedGcmIvUsesReservedNamespace(): void
    {
        $key = random_bytes(16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM);
        $ivHex = $options->getIv();
        $iv = hex2bin($ivHex);
        $this->assertIsString($iv);

        Sm4::encrypt('facade', bin2hex($key), $options);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('reserved internally generated IV namespace');
        Gcm::fromKey($key)->encrypt('direct', $iv);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testMaterializedGeneratedGcmIvsDoNotAccumulateInExplicitTrackingTable(): void
    {
        $key = str_repeat('ae', 16);
        $usedIvs = new \ReflectionProperty(Gcm::class, 'usedIvPairs');
        $this->assertSame([], $usedIvs->getValue());

        for ($i = 0; $i < 128; $i++) {
            $options = new Sm4Options();
            $iv = hex2bin($options->getIv());
            $this->assertIsString($iv);
            $this->assertSame('SM4R', substr($iv, 0, 4));
            Sm4::encrypt('materialized random nonce', $key, $options);
            $this->assertSame($iv, hex2bin($options->getIv()));
        }

        $this->assertSame([], $usedIvs->getValue());
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testMaterializedRandomIvBridgeRefreshesAndRejectsExplicitIvOptions(): void
    {
        $key = random_bytes(16);
        $gcm = Gcm::fromKey($key);
        $options = new Sm4Options();
        $firstIv = $options->getIv();

        $gcm->encryptWithMaterializedRandomIvFromFacade('first', $options);
        $this->assertSame($firstIv, $options->getIv());
        $gcm->encryptWithMaterializedRandomIvFromFacade('second', $options);
        $this->assertNotSame($firstIv, $options->getIv());

        $explicitOptions = (new Sm4Options())->setIv(bin2hex(random_bytes(12)));
        $this->expectException(InvalidKeyException::class);
        $gcm->encryptWithMaterializedRandomIvFromFacade('explicit', $explicitOptions);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testExplicitGcmIvTrackingFailsClosedAtCapacity(): void
    {
        $key = str_repeat('af', 16);
        $usedIvs = new \ReflectionProperty(Gcm::class, 'usedIvPairs');
        $usedIvs->setValue(null, array_fill_keys(array_map(
            static fn (int $i): string => hash('sha256', 'preexisting-' . $i),
            range(0, 65535)
        ), true));

        $options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(bin2hex(random_bytes(12)));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('process-local IV tracking table is full');
        Sm4::encrypt('new explicit nonce', $key, $options);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testModeChangeClearsExplicitIvStateBeforeGeneratedGcmIv(): void
    {
        $key = str_repeat('ad', 16);
        $options = (new Sm4Options())
            ->setMode(Sm4::MODE_CBC)
            ->setIv(str_repeat('11', 16))
            ->setMode(Sm4::MODE_GCM);

        $this->assertFalse($options->hasExplicitIv());

        Sm4::encrypt('first', $key, $options);
        $firstIv = $options->getIv();
        Sm4::encrypt('second', $key, $options);

        $this->assertFalse($options->hasExplicitIv());
        $this->assertNotSame($firstIv, $options->getIv());
    }

    // ─── GCM tagLength 校验一致性 ─────────────────────────────────────────

    public function testGcmClassRejectsNonStandardTagLengths(): void
    {
        $gcm = Gcm::fromKey(random_bytes(16));

        foreach ([4, 5, 6, 7, 8, 9, 10, 11, 0, -1, 17] as $badTagLength) {
            try {
                $gcm->encrypt('x', random_bytes(12), '', $badTagLength);
                $this->fail("Expected CryptoException for tagLength={$badTagLength}");
            } catch (CryptoException $e) {
                $this->assertStringContainsString('invalid tag length', $e->getMessage());
            }
        }
    }

    public function testGcmTagLengthMustRemainFixedForEachKey(): void
    {
        $key = random_bytes(16);
        Gcm::fromKey($key)->encrypt('first', random_bytes(12), '', 16);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tag length must remain fixed');
        Gcm::fromKey($key)->encrypt('second', random_bytes(12), '', 12);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmSuccessfulDecryptEstablishesTagLengthProfile(): void
    {
        $key = random_bytes(16);
        $iv = random_bytes(12);
        $cipher = Gcm::fromKey($key)->encrypt('received under a 12-byte tag', $iv, '', 12);

        // Model a fresh process that receives an authenticated message before
        // it has performed any encryption with this key.
        $profiles = new \ReflectionProperty(Gcm::class, 'tagLengthByKey');
        $current = $profiles->getValue();
        $this->assertIsArray($current);
        $keyId = hash('sha256', $key);
        unset($current[$keyId]);
        $profiles->setValue(null, $current);

        $this->assertSame(
            'received under a 12-byte tag',
            Gcm::fromKey($key)->decrypt($cipher['ciphertext'], $cipher['tag'], $iv, '', 12)
        );
        $establishedProfiles = $profiles->getValue();
        $this->assertIsArray($establishedProfiles);
        $this->assertSame(12, $establishedProfiles[$keyId] ?? null);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tag length must remain fixed');
        Gcm::fromKey($key)->encrypt('must keep the established profile', random_bytes(12), '', 16);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmFailedDecryptDoesNotEstablishTagLengthProfile(): void
    {
        $key = random_bytes(16);
        try {
            Gcm::fromKey($key)->decrypt('', str_repeat("\0", 12), random_bytes(12), '', 12);
            $this->fail('An invalid tag must not establish the key tag profile');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('authentication tag mismatch', $e->getMessage());
        }

        $result = Gcm::fromKey($key)->encrypt('valid 16-byte tag profile', random_bytes(12), '', 16);
        $this->assertSame(16, strlen($result['tag']));
    }

    public function testGcmRejectsTruncatedTagUnderDifferentKeyProfile(): void
    {
        $key = random_bytes(16);
        $iv = random_bytes(12);
        $cipher = Gcm::fromKey($key)->encrypt('do not downgrade this tag', $iv, '', 16);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('authentication tag mismatch');
        Gcm::fromKey($key)->decrypt($cipher['ciphertext'], substr($cipher['tag'], 0, 12), $iv, '', 12);
    }

    public function testGcmLengthLimitsRejectCounterWrapAndLengthOverflow(): void
    {
        $gcm = Gcm::fromKey(random_bytes(16));
        $validateParams = new \ReflectionMethod(Gcm::class, 'validateParams');
        $validateParams->setAccessible(true);

        $validateParams->invoke($gcm, 12, 16, Gcm::MAX_PLAINTEXT_LENGTH_BYTES, 0);

        $cases = [
            [12, intdiv(PHP_INT_MAX, 8) + 1, 0, 'plaintext/ciphertext exceeds the supported bit-length range'],
            [12, Gcm::MAX_PLAINTEXT_LENGTH_BYTES + 1, 0, 'NIST maximum length'],
            [12, 0, intdiv(PHP_INT_MAX, 8) + 1, 'AAD exceeds the supported bit-length range'],
            [intdiv(PHP_INT_MAX, 8) + 1, 0, 0, 'IV exceeds the supported bit-length range'],
        ];

        foreach ($cases as [$ivLength, $dataLength, $aadLength, $message]) {
            try {
                $validateParams->invoke($gcm, $ivLength, 16, $dataLength, $aadLength);
                $this->fail("Expected GCM length rejection for {$message}");
            } catch (CryptoException $e) {
                $this->assertStringContainsString($message, $e->getMessage());
            }
        }
    }

    // ─── setMode 幂等性 ──────────────────────────────────────────────────

    public function testSetModeSameValuePreservesIv(): void
    {
        $iv = str_repeat('55', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setIv($iv);
        $options->setMode(Sm4::MODE_CBC)->setMode('CBC');

        $this->assertSame($iv, $options->getIv());
    }

    public function testSetModeDifferentValueResetsIv(): void
    {
        $options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setIv(str_repeat('66', 16));
        $options->setMode(Sm4::MODE_CTR);

        $this->assertFalse($options->hasIv());
    }

    // ─── PEM 标签严格匹配 ────────────────────────────────────────────────

    public function testPemWithMismatchedBeginEndLabelsIsRejected(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $pem = Pem::exportPrivateKey($kp->getPrivateKey(), $kp->getPublicKey());
        $mismatched = str_replace(
            '-----END EC PRIVATE KEY-----',
            '-----END PRIVATE KEY-----',
            $pem
        );

        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKey($mismatched);
    }

    // ─── 密钥交换 klen 边界 ───────────────────────────────────────────────

    public function testKeyExchangeRejectsOversizedKlen(): void
    {
        $kp = Sm2::generateKeyPairHex();

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('must not exceed');
        KeyExchange::initiatorComputeKey(
            $kp->getPrivateKey(),
            $kp->getPrivateKey(),
            $kp->getPublicKey(),
            $kp->getPublicKey(),
            KeyExchange::MAX_KLEN + 1
        );
    }

    public function testKeyExchangeAcceptsKlenAtUpperBound(): void
    {
        $kp = Sm2::generateKeyPairHex();
        $ephemeral = Sm2::generateKeyPairHex();

        $key = KeyExchange::initiatorComputeKey(
            $kp->getPrivateKey(),
            $ephemeral->getPrivateKey(),
            $kp->getPublicKey(),
            $ephemeral->getPublicKey(),
            KeyExchange::MAX_KLEN
        );

        $this->assertSame(KeyExchange::MAX_KLEN * 2, strlen($key));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRawBlockPrimitiveCannotShareAKeyWithStreamMode(): void
    {
        $key = str_repeat('11', 16);
        $counter = str_repeat("\0", 16);
        $feedbackIv = str_repeat("\1", 16);

        // The public raw block engine is an ECB oracle if exposed to a caller.
        $blockCipher = new Sm4PurePhp();
        $keyBytes = hex2bin($key);
        self::assertIsString($keyBytes);
        $blockCipher->setKey($keyBytes);
        $blockCipher->encryptBlock($feedbackIv);
        $ctrOptions = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv(bin2hex($counter));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('separate keys');
        Sm4::encrypt(str_repeat("\0", 16), $key, $ctrOptions);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRawBlockPrimitiveIsRejectedAfterGcmUse(): void
    {
        $key = str_repeat("\x12", 16);
        Sm4::encrypt('GCM operation', bin2hex($key), new Sm4Options());

        $engine = new Sm4PurePhp();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('separate keys');
        $engine->setKey($key);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmAndCtrCannotReuseOneKey(): void
    {
        $key = str_repeat('22', 16);
        $iv = str_repeat('33', 12);
        Sm4::encrypt('gcm payload', $key, (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv));

        // For a 96-bit GCM IV, the first payload counter is IV || 2.
        $counter = hex2bin($iv . '00000002');
        self::assertIsString($counter);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv(bin2hex($counter));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('separate keys');
        Sm4::encrypt(str_repeat("\0", 16), $key, $options);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmAndBlockModesCannotReuseOneKey(): void
    {
        $key = str_repeat('66', 16);
        $gcmIv = str_repeat('33', 12);
        Sm4::encrypt(
            str_repeat("\0", 16),
            $key,
            (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($gcmIv)
        );

        // CBC can expose E_K(IV || 2), the first payload keystream block from
        // GCM with a 96-bit IV, by selecting plaintext XOR IV to that value.
        $targetInput = hex2bin($gcmIv . '00000002');
        self::assertIsString($targetInput);
        $cbcIv = str_repeat("\1", 16);
        $cbcPlaintext = $targetInput ^ $cbcIv;
        $cbcOptions = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setPadding('none')->setIv(bin2hex($cbcIv));

        try {
            Sm4::encrypt($cbcPlaintext, $key, $cbcOptions);
            $this->fail('CBC must not expose a block input already used by GCM');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('separate keys', $exception->getMessage());
        }

        try {
            Sm4::encrypt($targetInput, $key, (new Sm4Options())->setMode(Sm4::MODE_ECB)->setPadding('none'));
            $this->fail('ECB must not expose a block input already used by GCM');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('separate keys', $exception->getMessage());
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmKeyCannotBeReusedToReadLegacyCbcCiphertext(): void
    {
        // Generated by v0.3.0's default Sm4::encrypt() using this same key:
        // IV || CBC ciphertext, with PKCS5 padding.
        $key = '00112233445566778899aabbccddeeff';
        $legacyCiphertext = '4257693c4857b52bc1acf9871eaa41b7'
            . '9be3d77841130ad1094300f8e7f4bed1e2f15d4d60bd62261039437434cbf0b8';

        self::assertSame('historical CBC payload', Sm4::decryptLegacyCbc($legacyCiphertext, $key));

        Sm4::encrypt('new GCM record', $key);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('not registered for this decryption mode');
        Sm4::decryptLegacyCbc($legacyCiphertext, $key);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testCcmAndGcmCannotReuseOneKey(): void
    {
        $key = str_repeat("\x6A", 16);
        Ccm::fromKey($key)->encrypt('CCM payload', random_bytes(12));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('separate keys');
        Gcm::fromKey($key)->encrypt('GCM payload', random_bytes(12));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testGcmAndCcmCannotReuseOneKey(): void
    {
        $key = str_repeat("\x6B", 16);
        Gcm::fromKey($key)->encrypt('GCM payload', random_bytes(12));

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('separate keys');
        Ccm::fromKey($key)->encrypt('CCM payload', random_bytes(12));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testMalformedCcmDecryptDoesNotReserveMode(): void
    {
        $key = str_repeat("\x6C", 16);
        try {
            Ccm::fromKey($key)->decrypt('ciphertext', 'short', random_bytes(12));
            $this->fail('Malformed CCM tag must be rejected before cipher work');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('tag length mismatch', $exception->getMessage());
        }

        Gcm::fromKey($key)->encrypt('valid GCM operation', random_bytes(12));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testInvalidBlockModeParametersDoNotReserveAKeyMode(): void
    {
        $key = str_repeat('77', 16);
        $options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setPadding('none');
        $ivProperty = new \ReflectionProperty(Sm4Options::class, 'iv');
        $ivProperty->setValue($options, 'badiv');

        try {
            Sm4::encrypt(str_repeat('x', 16), $key, $options);
            $this->fail('Malformed CBC IV must be rejected');
        } catch (InvalidKeyException $exception) {
            $this->assertStringContainsString('IV', $exception->getMessage());
        }

        Sm4::encrypt('valid GCM operation', $key, new Sm4Options());
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testFailedGcmAuthenticationDoesNotRegisterAnUntrustedMode(): void
    {
        $key = hex2bin(str_repeat('44', 16));
        self::assertIsString($key);
        try {
            Gcm::fromKey($key)->decrypt(str_repeat("\0", 16), str_repeat("\0", 16), str_repeat("\0", 12));
            $this->fail('Invalid GCM authentication must fail');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('authentication tag mismatch', $exception->getMessage());
        }

        $modeClaims = (new \ReflectionProperty(Sm4::class, 'cipherModeByKey'))->getValue();
        self::assertIsArray($modeClaims);
        self::assertArrayNotHasKey(hash('sha256', $key), $modeClaims);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testInvalidGcmTagLengthDoesNotReserveMode(): void
    {
        $key = hex2bin(str_repeat('55', 16));
        self::assertIsString($key);
        try {
            Gcm::fromKey($key)->decrypt(str_repeat("\0", 16), str_repeat("\0", 15), str_repeat("\0", 12));
            $this->fail('Invalid GCM authentication tag length must fail');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('tag length mismatch', $exception->getMessage());
        }

        Sm4::encrypt(
            str_repeat("\0", 16),
            bin2hex($key),
            (new Sm4Options())->setMode(Sm4::MODE_ECB)->setPadding('none')
        );
    }

    private function configureFiberStackSize(): void
    {
        if (ini_set('fiber.stack_size', '2M') === false) {
            $this->fail('Unable to configure the Fiber stack size for concurrency regression tests');
        }
    }

    /** @return array<array-key, mixed> */
    private function readReflectedArray(\ReflectionProperty $property): array
    {
        $value = $property->getValue();
        if (!is_array($value)) {
            $this->fail('Expected the reflected state to be an array');
        }

        return $value;
    }
}
