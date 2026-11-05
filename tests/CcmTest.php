<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Crypto\Ccm;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Interfaces\CcmTagLengthTrackerInterface;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4PurePhp;
use PHPUnit\Framework\TestCase;

/**
 * SM4-CCM 认证加密测试（NIST SP 800-38C / RFC 3610 构造）
 *
 * 覆盖：正常加解密往返、AAD、各标签长度、篡改检测、参数校验异常分支。
 * CCM 编排参考模型通过 RFC 3610 Packet Vector #1 的 AES-128-CCM 官方值校准；
 * SM4 块密码另由标准向量验证，再以独立参考编排核对库输出。
 */
class CcmTest extends TestCase
{
    private function makeCcm(): Ccm
    {
        return Ccm::fromKey(random_bytes(16));
    }

    // ─── 基本功能 ─────────────────────────────────────────────────────────

    public function testRoundTripWithAad(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $aad = 'additional authenticated data';
        $pt = 'secret message to protect';

        $r = $ccm->encrypt($pt, $nonce, $aad, 16);
        $this->assertSame($pt, $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16));
    }

    public function testVarExportDoesNotExposeKeyBeforeOrAfterEncryption(): void
    {
        $key = random_bytes(16);
        $ccm = new Ccm($key);

        $this->assertStringNotContainsString($key, var_export($ccm, true));

        $ccm->encrypt('secret', random_bytes(12));

        $this->assertStringNotContainsString($key, var_export($ccm, true));
    }

    public function testCloneKeepsIndependentKeyContextAndRoundTrips(): void
    {
        $key = random_bytes(16);
        $original = new Ccm($key);
        $original->encrypt('warm up engine', random_bytes(12));
        $clone = clone $original;
        $nonce = random_bytes(12);
        $plaintext = 'clone context round trip';

        $result = $clone->encrypt($plaintext, $nonce);

        $this->assertSame($plaintext, $clone->decrypt($result['ciphertext'], $result['tag'], $nonce));
        $this->assertSame($plaintext, $original->decrypt($result['ciphertext'], $result['tag'], $nonce));
        $this->assertStringNotContainsString($key, var_export($clone, true));
    }

    public function testRoundTripEmptyPlaintextAndAad(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('', $nonce, '', 16);
        $this->assertSame('', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 16));
    }

    public function testRoundTripMultiBlock(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(7); // 最短 nonce → 最大消息空间
        $pt = str_repeat('CCM multi-block test data! ', 10); // > 16 字节非对齐

        $r = $ccm->encrypt($pt, $nonce, '', 12);
        $this->assertSame($pt, $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 12));
    }

    public function testCcmOutputMatchesIndependentSm4ReferenceModel(): void
    {
        $key = hex2bin('0123456789abcdeffedcba9876543210');
        $nonce = hex2bin('a0a1a2a3a4a5a6a7a8a9aaab');
        $aad = hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        $plaintext = hex2bin('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
        self::assertIsString($key);
        self::assertIsString($nonce);
        self::assertIsString($aad);
        self::assertIsString($plaintext);

        $reference = self::referenceSm4Ccm($key, $nonce, $aad, $plaintext, 16);
        $this->assertSame('70190af565ac40889406e8b9c744b0ff6710007f1a769694565f1e2cb55bd0a3', bin2hex($reference['ciphertext']));
        $this->assertSame('4f39fb00296d08abfa7facfff9ef7667', bin2hex($reference['tag']));

        $result = Ccm::fromKey($key)->encrypt($plaintext, $nonce, $aad, 16);
        $this->assertSame($reference['ciphertext'], $result['ciphertext']);
        $this->assertSame($reference['tag'], $result['tag']);
    }

    public function testSm4CcmMatchesRfc8998AppendixA2Vector(): void
    {
        $key = hex2bin('0123456789abcdeffedcba9876543210');
        $nonce = hex2bin('00001234567800000000abcd');
        $plaintext = hex2bin(
            'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb'
            . 'ccccccccccccccccdddddddddddddddd'
            . 'eeeeeeeeeeeeeeeeffffffffffffffff'
            . 'eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa'
        );
        $aad = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');
        self::assertIsString($key);
        self::assertIsString($nonce);
        self::assertIsString($plaintext);
        self::assertIsString($aad);

        $ccm = Ccm::fromKey($key);
        $result = $ccm->encrypt($plaintext, $nonce, $aad, 16);

        $this->assertSame(
            '48af93501fa62adbcd414cce6034d895'
            . 'dda1bf8f132f042098661572e7483094'
            . 'fd12e518ce062c98acee28d95df4416b'
            . 'ed31a2f04476c18bb40c84a74b97dc5b',
            bin2hex($result['ciphertext']),
            'RFC 8998 Appendix A.2 ciphertext mismatch'
        );
        $this->assertSame(
            '16842d4fa186f56ab33256971fa110f4',
            bin2hex($result['tag']),
            'RFC 8998 Appendix A.2 authentication tag mismatch'
        );
        $this->assertSame($plaintext, $ccm->decrypt($result['ciphertext'], $result['tag'], $nonce, $aad, 16));
    }

    public function testReferenceCompositionMatchesRfc3610PacketVectorOne(): void
    {
        $key = hex2bin('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf');
        $nonce = hex2bin('00000003020100a0a1a2a3a4a5');
        $aad = hex2bin('0001020304050607');
        $plaintext = hex2bin('08090a0b0c0d0e0f101112131415161718191a1b1c1d1e');
        self::assertIsString($key);
        self::assertIsString($nonce);
        self::assertIsString($aad);
        self::assertIsString($plaintext);

        $encryptBlock = static function (string $block) use ($key): string {
            $encrypted = openssl_encrypt(
                $block,
                'aes-128-ecb',
                $key,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
            );
            if (!is_string($encrypted) || strlen($encrypted) !== 16) {
                throw new \RuntimeException('AES-128-ECB reference block encryption failed');
            }
            return $encrypted;
        };

        $reference = self::referenceCcm($encryptBlock, $nonce, $aad, $plaintext, 8);

        $this->assertSame(
            '588c979a61c663d2f066d0c2c0f989806d5f6b61dac384',
            bin2hex($reference['ciphertext']),
            'RFC 3610 Packet Vector #1 ciphertext mismatch'
        );
        $this->assertSame(
            '17e8d12cfdf926e0',
            bin2hex($reference['tag']),
            'RFC 3610 Packet Vector #1 tag mismatch'
        );
    }

    public function testCcmAadLengthEncodingBoundariesMatchIndependentReference(): void
    {
        $key = hex2bin('0123456789abcdeffedcba9876543210');
        self::assertIsString($key);
        $ccm = Ccm::fromKey($key);
        $plaintext = 'CCM AAD length boundary';

        foreach ([1, 255, 256, 65279, 65280, 65536] as $aadLength) {
            $aad = str_repeat('A', $aadLength);
            $nonce = str_repeat("\0", 10) . pack('n', $aadLength);
            $reference = self::referenceSm4Ccm($key, $nonce, $aad, $plaintext, 16);
            $actual = $ccm->encrypt($plaintext, $nonce, $aad, 16);

            $this->assertSame(
                $reference['ciphertext'],
                $actual['ciphertext'],
                "ciphertext mismatch at AAD length {$aadLength}"
            );
            $this->assertSame(
                $reference['tag'],
                $actual['tag'],
                "tag mismatch at AAD length {$aadLength}"
            );
        }
    }

    /**
     * CCM reference composition written independently of Crypto\Ccm.
     * The SM4 block primitive is validated separately by the standard vectors.
     *
     * @return array{ciphertext: string, tag: string}
     */
    private static function referenceSm4Ccm(string $key, string $nonce, string $aad, string $plaintext, int $tagLength): array
    {
        $engine = new Sm4PurePhp();
        $engine->setKeyForMode($key, Sm4::MODE_CCM);
        $encryptBlock = static fn (string $block): string => $engine->encryptBlock($block);

        return self::referenceCcm($encryptBlock, $nonce, $aad, $plaintext, $tagLength);
    }

    /**
     * Independent CCM composition over a caller-supplied 128-bit block cipher.
     *
     * @param  callable(string): string               $encryptBlock
     * @return array{ciphertext: string, tag: string}
     */
    private static function referenceCcm(
        callable $encryptBlock,
        string $nonce,
        string $aad,
        string $plaintext,
        int $tagLength
    ): array {
        $q = 15 - strlen($nonce);
        $flags = ($aad === '' ? 0 : 0x40) | ((($tagLength - 2) >> 1) << 3) | ($q - 1);
        $b0 = chr($flags) . $nonce . substr(pack('J', strlen($plaintext)), 8 - $q);

        $encodedAad = '';
        if ($aad !== '') {
            $aadLength = strlen($aad);
            if ($aadLength < 65280) {
                $encodedAad = pack('n', $aadLength);
            } elseif ($aadLength < 4294967296) {
                $encodedAad = "\xFF\xFE" . pack('N', $aadLength);
            } else {
                $encodedAad = "\xFF\xFF" . pack('J', $aadLength);
            }
            $encodedAad .= $aad;
            $encodedAad .= str_repeat("\0", (16 - strlen($encodedAad) % 16) % 16);
        }

        $macInput = $b0 . $encodedAad . $plaintext;
        $macInput .= str_repeat("\0", (16 - strlen($macInput) % 16) % 16);
        $mac = str_repeat("\0", 16);
        for ($offset = 0; $offset < strlen($macInput); $offset += 16) {
            $mac = $encryptBlock($mac ^ substr($macInput, $offset, 16));
        }

        $counterPrefix = chr($q - 1) . $nonce;
        $ciphertext = '';
        for ($offset = 0, $length = strlen($plaintext); $offset < $length; $offset += 16) {
            $counter = substr(pack('J', intdiv($offset, 16) + 1), 8 - $q);
            $keystream = $encryptBlock($counterPrefix . $counter);
            $chunk = substr($plaintext, $offset, 16);
            $ciphertext .= $chunk ^ substr($keystream, 0, strlen($chunk));
        }

        $a0 = $counterPrefix . str_repeat("\0", $q);
        return ['ciphertext' => $ciphertext, 'tag' => $mac ^ substr($encryptBlock($a0), 0, $tagLength)];
    }

    public function testAllValidTagLengths(): void
    {
        foreach ([4, 6, 8, 10, 12, 14, 16] as $tagLen) {
            $ccm = $this->makeCcm();
            $nonce = random_bytes(13); // 最长 nonce
            $r = $ccm->encrypt('data', $nonce, 'aad', $tagLen);
            $this->assertCount($tagLen, str_split($r['tag']), "tag len=$tagLen");
            $this->assertSame('data', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, 'aad', $tagLen), "roundtrip tag len=$tagLen");
        }
    }

    public function testTagLengthMustRemainFixedForEachKey(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(12);
        (new Ccm($key))->encrypt('first', $nonce, '', 16);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tag length must remain fixed');
        (new Ccm($key))->encrypt('second', random_bytes(12), '', 12);
    }

    public function testAllValidNonceLengths(): void
    {
        $ccm = $this->makeCcm();

        foreach ([7, 8, 9, 10, 11, 12, 13] as $nonceLen) {
            $nonce = random_bytes($nonceLen);
            $r = $ccm->encrypt('test', $nonce, '', 16);
            $this->assertSame('test', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 16), "nonce len=$nonceLen");
        }
    }

    public function testNonceReuseIsRejectedAcrossInstancesButDifferentKeysMayReuseNonce(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(12);
        $ccm1 = new Ccm($key);
        $ccm2 = new Ccm($key);

        $r1 = $ccm1->encrypt('deterministic', $nonce, '', 16);
        $this->assertSame('deterministic', $ccm1->decrypt($r1['ciphertext'], $r1['tag'], $nonce));

        try {
            $ccm2->encrypt('deterministic', $nonce, '', 16);
            $this->fail('Expected repeated CCM nonce to be rejected');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('nonce reuse detected', $exception->getMessage());
        }

        $otherKeyCcm = new Ccm(random_bytes(16));
        $this->assertSame('deterministic', $otherKeyCcm->decrypt(
            ($result = $otherKeyCcm->encrypt('deterministic', $nonce))['ciphertext'],
            $result['tag'],
            $nonce
        ));
    }

    public function testNonceTrackingCoversClonesAndExactNonceBytes(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(12);
        $original = new Ccm($key);
        $clone = clone $original;

        $original->encrypt('first', $nonce);
        try {
            $clone->encrypt('duplicate', $nonce);
            $this->fail('Expected cloned context to share nonce history');
        } catch (CryptoException $exception) {
            $this->assertStringContainsString('nonce reuse detected', $exception->getMessage());
        }

        $prefix = random_bytes(7);
        $original->encrypt('short nonce', $prefix);
        $original->encrypt('long nonce', $prefix . "\0");
        $original->encrypt('new nonce', random_bytes(12));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRfc8998Sm4CcmVector(): void
    {
        $this->assertRfc8998Sm4CcmVector();
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testRfc8998Sm4CcmVectorWithPurePhpBackend(): void
    {
        (new \ReflectionProperty(Sm4PurePhp::class, 'openSslSm4Available'))->setValue(null, false);
        $this->assertRfc8998Sm4CcmVector();
    }

    private function assertRfc8998Sm4CcmVector(): void
    {
        $key = hex2bin('0123456789abcdeffedcba9876543210');
        $nonce = hex2bin('00001234567800000000abcd');
        $plaintext = hex2bin(
            'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb'
            . 'ccccccccccccccccdddddddddddddddd'
            . 'eeeeeeeeeeeeeeeeffffffffffffffff'
            . 'eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa'
        );
        $aad = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');
        self::assertIsString($key);
        self::assertIsString($nonce);
        self::assertIsString($plaintext);
        self::assertIsString($aad);

        $result = Ccm::fromKey($key)->encrypt($plaintext, $nonce, $aad, 16);

        $this->assertSame(
            '48af93501fa62adbcd414cce6034d895'
            . 'dda1bf8f132f042098661572e7483094'
            . 'fd12e518ce062c98acee28d95df4416b'
            . 'ed31a2f04476c18bb40c84a74b97dc5b',
            bin2hex($result['ciphertext'])
        );
        $this->assertSame('16842d4fa186f56ab33256971fa110f4', bin2hex($result['tag']));
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSharedCcmTagLengthTrackerRejectsAuthenticatedDifferentProfile(): void
    {
        $key = hex2bin('0123456789abcdeffedcba9876543210');
        $nonce = hex2bin('00001234567800000000abcd');
        $ciphertext = hex2bin(
            '48af93501fa62adbcd414cce6034d895'
            . 'dda1bf8f132f042098661572e7483094'
            . 'fd12e518ce062c98acee28d95df4416b'
            . 'ed31a2f04476c18bb40c84a74b97dc5b'
        );
        $tag = hex2bin('16842d4fa186f56ab33256971fa110f4');
        $aad = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');
        self::assertIsString($key);
        self::assertIsString($nonce);
        self::assertIsString($ciphertext);
        self::assertIsString($tag);
        self::assertIsString($aad);

        Ccm::setTagLengthTracker(new class () implements CcmTagLengthTrackerInterface {
            public function claimTagLength(string $key, int $tagLength): bool
            {
                return $tagLength === 12;
            }
        });

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('authentication failed');
        Ccm::fromKey($key)->decrypt($ciphertext, $tag, $nonce, $aad, 16);
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSharedCcmTagLengthTrackerAvoidsLocalProfileCapacity(): void
    {
        $profiles = new \ArrayObject();
        Ccm::setTagLengthTracker(new class ($profiles) implements CcmTagLengthTrackerInterface {
            /** @param \ArrayObject<string, int> $profiles */
            public function __construct(private \ArrayObject $profiles)
            {
            }

            public function claimTagLength(string $key, int $tagLength): bool
            {
                $keyId = hash('sha256', $key);
                if ($this->profiles->offsetExists($keyId)) {
                    return $this->profiles->offsetGet($keyId) === $tagLength;
                }
                $this->profiles->offsetSet($keyId, $tagLength);
                return true;
            }
        });

        $maxTrackedProfiles = (new \ReflectionClass(Ccm::class))->getConstant('MAX_TRACKED_TAG_PROFILES');
        self::assertIsInt($maxTrackedProfiles);
        $localProfiles = new \ReflectionProperty(Ccm::class, 'tagLengthByKey');
        $existingProfiles = [];
        for ($i = 0; $i < $maxTrackedProfiles; $i++) {
            $existingProfiles[hash('sha256', 'existing-ccm-key-' . $i)] = 16;
        }
        $localProfiles->setValue(null, $existingProfiles);

        $key = random_bytes(16);
        $nonce = random_bytes(12);
        $ccm = Ccm::fromKey($key);
        $result = $ccm->encrypt('shared profile path', $nonce);

        $this->assertSame('shared profile path', $ccm->decrypt($result['ciphertext'], $result['tag'], $nonce));
        $this->assertSame(16, $profiles->offsetGet(hash('sha256', $key)));
        $storedProfiles = $localProfiles->getValue();
        self::assertIsArray($storedProfiles);
        $this->assertCount($maxTrackedProfiles, $storedProfiles);
        $this->assertArrayNotHasKey(hash('sha256', $key), $storedProfiles);
    }

    public function testAadLengthPrefixMatchesCcmEncodingBoundaries(): void
    {
        $encode = new \ReflectionMethod(Ccm::class, 'aadLengthPrefix');
        $cases = [
            1 => '0001',
            255 => '00ff',
            256 => '0100',
            65279 => 'feff',
            65280 => 'fffe0000ff00',
            65536 => 'fffe00010000',
            4294967296 => 'ffff0000000100000000',
        ];

        foreach ($cases as $length => $expectedHex) {
            $prefix = $encode->invoke(null, $length);
            self::assertIsString($prefix);
            $this->assertSame($expectedHex, bin2hex($prefix), 'AAD length=' . $length);
        }
    }

    // ─── 篡改检测 ─────────────────────────────────────────────────────────

    public function testTamperedCiphertextRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('auth test', $nonce, '', 16);

        $bad = $r['ciphertext'];
        $bad[0] = chr(ord($bad[0]) ^ 0x01);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('authentication failed');
        $ccm->decrypt($bad, $r['tag'], $nonce, '', 16);
    }

    public function testTamperedTagRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('auth test', $nonce, '', 16);

        $badTag = $r['tag'];
        $badTag[0] = chr(ord($badTag[0]) ^ 0xFF);

        $this->expectException(CryptoException::class);
        $ccm->decrypt($r['ciphertext'], $badTag, $nonce, '', 16);
    }

    public function testTamperedAadRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('data', $nonce, 'original aad', 16);

        $this->expectException(CryptoException::class);
        $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, 'tampered aad!!', 16);
    }

    public function testWrongNonceRejected(): void
    {
        $ccm = $this->makeCcm();
        $r = $ccm->encrypt('data', random_bytes(12), '', 16);

        $this->expectException(CryptoException::class);
        $ccm->decrypt($r['ciphertext'], $r['tag'], random_bytes(12), '', 16);
    }

    public function testTagLengthMismatchRejected(): void
    {
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $r = $ccm->encrypt('data', $nonce, '', 16);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('tag length mismatch');
        // 声明 8 字节标签但传入 16 字节 → 长度不匹配
        $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, '', 8);
    }

    // ─── 参数校验异常分支 ──────────────────────────────────────────────────

    public function testConstructorRejectsWrongKeySize(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('key must be 16 bytes');
        new Ccm('short');
    }

    public function testFromKeyReturnsInstance(): void
    {
        $ccm = Ccm::fromKey(random_bytes(16));
        $this->assertInstanceOf(Ccm::class, $ccm);
    }

    public function testRejectsShortNonce(): void
    {
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('nonce must be 7–13 bytes');
        $ccm->encrypt('x', random_bytes(6), '', 16);
    }

    public function testRejectsLongNonce(): void
    {
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('nonce must be 7–13 bytes');
        $ccm->encrypt('x', random_bytes(14), '', 16);
    }

    public function testDecryptRejectsShortNonce(): void
    {
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $ccm->decrypt('a', 'b', "\0\0\0", '', 16);
    }

    public function testRejectsInvalidTagLength(): void
    {
        $ccm = $this->makeCcm();
        foreach ([3, 5, 7, 9, 11, 13, 15, 17, 0, -1] as $bad) {
            try {
                $ccm->encrypt('x', random_bytes(12), '', $bad);
                $this->fail("tagLength=$bad should throw");
            } catch (CryptoException $e) {
                $this->assertStringContainsString('invalid tag length', $e->getMessage());
            }
        }
    }

    public function testRejectsOversizedMessage(): void
    {
        // nonce=13 → q=2 → max message size = 65535 bytes
        $ccm = $this->makeCcm();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('message too long');
        $ccm->encrypt(str_repeat("\0", 65536), random_bytes(13), '', 16);
    }

    public function testMessageLengthFieldAcceptsRepresentableWideValues(): void
    {
        $validate = new \ReflectionMethod(Ccm::class, 'validateParams');
        $validate->invoke(null, str_repeat('n', 7), 16, 0, PHP_INT_MAX);
        $validate->invoke(null, str_repeat('n', 13), 16, 0, 65535);
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('message too long');
        $validate->invoke(null, str_repeat('n', 13), 16, 0, 65536);
    }

    public function testAcceptsAadAbove16BitBoundary(): void
    {
        // RFC 3610 扩展前缀编码：AAD ≥65280 使用 FF FE + 4 字节长度
        // （拒绝阈值已上移至 2^32，见 Ccm::validateParams）
        $ccm = $this->makeCcm();
        $nonce = random_bytes(12);
        $aad = str_repeat("\0", 65536);
        $r = $ccm->encrypt('boundary', $nonce, $aad, 16);
        $this->assertSame('boundary', $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16));
    }

    // ─── AAD 长度边界（RFC 3610 编码格式切换）───────────────────────────────

    public function testAadLengthBoundaries(): void
    {
        $ccm = $this->makeCcm();

        $encodeAadLength = new \ReflectionMethod(Ccm::class, 'aadLengthPrefix');
        $this->assertSame("\xFE\xFF", $encodeAadLength->invoke(null, 65279));
        $this->assertSame("\xFF\xFE\x00\x00\xFF\x00", $encodeAadLength->invoke(null, 65280));
        if (PHP_INT_SIZE >= 8) {
            $this->assertSame("\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00", $encodeAadLength->invoke(null, 4294967296));
            $this->assertSame("\xFF\xFF\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", $encodeAadLength->invoke(null, PHP_INT_MAX));
        }

        foreach ([0, 1, 255, 256, 65279, 65280, 65536] as $aadLen) {
            $aad = str_repeat('A', $aadLen);
            $nonce = random_bytes(12);
            $r = $ccm->encrypt('payload', $nonce, $aad, 16);
            $this->assertSame(
                'payload',
                $ccm->decrypt($r['ciphertext'], $r['tag'], $nonce, $aad, 16),
                "aadLen=$aadLen"
            );
        }
    }
}
