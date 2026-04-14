<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use CryptoSm\SmCrypto;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for new features: SM3 streaming, HMAC-SM3, SM4 new modes,
 * padding schemes, PEM import/export, SM2 key exchange.
 */
class NewFeatureTest extends TestCase
{
    // ─── SM3 Streaming ────────────────────────────────────────────────────

    public function testSm3StreamingMatchesOneShot(): void
    {
        $data = 'Hello, SM3 streaming mode!';
        $expected = Sm3::sm3($data);

        $hasher = new Sm3();
        $hasher->update($data);
        $this->assertEquals($expected, $hasher->finalize());
    }

    public function testSm3StreamingChunked(): void
    {
        $data = str_repeat('A', 1000);
        $expected = Sm3::sm3($data);

        $hasher = new Sm3();
        // Feed in 100-byte chunks
        for ($i = 0; $i < strlen($data); $i += 100) {
            $hasher->update(substr($data, $i, 100));
        }
        $this->assertEquals($expected, $hasher->finalize());
    }

    public function testSm3StreamingEmptyInput(): void
    {
        $expected = Sm3::sm3('');
        $hasher = new Sm3();
        $this->assertEquals($expected, $hasher->finalize());
    }

    public function testSm3StreamingBlockBoundary(): void
    {
        // Test with data exactly at block boundary (64 bytes)
        $data = str_repeat('B', 64);
        $expected = Sm3::sm3($data);

        $hasher = new Sm3();
        $hasher->update($data);
        $this->assertEquals($expected, $hasher->finalize());
    }

    public function testSm3StreamingMultipleFinalize(): void
    {
        $hasher = new Sm3();
        $hasher->update('test1');
        $result1 = $hasher->finalize();

        // After finalize, should be reset
        $hasher->update('test2');
        $result2 = $hasher->finalize();

        $this->assertEquals(Sm3::sm3('test1'), $result1);
        $this->assertEquals(Sm3::sm3('test2'), $result2);
    }

    public function testSm3StreamingViaFacade(): void
    {
        $data = 'facade streaming test';
        $expected = Sm3::sm3($data);

        $hasher = SmCrypto::sm3Stream();
        $hasher->update($data);
        $this->assertEquals($expected, $hasher->finalize());
    }

    public function testSm3StreamingMethodChaining(): void
    {
        $data = 'chaining test';
        $expected = Sm3::sm3($data);

        $result = (new Sm3())->update($data)->finalize();
        $this->assertEquals($expected, $result);
    }

    // ─── HMAC-SM3 ─────────────────────────────────────────────────────────

    public function testHmacSm3Basic(): void
    {
        $key = 'secret_key';
        $data = 'hello world';
        $result = HmacSm3::hmac($key, $data);
        $this->assertEquals(64, strlen($result));
        $this->assertTrue(ctype_xdigit($result));
    }

    public function testHmacSm3Deterministic(): void
    {
        $key = 'test_key';
        $data = 'test_data';
        $this->assertEquals(HmacSm3::hmac($key, $data), HmacSm3::hmac($key, $data));
    }

    public function testHmacSm3DifferentKeys(): void
    {
        $data = 'same data';
        $hmac1 = HmacSm3::hmac('key1', $data);
        $hmac2 = HmacSm3::hmac('key2', $data);
        $this->assertNotEquals($hmac1, $hmac2);
    }

    public function testHmacSm3DifferentData(): void
    {
        $key = 'same_key';
        $hmac1 = HmacSm3::hmac($key, 'data1');
        $hmac2 = HmacSm3::hmac($key, 'data2');
        $this->assertNotEquals($hmac1, $hmac2);
    }

    public function testHmacSm3LongKey(): void
    {
        // Key longer than block size (64 bytes) should be hashed first
        $key = str_repeat('x', 100);
        $data = 'test';
        $result = HmacSm3::hmac($key, $data);
        $this->assertEquals(64, strlen($result));
    }

    public function testHmacSm3Streaming(): void
    {
        $key = 'streaming_key';
        $data = 'hello world';

        // One-shot
        $expected = HmacSm3::hmac($key, $data);

        // Streaming
        $hmac = HmacSm3::create($key);
        $hmac->update($data);
        $this->assertEquals($expected, $hmac->finalize());
    }

    public function testHmacSm3StreamingChunked(): void
    {
        $key = 'chunked_key';
        $data = str_repeat('X', 500);
        $expected = HmacSm3::hmac($key, $data);

        $hmac = HmacSm3::create($key);
        for ($i = 0; $i < strlen($data); $i += 50) {
            $hmac->update(substr($data, $i, 50));
        }
        $this->assertEquals($expected, $hmac->finalize());
    }

    public function testHmacSm3ViaFacade(): void
    {
        $key = 'facade_key';
        $data = 'facade_data';
        $this->assertEquals(SmCrypto::hmacSm3($key, $data), HmacSm3::hmac($key, $data));
    }

    public function testHmacSm3StreamingViaFacade(): void
    {
        $key = 'facade_stream_key';
        $data = 'facade_stream_data';
        $expected = HmacSm3::hmac($key, $data);

        $hmac = SmCrypto::hmacSm3Stream($key);
        $hmac->update($data);
        $this->assertEquals($expected, $hmac->finalize());
    }

    // ─── SM4 New Modes ────────────────────────────────────────────────────

    /**
     * @return array<int, array{string}>
     */
    public static function sm4KeyProvider(): array
    {
        return [[bin2hex(random_bytes(16))]];
    }

    /**
     * @dataProvider sm4KeyProvider
     */
    #[DataProvider('sm4KeyProvider')]
    public function testSm4CfbRoundTrip(string $key): void
    {
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CFB);
        $iv = $opts->getIv();
        $data = 'SM4-CFB mode test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    /**
     * @dataProvider sm4KeyProvider
     */
    #[DataProvider('sm4KeyProvider')]
    public function testSm4OfbRoundTrip(string $key): void
    {
        $opts = (new Sm4Options())->setMode(Sm4::MODE_OFB);
        $iv = $opts->getIv();
        $data = 'SM4-OFB mode test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_OFB)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    /**
     * @dataProvider sm4KeyProvider
     */
    #[DataProvider('sm4KeyProvider')]
    public function testSm4CtrRoundTrip(string $key): void
    {
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CTR);
        $iv = $opts->getIv();
        $data = 'SM4-CTR mode test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4CfbNoPaddingRequired(): void
    {
        // CFB is stream-like, no need for data to be block-aligned
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_CFB);
        $iv = $opts->getIv();
        $data = 'short'; // 5 bytes, not block-aligned
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4GcmRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM);
        $iv = $opts->getIv();
        $data = 'SM4-GCM authenticated encryption';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4GcmWithAad(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setAad('additional data');
        $iv = $opts->getIv();
        $data = 'GCM with AAD test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv)->setAad('additional data'));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4GcmTagTamperFails(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM);
        $iv = $opts->getIv();
        $data = 'tamper test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        // Tamper with the tag (last 32 hex chars for 16-byte tag)
        $tampered = substr($encrypted, 0, -2) . dechex((hexdec(substr($encrypted, -2, 2)) + 1) % 256);

        $this->expectException(CryptoException::class);
        Sm4::decrypt($tampered, $key, (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv));
    }

    public function testSm4GcmWrongAadFails(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setAad('correct aad');
        $iv = $opts->getIv();
        $data = 'aad test';
        $encrypted = Sm4::encrypt($data, $key, $opts);

        $this->expectException(CryptoException::class);
        Sm4::decrypt($encrypted, $key, (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv($iv)->setAad('wrong aad'));
    }

    // ─── SM4 New Padding Schemes ──────────────────────────────────────────

    public function testSm4ZeroPaddingRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setPadding('zero');
        $iv = $opts->getIv();
        $data = 'zero padding test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setPadding('zero')->setIv($iv));
        // Zero padding trims trailing \0 bytes, so data ending with \0 will be truncated
        $this->assertStringStartsWith($data, $decrypted);
    }

    public function testSm4Iso10126PaddingRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setPadding('iso10126');
        $iv = $opts->getIv();
        $data = 'ISO 10126 padding test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setPadding('iso10126')->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4AnsiX923PaddingRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setPadding('ansix923');
        $iv = $opts->getIv();
        $data = 'ANSI X9.23 padding test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setPadding('ansix923')->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4Pkcs7PaddingRoundTrip(): void
    {
        $key = bin2hex(random_bytes(16));
        $opts = (new Sm4Options())->setPadding('pkcs7');
        $iv = $opts->getIv();
        $data = 'PKCS7 padding test';
        $encrypted = Sm4::encrypt($data, $key, $opts);
        $decrypted = Sm4::decrypt($encrypted, $key, (new Sm4Options())->setPadding('pkcs7')->setIv($iv));
        $this->assertEquals($data, $decrypted);
    }

    public function testSm4InvalidAnsiX923Padding(): void
    {
        $ref = new \ReflectionClass(Sm4::class);
        $method = $ref->getMethod('maybeUnpad');
        $method->setAccessible(true);

        // Create data with invalid ANSI X9.23: non-zero bytes in padding area
        // Last byte = 3 (pad length), but preceding 2 bytes not all zero
        $data = str_repeat('A', 13) . "\x01\x02\x03";
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('ANSI X9.23');
        $method->invoke(null, $data, 'ansix923');
    }

    public function testSm4OptionsInvalidPadding(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm4Options())->setPadding('invalid_padding');
    }

    public function testSm4OptionsValidPaddings(): void
    {
        foreach (['pkcs5', 'pkcs7', 'zero', 'iso10126', 'ansix923', 'none'] as $padding) {
            $opts = (new Sm4Options())->setPadding($padding);
            $this->assertEquals($padding, $opts->getPadding());
        }
    }

    public function testSm4OptionsValidModes(): void
    {
        foreach ([Sm4::MODE_ECB, Sm4::MODE_CBC, Sm4::MODE_CFB, Sm4::MODE_OFB, Sm4::MODE_CTR, Sm4::MODE_GCM] as $mode) {
            $opts = (new Sm4Options())->setMode($mode);
            $this->assertEquals($mode, $opts->getMode());
        }
    }

    public function testSm4OptionsGcmIvNotRequired32Chars(): void
    {
        // GCM mode allows variable-length IV
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv(bin2hex(random_bytes(12)));
        $this->assertEquals(24, strlen($opts->getIv()));
    }

    public function testSm4OptionsGcmAad(): void
    {
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM);
        $this->assertEquals('', $opts->getAad());
        $opts->setAad('test aad');
        $this->assertEquals('test aad', $opts->getAad());
    }

    public function testSm4OptionsGcmTagLength(): void
    {
        $opts = (new Sm4Options())->setMode(Sm4::MODE_GCM);
        $this->assertEquals(16, $opts->getTagLength());
        $opts->setTagLength(12);
        $this->assertEquals(12, $opts->getTagLength());
    }

    public function testSm4OptionsInvalidTagLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        (new Sm4Options())->setMode(Sm4::MODE_GCM)->setTagLength(7);
    }

    // ─── PEM Import/Export ────────────────────────────────────────────────

    public function testPemExportImportPrivateKeySec1(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $pem = Pem::exportPrivateKey($pair->getPrivateKey(), $pair->getPublicKey());

        $this->assertStringContainsString('BEGIN EC PRIVATE KEY', $pem);
        $this->assertStringContainsString('END EC PRIVATE KEY', $pem);

        $imported = Pem::importPrivateKey($pem);
        $this->assertEquals($pair->getPrivateKey(), $imported['privateKey']);
        $this->assertEquals($pair->getPublicKey(), $imported['publicKey']);
    }

    public function testPemExportImportPrivateKeyWithoutPubKey(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $pem = Pem::exportPrivateKey($pair->getPrivateKey());
        // Public key should be derived
        $imported = Pem::importPrivateKey($pem);
        $this->assertEquals($pair->getPrivateKey(), $imported['privateKey']);
        $this->assertEquals($pair->getPublicKey(), $imported['publicKey']);
    }

    public function testPemExportImportPrivateKeyPkcs8(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $pem = Pem::exportPrivateKeyPkcs8($pair->getPrivateKey());

        $this->assertStringContainsString('BEGIN PRIVATE KEY', $pem);
        $this->assertStringContainsString('END PRIVATE KEY', $pem);

        $imported = Pem::importPrivateKey($pem);
        $this->assertEquals($pair->getPrivateKey(), $imported['privateKey']);
        $this->assertEquals($pair->getPublicKey(), $imported['publicKey']);
    }

    public function testPemExportImportPublicKey(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $pem = Pem::exportPublicKey($pair->getPublicKey());

        $this->assertStringContainsString('BEGIN PUBLIC KEY', $pem);
        $this->assertStringContainsString('END PUBLIC KEY', $pem);

        $imported = Pem::importPublicKey($pem);
        $this->assertEquals($pair->getPublicKey(), $imported);
    }

    public function testPemImportInvalidType(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::importPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n");
    }

    public function testPemImportInvalidPublicKeyType(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::importPublicKey("-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----\n");
    }

    public function testPemExportPrivateKeyInvalidKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::exportPrivateKey('invalid');
    }

    public function testPemExportPublicKeyInvalidKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        Pem::exportPublicKey('invalid');
    }

    public function testPemRoundTripEncryption(): void
    {
        // Full workflow: generate → export PEM → import → encrypt → decrypt
        $pair = Sm2::generateKeyPairHex();
        $privPem = Pem::exportPrivateKey($pair->getPrivateKey(), $pair->getPublicKey());
        $pubPem = Pem::exportPublicKey($pair->getPublicKey());

        $imported = Pem::importPrivateKey($privPem);
        $pubKey = Pem::importPublicKey($pubPem);

        $data = 'PEM round-trip encryption test';
        $encrypted = Sm2::doEncrypt($data, $pubKey);
        $decrypted = Sm2::doDecrypt($encrypted, $imported['privateKey']);
        $this->assertEquals($data, $decrypted);
    }

    public function testPemViaFacade(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $privPem = SmCrypto::exportPrivateKeyPem($pair->getPrivateKey(), $pair->getPublicKey());
        $pubPem = SmCrypto::exportPublicKeyPem($pair->getPublicKey());

        $imported = SmCrypto::importPrivateKeyPem($privPem);
        $pubKey = SmCrypto::importPublicKeyPem($pubPem);

        $this->assertEquals($pair->getPrivateKey(), $imported['privateKey']);
        $this->assertEquals($pair->getPublicKey(), $pubKey);
    }

    // ─── SM2 Key Exchange ─────────────────────────────────────────────────

    public function testKeyExchangeBasic(): void
    {
        // Generate static keypairs for A and B
        $pairA = Sm2::generateKeyPairHex();
        $pairB = Sm2::generateKeyPairHex();

        // Generate ephemeral keypairs for A and B
        $ephA = KeyExchange::generateEphemeralKeyPair();
        $ephB = KeyExchange::generateEphemeralKeyPair();

        // Both parties compute shared key
        $klen = 32; // 32 bytes = 256 bits
        $keyA = KeyExchange::initiatorComputeKey(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            $pairB->getPublicKey(),
            $ephB->getPublicKey(),
            $klen
        );
        $keyB = KeyExchange::responderComputeKey(
            $pairB->getPrivateKey(),
            $ephB->getPrivateKey(),
            $pairA->getPublicKey(),
            $ephA->getPublicKey(),
            $klen
        );

        $this->assertEquals($keyA, $keyB);
        $this->assertEquals(64, strlen($keyA)); // 32 bytes = 64 hex chars
    }

    public function testKeyExchangeDifferentLengths(): void
    {
        $pairA = Sm2::generateKeyPairHex();
        $pairB = Sm2::generateKeyPairHex();
        $ephA = KeyExchange::generateEphemeralKeyPair();
        $ephB = KeyExchange::generateEphemeralKeyPair();

        foreach ([16, 24, 32, 48, 64] as $klen) {
            $keyA = KeyExchange::initiatorComputeKey(
                $pairA->getPrivateKey(),
                $ephA->getPrivateKey(),
                $pairB->getPublicKey(),
                $ephB->getPublicKey(),
                $klen
            );
            $keyB = KeyExchange::responderComputeKey(
                $pairB->getPrivateKey(),
                $ephB->getPrivateKey(),
                $pairA->getPublicKey(),
                $ephA->getPublicKey(),
                $klen
            );
            $this->assertEquals($keyA, $keyB, "Key mismatch for klen=$klen");
            $this->assertEquals($klen * 2, strlen($keyA), "Wrong key length for klen=$klen");
        }
    }

    public function testKeyExchangeCustomIds(): void
    {
        $pairA = Sm2::generateKeyPairHex();
        $pairB = Sm2::generateKeyPairHex();
        $ephA = KeyExchange::generateEphemeralKeyPair();
        $ephB = KeyExchange::generateEphemeralKeyPair();

        $keyA = KeyExchange::initiatorComputeKey(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            $pairB->getPublicKey(),
            $ephB->getPublicKey(),
            32,
            'alice@sm2',
            'bob@sm2'
        );
        $keyB = KeyExchange::responderComputeKey(
            $pairB->getPrivateKey(),
            $ephB->getPrivateKey(),
            $pairA->getPublicKey(),
            $ephA->getPublicKey(),
            32,
            'alice@sm2',
            'bob@sm2'
        );
        $this->assertEquals($keyA, $keyB);
    }

    public function testKeyExchangeInvalidPublicKey(): void
    {
        $pairA = Sm2::generateKeyPairHex();
        $ephA = KeyExchange::generateEphemeralKeyPair();
        $ephB = KeyExchange::generateEphemeralKeyPair();

        $this->expectException(InvalidKeyException::class);
        KeyExchange::initiatorComputeKey(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            'invalid_public_key',
            $ephB->getPublicKey(),
            32
        );
    }

    public function testKeyExchangeViaFacade(): void
    {
        $pairA = Sm2::generateKeyPairHex();
        $pairB = Sm2::generateKeyPairHex();
        $ephA = SmCrypto::generateExchangeKeyPair();
        $ephB = SmCrypto::generateExchangeKeyPair();

        $keyA = SmCrypto::initiatorKeyExchange(
            $pairA->getPrivateKey(),
            $ephA->getPrivateKey(),
            $pairB->getPublicKey(),
            $ephB->getPublicKey(),
            32
        );
        $keyB = SmCrypto::responderKeyExchange(
            $pairB->getPrivateKey(),
            $ephB->getPrivateKey(),
            $pairA->getPublicKey(),
            $ephA->getPublicKey(),
            32
        );
        $this->assertEquals($keyA, $keyB);
    }

    // ─── SM2 getPublicKey ─────────────────────────────────────────────────

    public function testSm2GetPublicKey(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $derivedPub = Sm2::getPublicKey($pair->getPrivateKey());
        $this->assertEquals($pair->getPublicKey(), $derivedPub);
    }

    public function testSm2GetPublicKeyInvalidKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::getPublicKey('invalid');
    }

    // ─── SM2 validatePrivateKey / isOnCurve (public) ──────────────────────

    public function testSm2ValidatePrivateKeyValid(): void
    {
        $pair = Sm2::generateKeyPairHex();
        // Should not throw
        Sm2::validatePrivateKey($pair->getPrivateKey());
        // If we reach here without exception, the key is valid
        $this->addToAssertionCount(1);
    }

    public function testSm2ValidatePrivateKeyInvalid(): void
    {
        $this->expectException(InvalidKeyException::class);
        Sm2::validatePrivateKey('00');
    }

    public function testSm2IsOnCurveValid(): void
    {
        $pair = Sm2::generateKeyPairHex();
        $this->assertTrue(Sm2::isOnCurve($pair->getPublicKey()));
    }

    public function testSm2IsOnCurveInvalid(): void
    {
        $this->assertFalse(Sm2::isOnCurve(str_repeat('0', 128)));
    }

    // ─── Integration: Full SM2 workflow with new features ─────────────────

    public function testFullSm2WorkflowWithPem(): void
    {
        // Generate keypair
        $pair = SmCrypto::generateKeyPair();

        // Export PEM
        $privPem = SmCrypto::exportPrivateKeyPem($pair->getPrivateKey(), $pair->getPublicKey());
        $pubPem = SmCrypto::exportPublicKeyPem($pair->getPublicKey());

        // Import
        $imported = SmCrypto::importPrivateKeyPem($privPem);
        $pubKey = SmCrypto::importPublicKeyPem($pubPem);

        // Sign and verify
        $sig = SmCrypto::sign('test message', $imported['privateKey']);
        $this->assertTrue(SmCrypto::verify('test message', $sig, $pubKey));

        // Encrypt and decrypt
        $encrypted = SmCrypto::encrypt('secret data', $pubKey);
        $decrypted = SmCrypto::decrypt($encrypted, $imported['privateKey']);
        $this->assertEquals('secret data', $decrypted);
    }
}
