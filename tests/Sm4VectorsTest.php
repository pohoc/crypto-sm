<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use PHPUnit\Framework\TestCase;

/**
 * SM4 标准合规测试向量 (GM/T 0002-2012)
 *
 * 测试向量来源:
 * - GM/T 0002-2012 SM4 分组密码算法 标准附录
 */
class Sm4VectorsTest extends TestCase
{
    // ========================================================================
    // GM/T 0002-2012 标准测试向量
    // ========================================================================

    /**
     * 标准密钥
     * GM/T 0002-2012 附录
     */
    private const STD_KEY = '0123456789abcdeffedcba9876543210';

    /**
     * 标准明文
     */
    private const STD_PLAINTEXT_HEX = '0123456789abcdeffedcba9876543210';

    /**
     * 标准密文 (1 轮加密)
     * GM/T 0002-2012 附录第 1 轮加密结果
     */
    private const STD_CIPHERTEXT_1 = '681edf34d206965e86b3e94f536e4246';

    /**
     * 标准密文 (1000000 轮迭代加密)
     * GM/T 0002-2012 附录
     */
    private const STD_CIPHERTEXT_MILLION = '595298c7c6fd271f0402f804c33d3f66';

    // ========================================================================
    // ECB 模式标准测试向量
    // ========================================================================

    /**
     * ECB 单块加密
     * GM/T 0002-2012 附录
     */
    public function testEcbSingleBlock(): void
    {
        $plain = hex2bin(self::STD_PLAINTEXT_HEX);
        $this->assertNotFalse($plain);
        $cipher = Sm4::encrypt($plain, self::STD_KEY, (new Sm4Options())->setMode('ecb')->setPadding('none'));
        $this->assertEquals(self::STD_CIPHERTEXT_1, $cipher);
    }

    /**
     * ECB 单块解密
     */
    public function testEcbSingleBlockDecrypt(): void
    {
        $plain = Sm4::decrypt(self::STD_CIPHERTEXT_1, self::STD_KEY, (new Sm4Options())->setMode('ecb')->setPadding('none'));
        $this->assertEquals(hex2bin(self::STD_PLAINTEXT_HEX), $plain);
    }

    /**
     * ECB 100 万轮迭代加密
     * GM/T 0002-2012 附录: 反复加密 100 万次
     */
    public function testEcbMillionRoundIteration(): void
    {
        $opts = (new Sm4Options())->setMode('ecb')->setPadding('none');
        $data = hex2bin(self::STD_PLAINTEXT_HEX);
        $this->assertNotFalse($data);

        for ($i = 0; $i < 1_000_000; $i++) {
            $hex = Sm4::encrypt($data, self::STD_KEY, $opts);
            $data = hex2bin($hex);
            $this->assertNotFalse($data);
        }

        $this->assertEquals(self::STD_CIPHERTEXT_MILLION, bin2hex($data));
    }

    // ========================================================================
    // CBC 模式标准测试向量
    // ========================================================================

    /**
     * CBC 单块加密
     */
    public function testCbcSingleBlock(): void
    {
        $iv = '000102030405060708090a0b0c0d0e0f';
        $plain = hex2bin(self::STD_PLAINTEXT_HEX);
        $this->assertNotFalse($plain);
        $opts = (new Sm4Options())->setMode('cbc')->setPadding('none')->setIv($iv);

        $cipher = Sm4::encrypt($plain, self::STD_KEY, $opts);
        $this->assertEquals('a9a268883a336315bac0c9c9ff350ab1', $cipher);
    }

    /**
     * CBC 单块解密
     */
    public function testCbcSingleBlockDecrypt(): void
    {
        $iv = '000102030405060708090a0b0c0d0e0f';
        $opts = (new Sm4Options())->setMode('cbc')->setPadding('none')->setIv($iv);

        $plain = Sm4::decrypt('a9a268883a336315bac0c9c9ff350ab1', self::STD_KEY, $opts);
        $this->assertEquals(hex2bin(self::STD_PLAINTEXT_HEX), $plain);
    }

    /**
     * CBC 多块加密/解密
     */
    public function testCbcMultiBlock(): void
    {
        $iv = '000102030405060708090a0b0c0d0e0f';
        $opts = (new Sm4Options())->setMode('cbc')->setPadding('none')->setIv($iv);

        // 2 块明文
        $plain = hex2bin(self::STD_PLAINTEXT_HEX . self::STD_PLAINTEXT_HEX);
        $this->assertNotFalse($plain);
        $cipher = Sm4::encrypt($plain, self::STD_KEY, $opts);
        $this->assertEquals(64, strlen($cipher));

        $decrypted = Sm4::decrypt($cipher, self::STD_KEY, $opts);
        $this->assertEquals($plain, $decrypted);
    }

    // ========================================================================
    // PKCS7 填充测试
    // ========================================================================

    /**
     * 1 字节消息 → 16 字节填充 → 32 hex 密文
     */
    public function testPkcs7PaddingOneByte(): void
    {
        $opts = (new Sm4Options())->setMode('ecb');
        $cipher = Sm4::encrypt('a', self::STD_KEY, $opts);
        $this->assertEquals(32, strlen($cipher));

        $plain = Sm4::decrypt($cipher, self::STD_KEY, $opts);
        $this->assertEquals('a', $plain);
    }

    /**
     * 15 字节消息 → 1 字节填充 → 32 hex 密文
     */
    public function testPkcs7PaddingFifteenBytes(): void
    {
        $opts = (new Sm4Options())->setMode('ecb');
        $msg = str_repeat('a', 15);
        $cipher = Sm4::encrypt($msg, self::STD_KEY, $opts);
        $this->assertEquals(32, strlen($cipher));

        $plain = Sm4::decrypt($cipher, self::STD_KEY, $opts);
        $this->assertEquals($msg, $plain);
    }

    /**
     * 16 字节消息 → 16 字节填充 → 64 hex 密文
     * PKCS7: 整块时额外添加一个完整填充块
     */
    public function testPkcs7PaddingExactBlock(): void
    {
        $opts = (new Sm4Options())->setMode('ecb');
        $msg = str_repeat('a', 16);
        $cipher = Sm4::encrypt($msg, self::STD_KEY, $opts);
        $this->assertEquals(64, strlen($cipher));

        $plain = Sm4::decrypt($cipher, self::STD_KEY, $opts);
        $this->assertEquals($msg, $plain);
    }

    /**
     * No padding 模式: 非对齐数据应抛异常
     */
    public function testNoPaddingNonAlignedRejected(): void
    {
        $this->expectException(\CryptoSm\Exception\InvalidKeyException::class);
        $opts = (new Sm4Options())->setMode('ecb')->setPadding('none');
        Sm4::encrypt('short', self::STD_KEY, $opts);
    }

    // ========================================================================
    // 跨模式一致性测试
    // ========================================================================

    /**
     * ECB + CBC 对相同数据各自正确加解密
     */
    public function testEcbAndCbcBothCorrect(): void
    {
        $iv = '000102030405060708090a0b0c0d0e0f';
        $msg = str_repeat('A', 32); // 2 blocks

        $ecbOpts = (new Sm4Options())->setMode('ecb');
        $cbcOpts = (new Sm4Options())->setMode('cbc')->setIv($iv);

        $ecbCipher = Sm4::encrypt($msg, self::STD_KEY, $ecbOpts);
        $cbcCipher = Sm4::encrypt($msg, self::STD_KEY, $cbcOpts);

        // ECB 和 CBC 密文应不同（CBC 有 IV XOR）
        $this->assertNotEquals($ecbCipher, $cbcCipher);

        // 各自解密正确
        $this->assertEquals($msg, Sm4::decrypt($ecbCipher, self::STD_KEY, $ecbOpts));
        $this->assertEquals($msg, Sm4::decrypt($cbcCipher, self::STD_KEY, $cbcOpts));
    }

    /**
     * ECB 相同明文产生相同密文（ECB 的固有特性，也是其不安全的原因）
     */
    public function testEcbSameBlockProducesSameCiphertext(): void
    {
        $opts = (new Sm4Options())->setMode('ecb')->setPadding('none');
        $block = hex2bin('0123456789abcdeffedcba9876543210');
        $twoBlocks = $block . $block;

        $cipher = Sm4::encrypt($twoBlocks, self::STD_KEY, $opts);
        // 两个相同块的密文应该相同
        $block1Cipher = substr($cipher, 0, 32);
        $block2Cipher = substr($cipher, 32, 32);
        $this->assertEquals($block1Cipher, $block2Cipher, 'ECB 模式: 相同明文块应产生相同密文块');
    }

    /**
     * CBC 相同明文产生不同密文（因为 IV XOR）
     */
    public function testCbcSameBlockProducesDifferentCiphertext(): void
    {
        $iv = '000102030405060708090a0b0c0d0e0f';
        $opts = (new Sm4Options())->setMode('cbc')->setPadding('none')->setIv($iv);
        $block = hex2bin('0123456789abcdeffedcba9876543210');
        $twoBlocks = $block . $block;

        $cipher = Sm4::encrypt($twoBlocks, self::STD_KEY, $opts);
        $block1Cipher = substr($cipher, 0, 32);
        $block2Cipher = substr($cipher, 32, 32);
        $this->assertNotEquals($block1Cipher, $block2Cipher, 'CBC 模式: 相同明文块应产生不同密文块');
    }

    // ========================================================================
    // 边界条件测试
    // ========================================================================

    /**
     * 空消息 + PKCS7 填充
     */
    public function testEmptyMessageWithPkcs7(): void
    {
        $opts = (new Sm4Options())->setMode('ecb');
        $cipher = Sm4::encrypt('', self::STD_KEY, $opts);
        $this->assertEquals(32, strlen($cipher)); // 16 字节填充
        $plain = Sm4::decrypt($cipher, self::STD_KEY, $opts);
        $this->assertEquals('', $plain);
    }

    /**
     * 空消息 + 无填充
     */
    public function testEmptyMessageNoPadding(): void
    {
        $opts = (new Sm4Options())->setMode('ecb')->setPadding('none');
        // 空数据长度为 0，是 16 的倍数
        $cipher = Sm4::encrypt('', self::STD_KEY, $opts);
        $this->assertEquals('', $cipher);
    }

    /**
     * 全零密钥
     */
    public function testAllZeroKey(): void
    {
        $key = str_repeat('0', 32);
        $msg = 'test message';
        $opts = (new Sm4Options())->setMode('ecb');
        $cipher = Sm4::encrypt($msg, $key, $opts);
        $plain = Sm4::decrypt($cipher, $key, $opts);
        $this->assertEquals($msg, $plain);
    }

    /**
     * 全一密钥
     */
    public function testAllOneKey(): void
    {
        $key = str_repeat('f', 32);
        $msg = 'test message';
        $opts = (new Sm4Options())->setMode('ecb');
        $cipher = Sm4::encrypt($msg, $key, $opts);
        $plain = Sm4::decrypt($cipher, $key, $opts);
        $this->assertEquals($msg, $plain);
    }

    /**
     * 全零 IV
     */
    public function testAllZeroIv(): void
    {
        $iv = str_repeat('0', 32);
        $msg = 'test message';
        $opts = (new Sm4Options())->setMode('cbc')->setIv($iv);
        $cipher = Sm4::encrypt($msg, self::STD_KEY, $opts);
        $plain = Sm4::decrypt($cipher, self::STD_KEY, $opts);
        $this->assertEquals($msg, $plain);
    }

    /**
     * 大数据量加解密
     */
    public function testLargeData(): void
    {
        $iv = '000102030405060708090a0b0c0d0e0f';
        $msg = str_repeat('Large data test. ', 1000);
        $opts = (new Sm4Options())->setMode('cbc')->setIv($iv);
        $cipher = Sm4::encrypt($msg, self::STD_KEY, $opts);
        $plain = Sm4::decrypt($cipher, self::STD_KEY, $opts);
        $this->assertEquals($msg, $plain);
    }
}
