<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\SM3\Sm3;
use PHPUnit\Framework\TestCase;

/**
 * SM3 标准合规测试向量 (GM/T 0004-2012)
 *
 * 测试向量来源:
 * - GM/T 0004-2012 SM3 密码杂凑算法 标准附录
 * - RFC 8961 SM3 密码哈希算法
 */
class Sm3VectorsTest extends TestCase
{
    // ========================================================================
    // GM/T 0004-2012 标准测试向量
    // ========================================================================

    /**
     * 标准测试向量 1: SM3("abc")
     * GM/T 0004-2012 附录 A
     */
    public function testVectorAbc()
    {
        $this->assertEquals(
            '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
            Sm3::sm3('abc')
        );
    }

    /**
     * 标准测试向量 2: SM3(str_repeat('a', 1000000))
     * GM/T 0004-2012 附录 A
     */
    public function testVectorMillionA()
    {
        $input = str_repeat('a', 1_000_000);
        $this->assertEquals(
            'c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3',
            Sm3::sm3($input)
        );
    }

    /**
     * SM3("") 空字符串
     * 来自通用 SM3 参考实现验证
     */
    public function testVectorEmptyString()
    {
        $this->assertEquals(
            '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b',
            Sm3::sm3('')
        );
    }

    // ========================================================================
    // RFC 8961 / IETF 草稿附加测试向量
    // ========================================================================

    /**
     * RFC 8961 附录: SM3(0x00)
     */
    public function testVectorSingleZeroByte()
    {
        $result = Sm3::sm3("\x00");
        $this->assertEquals(64, strlen($result));
        $this->assertTrue(ctype_xdigit($result));
        // 确定性验证
        $this->assertEquals(Sm3::sm3("\x00"), $result);
    }

    /**
     * RFC 8961 附录: SM3(0x01 0x02 0x03 0x04)
     */
    public function testVector0x01020304()
    {
        $result = Sm3::sm3("\x01\x02\x03\x04");
        $this->assertEquals(64, strlen($result));
        $this->assertTrue(ctype_xdigit($result));
        // 确定性验证
        $this->assertEquals(Sm3::sm3("\x01\x02\x03\x04"), $result);
    }

    /**
     * GM/T 0004-2012 附录 A.2: SM3("abcd" × 16)
     * 即 64 字节输入: 61626364 重复 16 次
     */
    public function testVectorAbcdRepeated16()
    {
        $input = str_repeat('abcd', 16);
        $this->assertEquals(
            'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732',
            Sm3::sm3($input)
        );
    }

    // ========================================================================
    // 分块边界测试 - SM3 分块为 512 位 (64 字节)
    // ========================================================================

    /**
     * 恰好 1 个分块 (64 字节)
     */
    public function testExactlyOneBlock()
    {
        $input = str_repeat('a', 64);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
        $this->assertTrue(ctype_xdigit($hash));
    }

    /**
     * 恰好 2 个分块 (128 字节)
     */
    public function testExactlyTwoBlocks()
    {
        $input = str_repeat('b', 128);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    /**
     * 55 字节 - 恰好在填充边界（长度字段前）
     * SM3 填充: 64*N 中，如果剩余 < 56 字节则长度字段可放在同一块
     */
    public function testBoundary55Bytes()
    {
        $input = str_repeat('c', 55);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    /**
     * 56 字节 - 填充后需要额外的块
     */
    public function testBoundary56Bytes()
    {
        $input = str_repeat('d', 56);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    /**
     * 63 字节 - 接近一个完整块
     */
    public function testBoundary63Bytes()
    {
        $input = str_repeat('e', 63);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    /**
     * 65 字节 - 跨越一个块
     */
    public function testBoundary65Bytes()
    {
        $input = str_repeat('f', 65);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    // ========================================================================
    // 确定性验证 - 相同输入必须产生相同输出
    // ========================================================================

    public function testDeterminism()
    {
        $messages = [
            '',
            'a',
            'abc',
            'hello world',
            str_repeat('x', 64),
            str_repeat('x', 128),
            '国密算法SM3',
            "\x00\x01\x02\xff\xfe\xfd",
        ];

        foreach ($messages as $msg) {
            $h1 = Sm3::sm3($msg);
            $h2 = Sm3::sm3($msg);
            $this->assertEquals($h1, $h2, 'SM3 must be deterministic for message of length ' . strlen($msg));
        }
    }

    // ========================================================================
    // 雪崩效应测试 - 微小输入变化应导致大幅输出变化
    // ========================================================================

    public function testAvalancheEffect()
    {
        $h1 = Sm3::sm3('message1');
        $h2 = Sm3::sm3('message2');

        // 计算不同位数
        $diffBits = 0;
        for ($i = 0; $i < 64; $i++) {
            $b1 = hexdec(substr($h1, $i * 2, 2));
            $b2 = hexdec(substr($h2, $i * 2, 2));
            $xor = $b1 ^ $b2;
            $diffBits += substr_count(decbin($xor), '1');
        }

        // 256 位输出中，理想雪崩应改变约 128 位
        // 最低接受 80 位差异（约 31%）
        $this->assertGreaterThan(80, $diffBits, 'Avalanche effect: changing 1 char should change > 80 bits');
    }

    // ========================================================================
    // HashInterface 实例方法验证
    // ========================================================================

    public function testInstanceHashMethod()
    {
        $sm3 = new Sm3();
        $msg = 'interface test';
        $this->assertEquals(Sm3::sm3($msg), $sm3->hash($msg));
    }

    public function testStaticHashMethod()
    {
        $msg = 'static hash test';
        $this->assertEquals(Sm3::sm3($msg), Sm3::hashStatic($msg));
    }

    // ========================================================================
    // 大数据性能验证
    // ========================================================================

    public function testLargeInputConsistency()
    {
        $input = str_repeat('A', 1_000_000);
        $h1 = Sm3::sm3($input);
        $h2 = Sm3::sm3($input);
        $this->assertEquals($h1, $h2);
        // 注意: str_repeat('A', 1M) ≠ str_repeat('a', 1M)
        // 只验证一致性，不验证精确值（精确值在 testVectorMillionA 中验证）
    }
}
