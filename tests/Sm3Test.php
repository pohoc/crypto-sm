<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\SM3\Sm3;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

class Sm3Test extends TestCase
{
    // ========================================================================
    // 基本功能测试
    // ========================================================================

    public function testSm3Basic(): void
    {
        $result = Sm3::sm3('abc');
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3LongInput(): void
    {
        $result = Sm3::sm3('hello world');
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3Empty(): void
    {
        $result = Sm3::sm3('');
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3Consistency(): void
    {
        $msg = 'test message for consistency';
        $result1 = Sm3::sm3($msg);
        $result2 = Sm3::sm3($msg);
        $this->assertEquals($result1, $result2);
    }

    public function testSm3Chinese(): void
    {
        $result = Sm3::sm3('你好世界');
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3ReturnsHexadecimalString(): void
    {
        $result = Sm3::sm3('test');
        $this->assertTrue(ctype_xdigit($result));
    }

    public function testSm3DifferentInputsProduceDifferentOutputs(): void
    {
        $result1 = Sm3::sm3('input1');
        $result2 = Sm3::sm3('input2');
        $this->assertNotEquals($result1, $result2);
    }

    public function testSm3VeryLongInput(): void
    {
        $longInput = str_repeat('a', 10000);
        $result = Sm3::sm3($longInput);
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3SpecialCharacters(): void
    {
        $specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?\n\t\r";
        $result = Sm3::sm3($specialChars);
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3BinaryData(): void
    {
        $binaryData = chr(0) . chr(128) . chr(255);
        $result = Sm3::sm3($binaryData);
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3SingleCharacter(): void
    {
        $result = Sm3::sm3('a');
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3UnicodeCharacters(): void
    {
        $unicode = '😀🎉🚀';
        $result = Sm3::sm3($unicode);
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    public function testSm3Whitespace(): void
    {
        $whitespace = " \t\n\r";
        $result = Sm3::sm3($whitespace);
        $this->assertNotEmpty($result);
        $this->assertEquals(64, strlen($result));
    }

    // ========================================================================
    // 标准测试向量
    // ========================================================================

    public function testSm3KnownTestVector(): void
    {
        // GM/T 0004-2012 标准测试向量: SM3("abc")
        $result = Sm3::sm3('abc');
        $this->assertEquals('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0', $result);
    }

    public function testSm3EmptyStringTestVector(): void
    {
        // SM3("") 标准测试向量
        $result = Sm3::sm3('');
        $this->assertEquals('1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b', $result);
    }

    public function testSm3Abcd16TestVector(): void
    {
        // GM/T 0004-2012 标准测试向量2: SM3("abcd" * 16)
        $result = Sm3::sm3(str_repeat('abcd', 16));
        $this->assertEquals('debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732', $result);
    }

    /**
     * GB/T 32905-2016 标准测试向量: SM3(0x61 重复 1000000 次)
     *
     * @group slow
     */
    #[Group('slow')]
    public function testSm3StandardVectorMillionChars(): void
    {
        $input = str_repeat('a', 1000000);
        $result = Sm3::sm3($input);

        // GB/T 32905-2016 附加测试向量 (与 OpenSSL 交叉验证)
        $expected = 'c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3';
        $this->assertEquals($expected, $result);
    }

    // ========================================================================
    // ISO/IEC 10118-3:2018 附加向量
    // ========================================================================

    public function testSm3SingleCharacterAVector(): void
    {
        // ISO test vector: SM3('a') = 0x61
        $result = Sm3::sm3('a');
        $this->assertEquals('623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88', $result);
    }

    public function testSm3MessageDigestVector(): void
    {
        // ISO test vector: SM3("message digest")
        $result = Sm3::sm3('message digest');
        $this->assertEquals('c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77', $result);
    }

    // ========================================================================
    // 多次调用一致性
    // ========================================================================

    public function testSm3MultipleCallsSameResult(): void
    {
        $msg = 'consistent test';
        $results = [];
        for ($i = 0; $i < 10; $i++) {
            $results[] = Sm3::sm3($msg);
        }
        $firstResult = $results[0];
        foreach ($results as $result) {
            $this->assertEquals($firstResult, $result);
        }
    }

    public function testSm3Reproducibility(): void
    {
        $messages = [
            'test1',
            'test2',
            'hello world',
            '你好世界',
            str_repeat('x', 1000),
        ];
        foreach ($messages as $msg) {
            $hash1 = Sm3::sm3($msg);
            $hash2 = Sm3::sm3($msg);
            $this->assertEquals($hash1, $hash2, "Hash not reproducible for: $msg");
        }
    }

    // ========================================================================
    // HashInterface 实例方法
    // ========================================================================

    public function testSm3ImplementsHashInterface(): void
    {
        $sm3 = new Sm3();
        $this->assertInstanceOf(\CryptoSm\Interfaces\HashInterface::class, $sm3);
    }

    public function testInstanceHashMethodMatchesStatic(): void
    {
        $sm3 = new Sm3();
        $this->assertEquals(Sm3::sm3('test'), $sm3->hash('test'));
    }

    public function testStaticHashMethodAlias(): void
    {
        $this->assertEquals(Sm3::sm3('test'), Sm3::hashStatic('test'));
    }

    public function testInstanceHashMultipleMessages(): void
    {
        $sm3 = new Sm3();
        $messages = ['hello', 'world', '', chr(0) . chr(255)];
        foreach ($messages as $msg) {
            $this->assertEquals(Sm3::sm3($msg), $sm3->hash($msg));
        }
    }

    // ========================================================================
    // 输出格式验证
    // ========================================================================

    public function testOutputAlways64HexChars(): void
    {
        $inputs = ['', 'a', 'abc', str_repeat('x', 100), str_repeat('y', 1000)];
        foreach ($inputs as $input) {
            $result = Sm3::sm3($input);
            $this->assertEquals(64, strlen($result), 'Failed for input length: ' . strlen($input));
            $this->assertTrue(ctype_xdigit($result), 'Output not hex for input length: ' . strlen($input));
        }
    }

    public function testOutputIsLowerCase(): void
    {
        $result = Sm3::sm3('test');
        $this->assertEquals($result, strtolower($result));
    }

    // ========================================================================
    // 雪崩效应
    // ========================================================================

    public function testAvalancheEffect(): void
    {
        $h1 = Sm3::sm3('message1');
        $h2 = Sm3::sm3('message2');

        $diffBits = 0;
        for ($i = 0; $i < 64; $i++) {
            $b1 = hexdec(substr($h1, $i * 2, 2));
            $b2 = hexdec(substr($h2, $i * 2, 2));
            $xor = $b1 ^ $b2;
            $diffBits += substr_count(decbin($xor), '1');
        }

        // 256 位输出中，理想雪崩应改变约 128 位
        $this->assertGreaterThan(80, $diffBits, 'Avalanche effect: changing 1 char should change > 80 bits');
    }

    // ========================================================================
    // 分块边界 (SM3 分块为 512 位 = 64 字节)
    // ========================================================================

    public function testBlockBoundary55Bytes(): void
    {
        $input = str_repeat('c', 55);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    public function testBlockBoundary56Bytes(): void
    {
        $input = str_repeat('d', 56);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    public function testBlockBoundary64Bytes(): void
    {
        $input = str_repeat('a', 64);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    public function testBlockBoundary128Bytes(): void
    {
        $input = str_repeat('b', 128);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    public function testBlockBoundary65Bytes(): void
    {
        $input = str_repeat('f', 65);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    // ========================================================================
    // 更多分块边界
    // ========================================================================

    public function testBlockBoundary119Bytes(): void
    {
        // 119 字节 → 恰好在第二块填充边界附近
        $input = str_repeat('g', 119);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    public function testBlockBoundary120Bytes(): void
    {
        $input = str_repeat('h', 120);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    public function testBlockBoundary63Bytes(): void
    {
        // 63 字节 → 一个完整块减 1
        $input = str_repeat('i', 63);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    public function testBlockBoundary192Bytes(): void
    {
        // 3 个完整块
        $input = str_repeat('j', 192);
        $hash = Sm3::sm3($input);
        $this->assertEquals(64, strlen($hash));
    }

    // ========================================================================
    // SM3 IV 常量反射验证
    // ========================================================================

    public function testSm3IvConstants(): void
    {
        $ref = new \ReflectionClass(Sm3::class);
        $ivConst = $ref->getConstant('IV');
        $this->assertIsArray($ivConst);
        $this->assertCount(8, $ivConst);
        // GM/T 0004-2012 标准值
        $this->assertEquals(0x7380166f, $ivConst[0]);
        $this->assertEquals(0x4914b2b9, $ivConst[1]);
        $this->assertEquals(0x172442d7, $ivConst[2]);
        $this->assertEquals(0xda8a0600, $ivConst[3]);
        $this->assertEquals(0xa96f30bc, $ivConst[4]);
        $this->assertEquals(0x163138aa, $ivConst[5]);
        $this->assertEquals(0xe38dee4d, $ivConst[6]);
        $this->assertEquals(0xb0fb0e4e, $ivConst[7]);
    }

    // ========================================================================
    // SM3 确定性验证 - OpenSSL 交叉
    // ========================================================================

    public function testSm3OpenSslCrossValidation(): void
    {
        // 使用已知值验证与 OpenSSL 一致
        $testCases = [
            'abc' => '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
            '' => '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b',
        ];
        foreach ($testCases as $input => $expected) {
            $this->assertEquals($expected, Sm3::sm3($input), 'SM3 mismatch for input length ' . strlen($input));
        }
    }

    // ========================================================================
    // HashInterface 完整验证
    // ========================================================================

    public function testHashInterfaceMethodSignature(): void
    {
        $ref = new \ReflectionClass(\CryptoSm\Interfaces\HashInterface::class);
        $this->assertTrue($ref->hasMethod('hash'));
        $method = $ref->getMethod('hash');
        $this->assertTrue($method->isPublic());
    }

    // ========================================================================
    // OpenSSL 路径 vs 纯 PHP 路径一致性验证
    // ========================================================================

    public function testOpenSslAndPurePhpProduceSameResult(): void
    {
        if (!function_exists('openssl_digest') || !in_array('sm3', openssl_get_md_methods(), true)) {
            $this->markTestSkipped('OpenSSL SM3 not available');
        }

        $ref = new \ReflectionClass(Sm3::class);
        $method = $ref->getMethod('computeHashPure');
        $method->setAccessible(true);

        $testCases = [
            '',
            'a',
            'abc',
            'hello world',
            '你好世界',
            str_repeat('x', 55),   // 填充边界
            str_repeat('y', 56),   // 填充边界
            str_repeat('z', 64),   // 恰好一个块
            str_repeat('a', 128),  // 两个块
            str_repeat('b', 1000), // 多块
            chr(0) . chr(128) . chr(255), // 二进制
        ];

        foreach ($testCases as $input) {
            $openSslResult = Sm3::sm3($input);
            $purePhpResult = $method->invoke(null, $input);
            $this->assertEquals(
                $openSslResult,
                $purePhpResult,
                'OpenSSL and pure PHP SM3 differ for input length ' . strlen($input)
            );
        }
    }

    public function testPurePhpMatchesStandardVectors(): void
    {
        $ref = new \ReflectionClass(Sm3::class);
        $method = $ref->getMethod('computeHashPure');
        $method->setAccessible(true);

        // GM/T 0004-2012 标准向量
        $this->assertEquals(
            '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
            $method->invoke(null, 'abc'),
            'Pure PHP SM3("abc") mismatch'
        );
        $this->assertEquals(
            '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b',
            $method->invoke(null, ''),
            'Pure PHP SM3("") mismatch'
        );
    }
}
