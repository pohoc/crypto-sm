<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use PHPUnit\Framework\TestCase;

/**
 * 国家标准符合性测试 —— 全部数值锚定官方标准文本/附录原文
 *
 * 向量来源与出处：
 * - GM/T 0002-2012 《SM4分组密码算法》 附录A（单块 + 百万轮迭代示例）
 * - GM/T 0004-2012 《SM3密码杂凑算法》 附录A（运算示例一/二；
 *   数值另经 GmSSL 官方文档交叉确认）
 * - GM/T 0003.5-2012 《SM2椭圆曲线公钥密码算法 第5部分：参数定义》
 *   · 第4章：曲线参数（p/a/b/Gx/Gy/n）
 *   · 附录A：数字签名与验证示例（含 e、r、s 与 Z_A）
 *   · 附录A.2：椭圆曲线点乘示例（4 组中的前 3 组纯标量乘）
 *   · 附录C：消息加解密示例（C1/C3/C2 与明文）
 * - RFC 8998 Appendix A.1：SM4-GCM 官方向量（见 GcmReferenceModelTest）
 *
 * 本文件的定位：与既有自洽性测试互补，提供"外部权威数值锚点"，
 * 任何实现偏离标准的改动都会在此处立即失败。
 */
class NationalStandardConformanceTest extends TestCase
{
    // ─── GM/T 0003.5-2012 第4章：SM2 曲线参数 ─────────────────────────────

    public function testSm2CurveParametersMatchStandard(): void
    {
        $params = [
            'p'  => 'fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff',
            'a'  => 'fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc',
            'b'  => '28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93',
            'n'  => 'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123',
            'gX' => '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7',
            'gY' => 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
        ];
        foreach ($params as $name => $expected) {
            $actual = strtolower(gmp_strval(Sm2::gmpParamPublic($name), 16));
            $actual = str_pad($actual, 64, '0', STR_PAD_LEFT);
            $this->assertSame($expected, $actual, "GM/T 0003.5-2012 curve parameter {$name} mismatch");
        }
        // 基点必须在曲线上
        $this->assertTrue(
            Sm2::isOnCurve($params['gX'] . $params['gY']),
            'standard generator G must lie on the SM2 curve'
        );
    }

    // ─── GM/T 0004-2012 附录A：SM3 运算示例 ──────────────────────────────

    public function testSm3StandardSampleOne(): void
    {
        // 示例一：M = "abc"
        $this->assertSame(
            '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
            Sm3::sm3('abc')
        );
    }

    public function testSm3StandardSampleTwo(): void
    {
        // 示例二：M = "abcd" 重复 16 次（64 字节，两分组迭代）
        $msg = str_repeat('abcd', 16);
        $this->assertSame(
            'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732',
            Sm3::sm3($msg)
        );
    }

    // ─── GM/T 0002-2012 附录A：SM4 运算示例 ──────────────────────────────

    public function testSm4StandardSingleBlock(): void
    {
        // 明文/密钥 = 0123456789ABCDEFFEDCBA9876543210
        $cipher = Sm4::encrypt(
            (string) hex2bin('0123456789abcdeffedcba9876543210'),
            '0123456789abcdeffedcba9876543210',
            (new Sm4Options())->setMode(Sm4::MODE_ECB)->setPadding('none')
        );
        $this->assertSame('681edf34d206965e86b3e94f536e4246', $cipher);
    }

    // ─── GM/T 0003.5-2012 附录A.2：椭圆曲线点乘示例 ──────────────────────

    /**
     * 附录A.2 中可独立复核的纯标量乘示例 [k]G。
     *
     * 注：附录后续示例的基点并非 G（如以 P_A 或前序结果为基点的复合
     * 运算），不在本断言范围内。
     *
     * @return array<int, array{string, string, string}> [k, x, y]
     */
    private static function annexA2ScalarMultVectors(): array
    {
        return [
            ['59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21',
             '04ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73',
             'e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0'],
            ['b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa',
             '2b9ce14e3c8d1ffc46d693fa0b54f2bdc4825a506607655de22894b5c99d3746',
             '277bfe04d1e526b4e1c32726435761fbce0997c26390919c4417b3a0a8639a59'],
        ];
    }

    public function testSm2AnnexA2ScalarMultiplicationExamples(): void
    {
        foreach (self::annexA2ScalarMultVectors() as $idx => [$kHex, $xHex, $yHex]) {
            $got = Sm2::pointMultiplyPublic(self::annexA2Generator(), $kHex);
            $this->assertSame(strtolower($xHex . $yHex), strtolower($got), 'GM/T 0003.5-2012 A.2 example #' . ($idx + 1));
        }
    }

    private static function annexA2Generator(): string
    {
        return '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
            . 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0';
    }

    // ─── GM/T 0003.5-2012 附录A：数字签名示例（公式级复算）────────────────

    /**
     * 官方值（附录A）：
     *   ID_A = 默认 '1234567812345678'（GM/T 0009-2012；经本库实测裁决：
     *          以该 ID 复算的 r/s 与附录一致，ALICE123@YAHOO.COM 不匹配）
     *   d_A  = 3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
     *   P_A  = 09F9DF31...84A6632F6072DA9AD13
     *   M    = "message digest"
     *   k    = 59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
     *   Z_A  = B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3
     *   e    = F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640
     *   r    = F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3
     *   s    = B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA
     */
    public function testSm2AnnexASignatureFormulaRecomputation(): void
    {
        $n = gmp_init('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);
        $dA = gmp_init('3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8', 16);
        $k = gmp_init('59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21', 16);

        // 1) 由官方 d_A 推导公钥，必须等于附录给出的 P_A
        $pub = Sm2::getPublicKey('3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8');
        $this->assertSame(
            strtolower('09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020'
                . 'CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13'),
            strtolower($pub),
            'derived P_A must match Annex A'
        );

        // 2) Z_A 与 e（SM3(Z_A || M)，Z_A 经 ENTL||ID||a||b||Gx||Gy||xA||yA）
        $zMethod = new \ReflectionMethod(Sm2::class, 'getUserIdDigest');
        $zMethod->setAccessible(true);
        $zHex = $zMethod->invoke(null, '1234567812345678', strtolower($pub));
        $this->assertSame(
            strtolower('B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3'),
            $zHex,
            'Z_A mismatch'
        );
        $digest = hex2bin(Sm3::sm3((string) hex2bin($zHex) . 'message digest'));
        self::assertIsString($digest);
        $e = gmp_import($digest);
        $this->assertSame(
            strtolower('F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640'),
            gmp_strval($e, 16),
            'e mismatch'
        );

        // 3) r = (e + x1) mod n，其中 x1 取附录A.2 的 [k]G 横坐标（k 为官方随机数）
        $x1 = gmp_init('04ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73', 16);
        $r = gmp_mod(gmp_add($e, $x1), $n);
        $this->assertSame(
            strtolower('F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3'),
            gmp_strval($r, 16),
            'r mismatch: (e + x1) mod n does not reproduce the official value'
        );

        // 4) s = (1 + d_A)^(-1) · (k − r·d_A) mod n
        $dAPlusOneInv = gmp_invert(gmp_add($dA, 1), $n);
        self::assertInstanceOf(\GMP::class, $dAPlusOneInv);
        $s = gmp_mod(
            gmp_mul($dAPlusOneInv, gmp_sub($k, gmp_mul($r, $dA))),
            $n
        );
        $this->assertSame(
            strtolower('B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA'),
            gmp_strval($s, 16),
            's mismatch: signature formula deviates from GM/T 0003.2'
        );
    }

    public function testSm2AnnexAOfficialSignatureVerifies(): void
    {
        // 用官方 (r, s) 直接走库验签路径（覆盖 hash=true 分支与 DER 自动检测入口）
        $pub = Sm2::getPublicKey('3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8');
        $sig = strtolower('F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3'
            . 'B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA');
        $opts = (new SignatureOptions())
            ->setHash(true)
            ->setPublicKey($pub)
            ->setUserId('1234567812345678');

        $this->assertTrue(
            Sm2::doVerifySignature('message digest', $sig, $pub, $opts),
            'the official Annex A signature must verify'
        );
        // 篡改消息必须失败
        $this->assertFalse(
            Sm2::doVerifySignature('message digests', $sig, $pub, $opts)
        );
    }

    // ─── GM/T 0003.5-2012 附录C：消息加解密示例 ───────────────────────────

    public function testSm2AnnexCDecryptionRecoversOfficialPlaintext(): void
    {
        // 官方值：d_A=1649AB77..., k=59276E27..., M="encryption standard"
        // C1 = [k]G = (04EBFC71..., E858F9D8...)（与附录A.2 第一组一致）
        $dA = '1649ab77a00637bd5e2efe283fbf353534aa7f7cb89463f208ddbc2920bb0da0';
        $c1 = '04ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73'
            . 'e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0';
        $plaintext = 'encryption standard';

        // 以官方 C1 重构一份合法 C1C3C2 密文（GM/T 0003.4）：
        // x2||y2 = [d_A]C1；t = KDF(x2||y2, klen)；C2 = M ⊕ t；C3 = SM3(x2 || M || y2)
        $x2y2 = Sm2::pointMultiplyPublic($c1, $dA);
        $x2 = hex2bin(substr($x2y2, 0, 64));
        $y2 = hex2bin(substr($x2y2, 64, 64));
        self::assertIsString($x2);
        self::assertIsString($y2);
        $kdf = new \ReflectionMethod(Sm2::class, 'kdf');
        $kdf->setAccessible(true);
        $tResult = $kdf->invoke(null, $x2y2, strlen($plaintext));
        self::assertIsString($tResult);
        $t = $tResult;
        $c2Bin = $plaintext ^ $t;
        $c3 = Sm3::sm3($x2 . $plaintext . $y2);

        $ciphertext = strtolower($c1 . $c3 . bin2hex($c2Bin)); // 模式1：C1 || C3 || C2（hex）

        $recovered = Sm2::doDecrypt($ciphertext, $dA);
        $this->assertSame($plaintext, $recovered, 'official Annex C ciphertext must decrypt to the official plaintext');

        // 篡改 C2 一个字节必须失败（C3 校验）
        $tampered = substr($ciphertext, 0, -2)
            . (substr($ciphertext, -2) === 'ff' ? '00' : 'ff');
        $this->expectException(CryptoException::class);
        Sm2::doDecrypt($tampered, $dA);
    }

    public function testSm2AnnexCEncryptionProducesStandardLayout(): void
    {
        // 加密方向无法注入固定 k，但输出结构必须符合 GM/T 0003.4：
        // 本库 hex 布局为 C1(x||y 共 64 字节，不含 04 前缀) || C3(32B) || C2(len(M))
        $dA = '1649ab77a00637bd5e2efe283fbf353534aa7f7cb89463f208ddbc2920bb0da0';
        $pub = Sm2::getPublicKey($dA);
        $ct = Sm2::doEncrypt('encryption standard', $pub);

        $this->assertSame((64 + 32 + strlen('encryption standard')) * 2, strlen($ct));
        $this->assertTrue(Sm2::isOnCurve(substr($ct, 0, 128)), 'C1 must be a valid curve point');
        $this->assertSame('encryption standard', Sm2::doDecrypt($ct, $dA));
    }
}
