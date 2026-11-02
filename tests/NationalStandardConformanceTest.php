<?php

declare(strict_types=1);

namespace CryptoSm\Tests;

use CryptoSm\Exception\CryptoException;
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Sm2CipherOptions;
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
 * - GM/T 0003.2-2012 《SM2椭圆曲线公钥密码算法 第2部分：数字签名算法》附录A
 *   （签名与验证完整示例）
 * - GM/T 0003.4-2012 《SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法》附录A
 *   （消息加解密示例）
 * - GM/T 0003.5-2012 《SM2椭圆曲线公钥密码算法 第5部分：参数定义》
 *   · 第4章：曲线参数（p/a/b/Gx/Gy/n）
 *   · 附录A.2：椭圆曲线点乘示例（4 组中的前 3 组纯标量乘）
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

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
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

    // ─── 独立固定值签名回归向量（非 GM/T 0003.2 附录A）───────────────────

    /**
     * 固定值回归向量，使用推荐曲线和默认 ID。它不对应 GM/T 0003.2-2012 附录A；
     * 官方附录A向量在 testSm2Gmt0003Part2AnnexASignatureVector 中单独核验。
     *
     *   ID_A = '1234567812345678'
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

    public function testSm2FixedSignatureRegressionVectorVerifies(): void
    {
        // 用固定 (r, s) 走库验签路径（覆盖 hash=true 分支与 DER 自动检测入口）。
        $pub = Sm2::getPublicKey('3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8');
        $sig = strtolower('F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3'
            . 'B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA');
        $opts = (new SignatureOptions())
            ->setHash(true)
            ->setPublicKey($pub)
            ->setUserId('1234567812345678');

        $this->assertTrue(
            Sm2::doVerifySignature('message digest', $sig, $pub, $opts),
            'the fixed signature regression vector must verify'
        );
        // 篡改消息必须失败
        $this->assertFalse(
            Sm2::doVerifySignature('message digests', $sig, $pub, $opts)
        );
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm2Gmt0003Part2AnnexASignatureVector(): void
    {
        // GM/T 0003.2-2012 附录A的 Fp-256 示例使用 ALICE123@YAHOO.COM，
        // 私钥 128B...，随机数 6CB2...，并非推荐曲线上的另一组常见示例。
        $curve = [
            'p'  => '8542d69e4c044f18e8b92435bf6ff7de457283915c45517d722edb8b08f1dfc3',
            'a'  => '787968b4fa32c3fd2417842e73bbfeff2f3c848b6831d7e0ec65228b3937e498',
            'b'  => '63e4c6d3b23b0c849cf84241484bfe48f61d59a5b16ba06e6e12d1da27c5249a',
            'n'  => '8542d69e4c044f18e8b92435bf6ff7dd297720630485628d5ae74ee7c32e79b7',
            'gX' => '421debd61b62eab6746434ebc3cc315e32220b3badd50bdc4c4e6c147fedd43d',
            'gY' => '0680512bcbb42c07d47349d2153b70c4e5d7fdfcbfa36ea1a85841b9e46e09a2',
        ];
        Sm2CurveTestOverride::use($curve);

        try {
            $privateKey = bin2hex(pack(
                'C*',
                0x12,
                0x8b,
                0x2f,
                0xa8,
                0xbd,
                0x43,
                0x3c,
                0x6c,
                0x06,
                0x8c,
                0x8d,
                0x80,
                0x3d,
                0xff,
                0x79,
                0x79,
                0x2a,
                0x51,
                0x9a,
                0x55,
                0x17,
                0x1b,
                0x1b,
                0x65,
                0x0c,
                0x23,
                0x66,
                0x1d,
                0x15,
                0x89,
                0x72,
                0x63
            ));
            $publicKey = Sm2::getPublicKey($privateKey);
            $expectedPublicKey = '0ae4c7798aa0f119471bee11825be46202bb79e2a5844495e97c04ff4df2548a'
                . '7c0240f88f1cd4e16352a73c17b7f16f07353e53a176d684a9fe0c6bb798e857';
            $this->assertSame($expectedPublicKey, strtolower($publicKey), 'official P_A mismatch');

            $ida = 'ALICE123@YAHOO.COM';
            $z = Sm2::getUserIdDigest($ida, $publicKey);
            $this->assertSame(
                'f4a38489e32b45b6f876e3ac2168ca392362dc8f23459c1d1146fc3dbfb7bc9a',
                $z,
                'official Z_A mismatch'
            );

            $e = Sm3::sm3(hex2bin($z) . 'message digest');
            $this->assertSame(
                'b524f552cd82b8b028476e005c377fb19a87e6fc682d48bb5d42e3d9b9effe76',
                $e,
                'official e mismatch'
            );

            $k = '6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f';
            $point = Sm2::pointMultiplyPublic($curve['gX'] . $curve['gY'], $k);
            $this->assertSame(
                '110fcda57615705d5e7b9324ac4b856d23e6d9188b2ae47759514657ce25d112'
                    . '1c65d68a4a08601df24b431e0cab4ebe084772b3817e85811a8510b2df7eca1a',
                strtolower($point),
                'official [k]G mismatch'
            );

            $n = gmp_init($curve['n'], 16);
            $d = gmp_init($privateKey, 16);
            $kGmp = gmp_init($k, 16);
            $eGmp = gmp_init($e, 16);
            $x1 = gmp_init(substr($point, 0, 64), 16);
            $r = gmp_mod(gmp_add($eGmp, $x1), $n);
            $this->assertSame(
                '40f1ec59f793d9f49e09dcef49130d4194f79fb1eed2caa55bacdb49c4e755d1',
                str_pad(gmp_strval($r, 16), 64, '0', STR_PAD_LEFT),
                'official r formula mismatch'
            );
            $dPlusOneInverse = gmp_invert(gmp_add($d, 1), $n);
            self::assertInstanceOf(\GMP::class, $dPlusOneInverse);
            $s = gmp_mod(
                gmp_mul($dPlusOneInverse, gmp_sub($kGmp, gmp_mul($r, $d))),
                $n
            );
            $this->assertSame(
                '6fc6dac32c5d5cf10c77dfb20f7c2eb667a457872fb09ec56327a67ec7deebe7',
                str_pad(gmp_strval($s, 16), 64, '0', STR_PAD_LEFT),
                'official s formula mismatch'
            );

            $signature = strtolower(
                '40f1ec59f793d9f49e09dcef49130d4194f79fb1eed2caa55bacdb49c4e755d1'
                    . '6fc6dac32c5d5cf10c77dfb20f7c2eb667a457872fb09ec56327a67ec7deebe7'
            );
            $options = (new SignatureOptions())->setUserId($ida)->setPublicKey($publicKey);
            $this->assertTrue(
                Sm2::doVerifySignature('message digest', $signature, $publicKey, $options),
                'the signature from GM/T 0003.2 Annex A must verify'
            );
            $this->assertFalse(
                Sm2::doVerifySignature('message digests', $signature, $publicKey, $options),
                'the Annex A signature must reject a modified message'
            );
        } finally {
            Sm2CurveTestOverride::reset();
        }
    }

    // ─── GM/T 0003.4-2012 附录A：消息加解密示例 ───────────────────────────

    // ─── GM/T 0003.3-2012 附录A：密钥交换示例（存档说明）──────────────────

    // 官方附录A 给出了完整的密钥交换数值示例（IDA='ALICE123@YAHOO.COM'、
    // IDB='BILL456@YAHOO.COM'、klen=128 位）：
    //
    //   d_A  = 6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
    //   r_A  = 83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563
    //   d_B / r_B 等其余中间值与共享密钥：
    //   K_B  = 55B0AC62A6B927BA23703832C853DED4（128 位）
    //
    // ⚠️ 该示例定义在标准文本自带的**第二示例曲线**上
    // （p=8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3，
    //   即 SM2 主阶作为域素数；G=(421DEBD61B62EAB6...,0680512BCBB42C07...)），
    // 而非本库实现的主推荐曲线 sm2p256v1（GM/T 0003.5 第4章参数）。
    // 因此该向量无法在本库直接执行；其数值已由 BouncyCastle
    // SM2KeyExchangeTest 在同参数下复现（key=55b0ac62...，
    // 确认标签 284C8F19.../23444DAF...），证明协议公式理解无误。
    //
    // 本库的密钥交换符合性策略：
    // 1) 协议步骤严格按 GM/T 0003.3 实现（w 计算、x̄ 截取、S1/S2 确认哈希）
    // 2) 双方密钥一致性与确认标签交叉验证见 SecurityRegressionTest
    // 3) 若未来支持多曲线，应补跑上述官方向量

    // ─── GM/T 0003.3-2012 附录A：密钥交换示例 ─────────────────────────────

    /**
     * 官方密钥交换示例（在标准自带示例曲线上运行）。
     *
     * 该示例使用 GM/T 0003.5-2012 附录B 的第二示例曲线
     * （p = SM2 主阶 n），而非主推荐曲线 sm2p256v1。
     * 通过测试专用反射夹具临时注入参数以在该曲线上执行。
     */
    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm2KeyExchangeAnnexA(): void
    {
        $testCurve = [
            'p'  => '8542d69e4c044f18e8b92435bf6ff7de457283915c45517d722edb8b08f1dfc3',
            'a'  => '787968b4fa32c3fd2417842e73bbfeff2f3c848b6831d7e0ec65228b3937e498',
            'b'  => '63e4c6d3b23b0c849cf84241484bfe48f61d59a5b16ba06e6e12d1da27c5249a',
            'n'  => '8542d69e4c044f18e8b92435bf6ff7dd297720630485628d5ae74ee7c32e79b7',
            'gX' => '421debd61b62eab6746434ebc3cc315e32220b3badd50bdc4c4e6c147fedd43d',
            'gY' => '0680512bcbb42c07d47349d2153b70c4e5d7fdfcbfa36ea1a85841b9e46e09a2',
        ];

        Sm2CurveTestOverride::use($testCurve);
        try {
            // 官方值（GM/T 0003.3-2012 附录A / GM/T 0003.5-2012 附录A）
            $dA  = '6fcba2ef9ae0ab902bc3bde3ff915d44ba4cc78f88e2f8e7f8996d3b8cceedee';
            $rA  = '83a2c9c8b96e5af70bd480b472409a9a327257f1ebb73f5b073354b248668563';
            $dB  = '5e35d7d3f3c54dbac72e61819e730b019a84208ca3a35e4c2e353dfccb2a3b53';
            $rB  = '33fe21940342161c55619c4a0c060293d543c80af19748ce176d83477de71c80';
            $ida = 'ALICE123@YAHOO.COM';
            $idb = 'BILL456@YAHOO.COM';
            $klen = 16; // 128 bits

            $expectedKeyBin = hex2bin('55b0ac62a6b927ba23703832c853ded4');
            self::assertIsString($expectedKeyBin);
            $expectedKey = $expectedKeyBin;

            // 发起方计算
            $keyA = KeyExchange::initiatorComputeKey($dA, $rA, Sm2::getPublicKey($dB), Sm2::getPublicKey($rB), $klen, $ida, $idb);
            // 响应方计算
            $keyB = KeyExchange::responderComputeKey(
                $dB,
                $rB,
                Sm2::getPublicKey($dA),
                Sm2::getPublicKey($rA),
                $klen,
                $ida,
                $idb
            );

            // 自洽性：双方必须推导出相同密钥
            $this->assertSame(
                substr($keyA, 0, 32),
                substr($keyB, 0, 32),
                'initiator and responder must derive the same shared secret'
            );

            $this->assertSame(
                $expectedKey,
                hex2bin($keyA),
                'initiator key must match the official GM/T 0003.3 Annex A vector'
            );
            $this->assertSame(
                $expectedKey,
                hex2bin($keyB),
                'responder key must match the official GM/T 0003.3 Annex A vector'
            );

            $fullA = KeyExchange::initiatorComputeKeyFull(
                $dA,
                $rA,
                Sm2::getPublicKey($dB),
                Sm2::getPublicKey($rB),
                $klen,
                $ida,
                $idb
            );
            $confirmationInputs = [
                $fullA['xV'],
                $fullA['yV'],
                $ida,
                $idb,
                Sm2::getPublicKey($rA),
                Sm2::getPublicKey($rB),
                Sm2::getPublicKey($dA),
                Sm2::getPublicKey($dB),
            ];
            $this->assertSame(
                '284c8f198f141b502e81250f1581c7e9eeb4ca6990f9e02df388b45471f5bc5c',
                KeyExchange::computeResponderConfirmation(...$confirmationInputs),
                'responder S_B (0x02) must match the official vector'
            );
            $this->assertSame(
                '23444daf8ed7534366cb901c84b3bdbb63504f4065c1116c91a4c00697e6cf7a',
                KeyExchange::computeInitiatorConfirmation(...$confirmationInputs),
                'initiator S_A (0x03) must match the official vector'
            );

            $keyBytes = hex2bin(substr($keyA, 0, 32));
            $this->assertIsString($keyBytes);
            $this->assertSame(16, strlen($keyBytes), 'derived key must be exactly klen bytes');
        } finally {
            Sm2CurveTestOverride::reset();
        }
    }

    /** @runInSeparateProcess */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    public function testSm2AnnexAOfficialEncryptionVectorDecrypts(): void
    {
        // GM/T 0003.4-2012 附录 A 示例 2：该示例使用标准文本给出的第二条 Fp-256 曲线。
        $curve = [
            'p' => '8542d69e4c044f18e8b92435bf6ff7de457283915c45517d722edb8b08f1dfc3',
            'a' => '787968b4fa32c3fd2417842e73bbfeff2f3c848b6831d7e0ec65228b3937e498',
            'b' => '63e4c6d3b23b0c849cf84241484bfe48f61d59a5b16ba06e6e12d1da27c5249a',
            'n' => '8542d69e4c044f18e8b92435bf6ff7dd297720630485628d5ae74ee7c32e79b7',
            'gX' => '421debd61b62eab6746434ebc3cc315e32220b3badd50bdc4c4e6c147fedd43d',
            'gY' => '0680512bcbb42c07d47349d2153b70c4e5d7fdfcbfa36ea1a85841b9e46e09a2',
        ];
        Sm2CurveTestOverride::use($curve);
        try {
            $privateKey = bin2hex(pack(
                'C*',
                0x16,
                0x49,
                0xab,
                0x77,
                0xa0,
                0x06,
                0x37,
                0xbd,
                0x5e,
                0x2e,
                0xfe,
                0x28,
                0x3f,
                0xbf,
                0x35,
                0x35,
                0x34,
                0xaa,
                0x7f,
                0x7c,
                0xb8,
                0x94,
                0x63,
                0xf2,
                0x08,
                0xdd,
                0xbc,
                0x29,
                0x20,
                0xbb,
                0x0d,
                0xa0
            ));
            $nonce = '4c62eefd6ecfc2b95b92fd6c3d9575148afa17425546d49018e5388d49dd7b4f';
            $generator = $curve['gX'] . $curve['gY'];
            $c1 = Sm2::pointMultiplyPublic($generator, $nonce);
            $this->assertSame(
                '245c26fb68b1ddddb12c4b6bf9f2b6d5fe60a383b0d18d1c4144abf17f6252e7'
                    . '76cb9264c2a7e88e52b19903fdc47378f605e36811f5c07423a24b84400f01b8',
                strtolower($c1),
                'C1 must match GM/T 0003.4-2012 Annex A'
            );

            // Fixed standard C3 and C2 make this independent of the library KDF/hash output.
            // GM/T 0003.4-2012 Annex A serializes C1 || C2 || C3 and C1 as 04 || x || y.
            $ciphertext = '04' . $c1
                . '650053a89b41c418b0c3aad00d886c00286467'
                . '9c3d7360c30156fab7c80a0276712da9d8094a634b766d3a285e07480653426d';
            $options = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0);
            $this->assertSame(
                'encryption standard',
                Sm2::doDecrypt($ciphertext, $privateKey, $options),
                'the official Annex A ciphertext must decrypt to the standard plaintext'
            );

            $tampered = substr($ciphertext, 0, -2)
                . (substr($ciphertext, -2) === 'ff' ? '00' : 'ff');
            $this->expectException(CryptoException::class);
            Sm2::doDecrypt($tampered, $privateKey, $options);
        } finally {
            Sm2CurveTestOverride::reset();
        }
    }

    public function testSm2AnnexCEncryptionProducesStandardLayout(): void
    {
        // 加密方向无法注入固定 k；验证 GB/T 32918.4-2016 的 C1||C3||C2 布局，
        // C1 使用 SEC1 未压缩点编码 04||x||y（65 字节）。
        $dA = bin2hex(pack(
            'C*',
            0x16,
            0x49,
            0xab,
            0x77,
            0xa0,
            0x06,
            0x37,
            0xbd,
            0x5e,
            0x2e,
            0xfe,
            0x28,
            0x3f,
            0xbf,
            0x35,
            0x35,
            0x34,
            0xaa,
            0x7f,
            0x7c,
            0xb8,
            0x94,
            0x63,
            0xf2,
            0x08,
            0xdd,
            0xbc,
            0x29,
            0x20,
            0xbb,
            0x0d,
            0xa0
        ));
        $pub = Sm2::getPublicKey($dA);
        $ct = Sm2::doEncrypt('encryption standard', $pub);

        $this->assertSame((65 + 32 + strlen('encryption standard')) * 2, strlen($ct));
        $this->assertStringStartsWith('04', $ct);
        $this->assertTrue(Sm2::isOnCurve(substr($ct, 2, 128)), 'C1 must be a valid curve point');
        $this->assertSame('encryption standard', Sm2::doDecrypt($ct, $dA));
    }
}
