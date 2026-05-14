#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * 国密算法性能测试脚本
 *
 * 测试 SM2、SM3、SM4 各项操作的平均耗时和吞吐量。
 *
 * 用法: php scripts/benchmark.php
 */

require __DIR__ . '/../vendor/autoload.php';

use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

// ============================================================================
// 配置
// ============================================================================

const WARMUP_ITERATIONS = 3;       // 预热次数（不计入统计）
const SM3_ITERATIONS = 1000;       // SM3 迭代次数
const SM4_ITERATIONS = 1000;       // SM4 迭代次数
const SM2_SIGN_ITERATIONS = 50;    // SM2 签名迭代次数
const SM2_ENCRYPT_ITERATIONS = 50; // SM2 加密迭代次数
const SM2_KEYGEN_ITERATIONS = 20;  // SM2 密钥生成迭代次数
const HMAC_ITERATIONS = 1000;      // HMAC-SM3 迭代次数
const PEM_ITERATIONS = 100;        // PEM 迭代次数
const KEY_EXCHANGE_ITERATIONS = 20; // 密钥交换迭代次数
const GCM_ITERATIONS = 200;        // GCM 迭代次数

const DATA_SIZES = [16, 64, 256, 1024, 4096]; // 测试数据大小（字节）
const BASELINE_FILE = __DIR__ . '/benchmark-baseline.json';

// ============================================================================
// 辅助函数
// ============================================================================

function formatTime(float $seconds): string
{
    if ($seconds < 0.001) {
        return sprintf('%.2f μs', $seconds * 1_000_000);
    }
    if ($seconds < 1.0) {
        return sprintf('%.2f ms', $seconds * 1_000);
    }

    return sprintf('%.2f s', $seconds);
}

function formatBytes(int $bytes): string
{
    static $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $size = (float) $bytes;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }

    return sprintf('%.1f %s', $size, $units[$i]);
}

function formatThroughput(float $bytesPerSecond): string
{
    static $units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    $i = 0;
    $speed = $bytesPerSecond;
    while ($speed >= 1024 && $i < count($units) - 1) {
        $speed /= 1024;
        $i++;
    }

    return sprintf('%.1f %s', $speed, $units[$i]);
}

/**
 * @param callable(): void $fn
 */
function benchmark(string $name, callable $fn, int $iterations): array
{
    // 预热
    for ($i = 0; $i < WARMUP_ITERATIONS; $i++) {
        $fn();
    }

    $times = [];
    for ($i = 0; $i < $iterations; $i++) {
        $start = hrtime(true);
        $fn();
        $end = hrtime(true);
        $times[] = ($end - $start) / 1_000_000_000; // 纳秒 → 秒
    }

    $avg = array_sum($times) / count($times);
    $min = min($times);
    $max = max($times);
    sort($times);
    $p50 = $times[(int) floor(count($times) * 0.50)];
    $p95 = $times[(int) floor(count($times) * 0.95)];
    $p99 = $times[min((int) floor(count($times) * 0.99), count($times) - 1)];

    return [
        'name' => $name,
        'iterations' => $iterations,
        'avg' => $avg,
        'min' => $min,
        'max' => $max,
        'p50' => $p50,
        'p95' => $p95,
        'p99' => $p99,
    ];
}

function printResult(array $result): void
{
    printf(
        "  %-40s  avg: %s  min: %s  p50: %s  p95: %s  p99: %s\n",
        $result['name'],
        formatTime($result['avg']),
        formatTime($result['min']),
        formatTime($result['p50']),
        formatTime($result['p95']),
        formatTime($result['p99']),
    );
}

function printSection(string $title): void
{
    echo "\n" . str_repeat('=', 80) . "\n";
    echo "  {$title}\n";
    echo str_repeat('=', 80) . "\n";
}

/**
 * @return array<string, array{max_avg_seconds: float, note: string}>
 */
function loadBaseline(): array
{
    if (!is_file(BASELINE_FILE)) {
        return [];
    }

    $json = file_get_contents(BASELINE_FILE);
    if ($json === false) {
        return [];
    }

    $data = json_decode($json, true);
    if (!is_array($data) || !isset($data['metrics']) || !is_array($data['metrics'])) {
        return [];
    }

    $baseline = [];
    foreach ($data['metrics'] as $metric) {
        if (!is_array($metric) || !isset($metric['label'], $metric['max_avg_seconds'])) {
            continue;
        }
        $label = (string) $metric['label'];
        $baseline[$label] = [
            'max_avg_seconds' => (float) $metric['max_avg_seconds'],
            'note' => isset($metric['note']) ? (string) $metric['note'] : '',
        ];
    }

    return $baseline;
}

function printBaselineCheck(array $measured, array $baseline): void
{
    if ($baseline === []) {
        return;
    }

    printSection('性能基线检查');
    echo "\n";
    printf("  %-28s  %-12s  %-12s  %-8s\n", '指标', '实测', '阈值', '结果');
    echo str_repeat('-', 72) . "\n";

    foreach ($baseline as $label => $config) {
        if (!isset($measured[$label])) {
            printf("  %-28s  %-12s  %-12s  %-8s\n", $label, '-', formatTime($config['max_avg_seconds']), 'MISS');
            continue;
        }

        $avg = $measured[$label];
        $status = $avg <= $config['max_avg_seconds'] ? 'PASS' : 'WARN';
        printf(
            "  %-28s  %-12s  %-12s  %-8s\n",
            $label,
            formatTime($avg),
            formatTime($config['max_avg_seconds']),
            $status
        );
        if ($config['note'] !== '') {
            printf("    note: %s\n", $config['note']);
        }
    }
}

function printSystemInfo(): void
{
    echo "系统信息\n";
    echo '  PHP 版本:         ' . PHP_VERSION . "\n";
    echo '  操作系统:         ' . PHP_OS_FAMILY . "\n";
    echo '  GMP 扩展:         ' . (extension_loaded('gmp') ? '✓' : '✗') . "\n";
    echo '  OpenSSL 扩展:     ' . (extension_loaded('openssl') ? '✓' : '✗') . "\n";
    if (extension_loaded('openssl')) {
        echo '  OpenSSL 版本:     ' . OPENSSL_VERSION_TEXT . "\n";
    }

    // 检测 OpenSSL SM3 支持
    $sm3Available = function_exists('openssl_digest') && in_array('sm3', openssl_get_md_methods(), true);
    echo '  OpenSSL SM3:      ' . ($sm3Available ? '✓ (加速)' : '✗ (纯PHP回退)') . "\n";

    // 检测 OpenSSL SM4-GCM 支持；当前库的 GCM 路径仍使用 Gcm 后端。
    $gcmKey = hex2bin('0123456789abcdeffedcba9876543210');
    $gcmIv = random_bytes(12);
    $gcmTag = '';
    $gcmResult = @openssl_encrypt('probe', 'SM4-GCM', $gcmKey, OPENSSL_RAW_DATA, $gcmIv, $gcmTag, '', 16);
    $gcmAvailable = ($gcmResult !== false);
    echo '  OpenSSL SM4-GCM:  ' . ($gcmAvailable ? '✓ (可用，当前未作为后端)' : '✗') . "\n";

    echo '  当前时间:         ' . date('Y-m-d H:i:s') . "\n";
}

// ============================================================================
// 主测试
// ============================================================================

echo "╔══════════════════════════════════════════════════════════════════╗\n";
echo "║          国密算法性能测试 (SM2 / SM3 / SM4)                     ║\n";
echo "╚══════════════════════════════════════════════════════════════════╝\n";

printSystemInfo();
$baseline = loadBaseline();
$baselineMeasurements = [];

// --- SM3 测试 ---
printSection('SM3 哈希性能');

$sm3Results = [];
foreach (DATA_SIZES as $size) {
    $data = str_repeat('A', $size);
    $sm3Results[] = benchmark(
        "SM3 哈希 ({$size}B = " . formatBytes($size) . ')',
        fn () => Sm3::sm3($data),
        SM3_ITERATIONS,
    );
}

foreach ($sm3Results as $r) {
    printResult($r);
}
$baselineMeasurements['SM3 哈希 (4096B)'] = $sm3Results[4]['avg'];

// SM3 吞吐量
echo "\n  SM3 吞吐量:\n";
foreach (DATA_SIZES as $i => $size) {
    $avg = $sm3Results[$i]['avg'];
    $throughput = $avg > 0 ? $size / $avg : 0;
    printf("    %8s 输入: %s\n", formatBytes($size), formatThroughput($throughput));
}

// SM3 流式哈希
echo "\n  SM3 流式哈希 (分块更新):\n";
$sm3StreamResults = [];
foreach ([1024, 4096] as $totalSize) {
    $chunkSize = 256;
    $chunks = [];
    for ($i = 0; $i < $totalSize; $i += $chunkSize) {
        $chunks[] = str_repeat('A', min($chunkSize, $totalSize - $i));
    }
    $sm3StreamResults[] = benchmark(
        "SM3 流式哈希 ({$totalSize}B, {$chunkSize}B/chunk)",
        function () use ($chunks) {
            $hasher = new Sm3();
            foreach ($chunks as $chunk) {
                $hasher->update($chunk);
            }
            $hasher->finalize();
        },
        SM3_ITERATIONS,
    );
}
foreach ($sm3StreamResults as $r) {
    printResult($r);
}

// SM3 流式 vs 一次性
echo "\n  SM3 一次性 vs 流式 (4096B):\n";
$data4096 = str_repeat('A', 4096);
$r = benchmark('SM3 一次性 (4096B)', fn () => Sm3::sm3($data4096), SM3_ITERATIONS);
printResult($r);
$chunks4096 = str_split($data4096, 256);
$r = benchmark('SM3 流式 (4096B, 256B/chunk)', function () use ($chunks4096) {
    $hasher = new Sm3();
    foreach ($chunks4096 as $chunk) {
        $hasher->update($chunk);
    }
    $hasher->finalize();
}, SM3_ITERATIONS);
printResult($r);

// --- HMAC-SM3 测试 ---
printSection('HMAC-SM3 性能');

$hmacResults = [];
$hmacKey = 'this_is_a_secret_key_for_hmac_sm3';
foreach (DATA_SIZES as $size) {
    $data = str_repeat('A', $size);
    $hmacResults[] = benchmark(
        "HMAC-SM3 ({$size}B)",
        fn () => HmacSm3::hmac($hmacKey, $data),
        HMAC_ITERATIONS,
    );
}
foreach ($hmacResults as $r) {
    printResult($r);
}
$baselineMeasurements['HMAC-SM3 (4096B)'] = $hmacResults[4]['avg'];

// HMAC-SM3 流式
echo "\n  HMAC-SM3 流式:\n";
$data1024 = str_repeat('A', 1024);
$chunks1024 = str_split($data1024, 256);
$r = benchmark('HMAC-SM3 一次性 (1024B)', fn () => HmacSm3::hmac($hmacKey, $data1024), HMAC_ITERATIONS);
printResult($r);
$r = benchmark('HMAC-SM3 流式 (1024B, 256B/chunk)', function () use ($hmacKey, $chunks1024) {
    $hmac = HmacSm3::create($hmacKey);
    foreach ($chunks1024 as $chunk) {
        $hmac->update($chunk);
    }
    $hmac->finalize();
}, HMAC_ITERATIONS);
printResult($r);

// HMAC-SM3 吞吐量
echo "\n  HMAC-SM3 吞吐量:\n";
foreach (DATA_SIZES as $i => $size) {
    $avg = $hmacResults[$i]['avg'];
    $throughput = $avg > 0 ? $size / $avg : 0;
    printf("    %8s 输入: %s\n", formatBytes($size), formatThroughput($throughput));
}

// --- SM4 测试 ---
printSection('SM4 对称加密性能');

$sm4Key = '0123456789abcdeffedcba9876543210';
$sm4Iv = 'fedcba98765432100123456789abcdef';

// ECB 模式
echo "\n  ECB 模式:\n";
$sm4EcbResults = [];
foreach (DATA_SIZES as $size) {
    $data = str_repeat('A', $size);
    $options = (new Sm4Options())->setMode('ecb');
    $sm4EcbResults[] = benchmark(
        "SM4-ECB 加密 ({$size}B)",
        fn () => Sm4::encrypt($data, $sm4Key, $options),
        SM4_ITERATIONS,
    );
}
foreach ($sm4EcbResults as $r) {
    printResult($r);
}

echo "\n  CBC 模式:\n";
$sm4CbcResults = [];
foreach (DATA_SIZES as $size) {
    $data = str_repeat('A', $size);
    $options = (new Sm4Options())->setMode('cbc')->setIv($sm4Iv);
    $sm4CbcResults[] = benchmark(
        "SM4-CBC 加密 ({$size}B)",
        fn () => Sm4::encrypt($data, $sm4Key, $options),
        SM4_ITERATIONS,
    );
}
foreach ($sm4CbcResults as $r) {
    printResult($r);
}
$baselineMeasurements['SM4-CBC 加密 (1024B)'] = $sm4CbcResults[3]['avg'];

// CFB 模式
echo "\n  CFB 模式:\n";
$sm4CfbResults = [];
foreach ([64, 256, 1024] as $size) {
    $data = str_repeat('A', $size);
    $options = (new Sm4Options())->setMode('cfb')->setIv($sm4Iv);
    $sm4CfbResults[] = benchmark(
        "SM4-CFB 加密 ({$size}B)",
        fn () => Sm4::encrypt($data, $sm4Key, $options),
        SM4_ITERATIONS,
    );
}
foreach ($sm4CfbResults as $r) {
    printResult($r);
}

// OFB 模式
echo "\n  OFB 模式:\n";
$sm4OfbResults = [];
foreach ([64, 256, 1024] as $size) {
    $data = str_repeat('A', $size);
    $options = (new Sm4Options())->setMode('ofb')->setIv($sm4Iv);
    $sm4OfbResults[] = benchmark(
        "SM4-OFB 加密 ({$size}B)",
        fn () => Sm4::encrypt($data, $sm4Key, $options),
        SM4_ITERATIONS,
    );
}
foreach ($sm4OfbResults as $r) {
    printResult($r);
}

// CTR 模式
echo "\n  CTR 模式:\n";
$sm4CtrResults = [];
foreach ([64, 256, 1024] as $size) {
    $data = str_repeat('A', $size);
    $options = (new Sm4Options())->setMode('ctr')->setIv($sm4Iv);
    $sm4CtrResults[] = benchmark(
        "SM4-CTR 加密 ({$size}B)",
        fn () => Sm4::encrypt($data, $sm4Key, $options),
        SM4_ITERATIONS,
    );
}
foreach ($sm4CtrResults as $r) {
    printResult($r);
}

// GCM 模式
echo "\n  GCM 模式:\n";
$sm4GcmIv = bin2hex(random_bytes(12)); // 12 字节 IV
$gcmAvailable = false;
$gcmKey = hex2bin($sm4Key);
$gcmIv = hex2bin($sm4GcmIv);
$gcmTag = '';
$gcmProbeResult = @openssl_encrypt('probe', 'SM4-GCM', $gcmKey, OPENSSL_RAW_DATA, $gcmIv, $gcmTag, '', 16);
$gcmAvailable = ($gcmProbeResult !== false);
echo '  SM4-GCM 后端: Gcm (OpenSSL SM4-ECB + 本库 GHASH)' . ($gcmAvailable ? '；OpenSSL SM4-GCM 可用但当前未作为后端' : '') . "\n\n";

$sm4GcmEncResults = [];
$sm4GcmDecResults = [];
foreach ([64, 256, 1024] as $size) {
    $data = str_repeat('A', $size);
    $options = (new Sm4Options())->setMode('gcm')->setIv($sm4GcmIv);
    $ct = Sm4::encrypt($data, $sm4Key, $options);
    $sm4GcmEncResults[] = benchmark(
        "SM4-GCM 加密 ({$size}B)",
        fn () => Sm4::encrypt($data, $sm4Key, $options),
        GCM_ITERATIONS,
    );
    $sm4GcmDecResults[] = benchmark(
        "SM4-GCM 解密 ({$size}B)",
        fn () => Sm4::decrypt($ct, $sm4Key, $options),
        GCM_ITERATIONS,
    );
}
echo "  加密:\n";
foreach ($sm4GcmEncResults as $r) {
    printResult($r);
}
$baselineMeasurements['SM4-GCM 加密 (1024B)'] = $sm4GcmEncResults[2]['avg'];
echo "\n  解密:\n";
foreach ($sm4GcmDecResults as $r) {
    printResult($r);
}

// GCM with AAD
echo "\n  GCM + AAD (附加认证数据):\n";
$optionsWithAad = (new Sm4Options())->setMode('gcm')->setIv($sm4GcmIv)->setAad('additional authenticated data for benchmark');
$r = benchmark(
    'SM4-GCM 加密 + AAD (256B)',
    fn () => Sm4::encrypt(str_repeat('A', 256), $sm4Key, $optionsWithAad),
    GCM_ITERATIONS,
);
printResult($r);

// SM4 解密
echo "\n  SM4-CBC 解密:\n";
$sm4DecResults = [];
foreach (DATA_SIZES as $size) {
    $data = str_repeat('A', $size);
    $options = (new Sm4Options())->setMode('cbc')->setIv($sm4Iv);
    $ct = Sm4::encrypt($data, $sm4Key, $options);
    $sm4DecResults[] = benchmark(
        "SM4-CBC 解密 ({$size}B)",
        fn () => Sm4::decrypt($ct, $sm4Key, $options),
        SM4_ITERATIONS,
    );
}
foreach ($sm4DecResults as $r) {
    printResult($r);
}

// SM4 填充模式
echo "\n  SM4 填充模式 (CBC, 256B):\n";
$padData = str_repeat('A', 256);
foreach (['pkcs5', 'zero', 'iso10126', 'ansix923', 'none'] as $padding) {
    if ($padding === 'none') {
        $padData = str_repeat('A', 256); // 256 是 16 的倍数
    } else {
        $padData = str_repeat('A', 250); // 非对齐，测试填充
    }
    $options = (new Sm4Options())->setMode('cbc')->setIv($sm4Iv)->setPadding($padding);
    $r = benchmark(
        "SM4-CBC 加密 (padding={$padding})",
        fn () => Sm4::encrypt($padData, $sm4Key, $options),
        SM4_ITERATIONS,
    );
    printResult($r);
}

// SM4 吞吐量
echo "\n  SM4 吞吐量 (CBC 加密):\n";
foreach (DATA_SIZES as $i => $size) {
    $avg = $sm4CbcResults[$i]['avg'];
    $throughput = $avg > 0 ? $size / $avg : 0;
    printf("    %8s 输入: %s\n", formatBytes($size), formatThroughput($throughput));
}

// SM4 模式对比
echo "\n  SM4 模式吞吐量对比 (1024B):\n";
$refSize = 1024;
if (isset($sm4EcbResults[3])) {
    printf("    ECB: %s\n", formatThroughput($refSize / $sm4EcbResults[3]['avg']));
}
if (isset($sm4CbcResults[3])) {
    printf("    CBC: %s\n", formatThroughput($refSize / $sm4CbcResults[3]['avg']));
}
if (isset($sm4CfbResults[2])) {
    printf("    CFB: %s\n", formatThroughput($refSize / $sm4CfbResults[2]['avg']));
}
if (isset($sm4OfbResults[2])) {
    printf("    OFB: %s\n", formatThroughput($refSize / $sm4OfbResults[2]['avg']));
}
if (isset($sm4CtrResults[2])) {
    printf("    CTR: %s\n", formatThroughput($refSize / $sm4CtrResults[2]['avg']));
}
if (isset($sm4GcmEncResults[2])) {
    printf("    GCM: %s\n", formatThroughput($refSize / $sm4GcmEncResults[2]['avg']));
}

// --- SM2 测试 ---
printSection('SM2 非对称加密性能');

// 密钥生成
echo "\n  密钥生成:\n";
$r = benchmark('SM2 密钥生成', fn () => Sm2::generateKeyPairHex(), SM2_KEYGEN_ITERATIONS);
printResult($r);

// 生成测试密钥对
$kp = Sm2::generateKeyPairHex();
$privateKey = $kp->getPrivateKey();
$publicKey = $kp->getPublicKey();

// 签名
echo "\n  签名:\n";
$sm2SignResults = [];
foreach ([16, 256, 1024] as $size) {
    $data = str_repeat('A', $size);
    $sm2SignResults[] = benchmark(
        "SM2 签名 ({$size}B)",
        fn () => Sm2::doSignature($data, $privateKey),
        SM2_SIGN_ITERATIONS,
    );
}
foreach ($sm2SignResults as $r) {
    printResult($r);
}
$baselineMeasurements['SM2 签名 (16B)'] = $sm2SignResults[0]['avg'];

// 带 hash 的签名
$hashOpts = (new SignatureOptions())->setHash(true)->setPublicKey($publicKey);
$r = benchmark(
    'SM2 签名 (hash=true, 16B)',
    fn () => Sm2::doSignature(str_repeat('A', 16), $privateKey, $hashOpts),
    SM2_SIGN_ITERATIONS,
);
printResult($r);

// DER 签名
$derOpts = (new SignatureOptions())->setDer(true);
$r = benchmark(
    'SM2 签名 (DER, 16B)',
    fn () => Sm2::doSignature(str_repeat('A', 16), $privateKey, $derOpts),
    SM2_SIGN_ITERATIONS,
);
printResult($r);

// 验签
echo "\n  验签:\n";
$sm2VerifyResults = [];
foreach ([16, 256, 1024] as $size) {
    $data = str_repeat('A', $size);
    $sig = Sm2::doSignature($data, $privateKey);
    $sm2VerifyResults[] = benchmark(
        "SM2 验签 ({$size}B)",
        fn () => Sm2::doVerifySignature($data, $sig, $publicKey),
        SM2_SIGN_ITERATIONS,
    );
}
foreach ($sm2VerifyResults as $r) {
    printResult($r);
}

// 加密
echo "\n  加密:\n";
$sm2EncResults = [];
foreach ([16, 64, 256] as $size) {
    $data = str_repeat('A', $size);
    $sm2EncResults[] = benchmark(
        "SM2 加密 ({$size}B)",
        fn () => Sm2::doEncrypt($data, $publicKey),
        SM2_ENCRYPT_ITERATIONS,
    );
}
foreach ($sm2EncResults as $r) {
    printResult($r);
}

// 解密
echo "\n  解密:\n";
$sm2DecResults = [];
foreach ([16, 64, 256] as $size) {
    $data = str_repeat('A', $size);
    $ct = Sm2::doEncrypt($data, $publicKey);
    $sm2DecResults[] = benchmark(
        "SM2 解密 ({$size}B)",
        fn () => Sm2::doDecrypt($ct, $privateKey),
        SM2_ENCRYPT_ITERATIONS,
    );
}
foreach ($sm2DecResults as $r) {
    printResult($r);
}

// SM2 C1C3C2 vs C1C2C3 模式
echo "\n  SM2 密文模式对比:\n";
$cipherMode1 = new Sm2CipherOptions(); // C1C3C2 (default)
$cipherMode0 = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0); // C1C2C3
$r = benchmark(
    'SM2 加密 C1C3C2 (64B)',
    fn () => Sm2::doEncrypt(str_repeat('A', 64), $publicKey, $cipherMode1),
    SM2_ENCRYPT_ITERATIONS,
);
printResult($r);
$r = benchmark(
    'SM2 加密 C1C2C3 (64B)',
    fn () => Sm2::doEncrypt(str_repeat('A', 64), $publicKey, $cipherMode0),
    SM2_ENCRYPT_ITERATIONS,
);
printResult($r);

// --- SM2 PEM 导入/导出 ---
printSection('SM2 PEM 导入/导出性能');

echo "\n  PEM 导出:\n";
$r = benchmark('SEC1 私钥导出 (含公钥)', fn () => Pem::exportPrivateKey($privateKey, $publicKey), PEM_ITERATIONS);
printResult($r);
$r = benchmark('SEC1 私钥导出 (不含公钥)', fn () => Pem::exportPrivateKey($privateKey), PEM_ITERATIONS);
printResult($r);
$r = benchmark('PKCS#8 私钥导出', fn () => Pem::exportPrivateKeyPkcs8($privateKey), PEM_ITERATIONS);
printResult($r);
$r = benchmark('SPKI 公钥导出', fn () => Pem::exportPublicKey($publicKey), PEM_ITERATIONS);
printResult($r);

echo "\n  PEM 导入:\n";
$sec1Pem = Pem::exportPrivateKey($privateKey, $publicKey);
$pkcs8Pem = Pem::exportPrivateKeyPkcs8($privateKey);
$pubPem = Pem::exportPublicKey($publicKey);
$r = benchmark('SEC1 私钥导入 (含公钥)', fn () => Pem::importPrivateKey($sec1Pem), PEM_ITERATIONS);
printResult($r);
$r = benchmark('PKCS#8 私钥导入', fn () => Pem::importPrivateKey($pkcs8Pem), PEM_ITERATIONS);
printResult($r);
$r = benchmark('SPKI 公钥导入', fn () => Pem::importPublicKey($pubPem), PEM_ITERATIONS);
printResult($r);

echo "\n  PEM 导入 (不含公钥, 需推导公钥):\n";
$sec1NoPubPem = Pem::exportPrivateKey($privateKey); // 不含公钥
$r = benchmark('SEC1 私钥导入 (需推导公钥)', fn () => Pem::importPrivateKey($sec1NoPubPem), PEM_ITERATIONS);
printResult($r);

echo "\n  DER 导出:\n";
$r = benchmark('SEC1 DER 私钥导出', fn () => Pem::exportPrivateKeyDer($privateKey, $publicKey), PEM_ITERATIONS);
printResult($r);
$r = benchmark('PKCS#8 DER 私钥导出', fn () => Pem::exportPrivateKeyPkcs8Der($privateKey), PEM_ITERATIONS);
printResult($r);
$r = benchmark('SPKI DER 公钥导出', fn () => Pem::exportPublicKeyDer($publicKey), PEM_ITERATIONS);
printResult($r);

echo "\n  DER 导入:\n";
$sec1Der = Pem::exportPrivateKeyDer($privateKey, $publicKey);
$pkcs8Der = Pem::exportPrivateKeyPkcs8Der($privateKey);
$pubDer = Pem::exportPublicKeyDer($publicKey);
$r = benchmark('SEC1 DER 私钥导入', fn () => Pem::importPrivateKeyFromDer($sec1Der), PEM_ITERATIONS);
printResult($r);
$r = benchmark('PKCS#8 DER 私钥导入', fn () => Pem::importPrivateKeyFromDer($pkcs8Der), PEM_ITERATIONS);
printResult($r);
$r = benchmark('SPKI DER 公钥导入', fn () => Pem::importPublicKeyFromDer($pubDer), PEM_ITERATIONS);
printResult($r);

// --- SM2 密钥交换 ---
printSection('SM2 密钥交换性能');

// 生成静态密钥对
$kpA = Sm2::generateKeyPairHex();
$kpB = Sm2::generateKeyPairHex();

// 临时密钥对
$ephA = KeyExchange::generateEphemeralKeyPair();
$ephB = KeyExchange::generateEphemeralKeyPair();

echo "\n  临时密钥对生成:\n";
$r = benchmark('密钥交换临时密钥对', fn () => KeyExchange::generateEphemeralKeyPair(), SM2_KEYGEN_ITERATIONS);
printResult($r);

echo "\n  共享密钥计算:\n";
$r = benchmark(
    '发起方计算共享密钥 (32B)',
    fn () => KeyExchange::initiatorComputeKey(
        $kpA->getPrivateKey(),
        $ephA->getPrivateKey(),
        $kpB->getPublicKey(),
        $ephB->getPublicKey(),
        32
    ),
    KEY_EXCHANGE_ITERATIONS,
);
printResult($r);

$r = benchmark(
    '响应方计算共享密钥 (32B)',
    fn () => KeyExchange::responderComputeKey(
        $kpB->getPrivateKey(),
        $ephB->getPrivateKey(),
        $kpA->getPublicKey(),
        $ephA->getPublicKey(),
        32
    ),
    KEY_EXCHANGE_ITERATIONS,
);
printResult($r);

// 密钥交换完整流程（含临时密钥对生成）
$r = benchmark(
    '密钥交换完整流程 (含临时密钥对生成)',
    function () use ($kpA, $kpB) {
        $eA = KeyExchange::generateEphemeralKeyPair();
        $eB = KeyExchange::generateEphemeralKeyPair();
        $kA = KeyExchange::initiatorComputeKey(
            $kpA->getPrivateKey(), $eA->getPrivateKey(),
            $kpB->getPublicKey(), $eB->getPublicKey(), 32
        );
        $kB = KeyExchange::responderComputeKey(
            $kpB->getPrivateKey(), $eB->getPrivateKey(),
            $kpA->getPublicKey(), $eA->getPublicKey(), 32
        );
    },
    KEY_EXCHANGE_ITERATIONS,
);
printResult($r);

// ============================================================================
// 汇总
// ============================================================================

printSection('性能汇总');

echo "\n";
printf("  %-35s  %15s  %15s  %15s\n", '操作', '平均耗时', 'P50', '吞吐量');
echo str_repeat('-', 85) . "\n";

// SM3
foreach (DATA_SIZES as $i => $size) {
    $label = "SM3 哈希 ({$size}B)";
    $throughput = $sm3Results[$i]['avg'] > 0 ? formatThroughput($size / $sm3Results[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm3Results[$i]['avg']), formatTime($sm3Results[$i]['p50']), $throughput);
}

// HMAC-SM3
foreach (DATA_SIZES as $i => $size) {
    $label = "HMAC-SM3 ({$size}B)";
    $throughput = $hmacResults[$i]['avg'] > 0 ? formatThroughput($size / $hmacResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($hmacResults[$i]['avg']), formatTime($hmacResults[$i]['p50']), $throughput);
}

// SM4-CBC 加密
foreach (DATA_SIZES as $i => $size) {
    $label = "SM4-CBC 加密 ({$size}B)";
    $throughput = $sm4CbcResults[$i]['avg'] > 0 ? formatThroughput($size / $sm4CbcResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm4CbcResults[$i]['avg']), formatTime($sm4CbcResults[$i]['p50']), $throughput);
}

// SM4-CBC 解密
foreach (DATA_SIZES as $i => $size) {
    $label = "SM4-CBC 解密 ({$size}B)";
    $throughput = $sm4DecResults[$i]['avg'] > 0 ? formatThroughput($size / $sm4DecResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm4DecResults[$i]['avg']), formatTime($sm4DecResults[$i]['p50']), $throughput);
}

// SM4-GCM
foreach ([64, 256, 1024] as $i => $size) {
    $label = "SM4-GCM 加密 ({$size}B)";
    $throughput = $sm4GcmEncResults[$i]['avg'] > 0 ? formatThroughput($size / $sm4GcmEncResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm4GcmEncResults[$i]['avg']), formatTime($sm4GcmEncResults[$i]['p50']), $throughput);
}

// SM2 签名
foreach ([16, 256, 1024] as $i => $size) {
    $label = "SM2 签名 ({$size}B)";
    $throughput = $sm2SignResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2SignResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm2SignResults[$i]['avg']), formatTime($sm2SignResults[$i]['p50']), $throughput);
}

// SM2 验签
foreach ([16, 256, 1024] as $i => $size) {
    $label = "SM2 验签 ({$size}B)";
    $throughput = $sm2VerifyResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2VerifyResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm2VerifyResults[$i]['avg']), formatTime($sm2VerifyResults[$i]['p50']), $throughput);
}

// SM2 加密
foreach ([16, 64, 256] as $i => $size) {
    $label = "SM2 加密 ({$size}B)";
    $throughput = $sm2EncResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2EncResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm2EncResults[$i]['avg']), formatTime($sm2EncResults[$i]['p50']), $throughput);
}

// SM2 解密
foreach ([16, 64, 256] as $i => $size) {
    $label = "SM2 解密 ({$size}B)";
    $throughput = $sm2DecResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2DecResults[$i]['avg']) : '-';
    printf("  %-35s  %15s  %15s  %15s\n", $label, formatTime($sm2DecResults[$i]['avg']), formatTime($sm2DecResults[$i]['p50']), $throughput);
}

echo "\n测试完成。\n";
printBaselineCheck($baselineMeasurements, $baseline);
