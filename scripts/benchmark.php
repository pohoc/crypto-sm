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

use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2;
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

const DATA_SIZES = [16, 64, 256, 1024, 4096]; // 测试数据大小（字节）

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
    echo '  当前时间:         ' . date('Y-m-d H:i:s') . "\n";
}

// ============================================================================
// 主测试
// ============================================================================

echo "╔══════════════════════════════════════════════════════════════════╗\n";
echo "║          国密算法性能测试 (SM2 / SM3 / SM4)                     ║\n";
echo "╚══════════════════════════════════════════════════════════════════╝\n";

printSystemInfo();

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

// SM3 吞吐量
echo "\n  SM3 吞吐量:\n";
foreach (DATA_SIZES as $i => $size) {
    $avg = $sm3Results[$i]['avg'];
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

// SM4 吞吐量
echo "\n  SM4 吞吐量 (CBC 加密):\n";
foreach (DATA_SIZES as $i => $size) {
    $avg = $sm4CbcResults[$i]['avg'];
    $throughput = $avg > 0 ? $size / $avg : 0;
    printf("    %8s 输入: %s\n", formatBytes($size), formatThroughput($throughput));
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

// ============================================================================
// 汇总
// ============================================================================

printSection('性能汇总');

echo "\n";
printf("  %-30s  %15s  %15s  %15s\n", '操作', '平均耗时', 'P50', '吞吐量');
echo str_repeat('-', 80) . "\n";

// SM3
foreach (DATA_SIZES as $i => $size) {
    $label = "SM3 哈希 ({$size}B)";
    $throughput = $sm3Results[$i]['avg'] > 0 ? formatThroughput($size / $sm3Results[$i]['avg']) : '-';
    printf("  %-30s  %15s  %15s  %15s\n", $label, formatTime($sm3Results[$i]['avg']), formatTime($sm3Results[$i]['p50']), $throughput);
}

// SM4-CBC 加密
foreach (DATA_SIZES as $i => $size) {
    $label = "SM4-CBC 加密 ({$size}B)";
    $throughput = $sm4CbcResults[$i]['avg'] > 0 ? formatThroughput($size / $sm4CbcResults[$i]['avg']) : '-';
    printf("  %-30s  %15s  %15s  %15s\n", $label, formatTime($sm4CbcResults[$i]['avg']), formatTime($sm4CbcResults[$i]['p50']), $throughput);
}

// SM4-CBC 解密
foreach (DATA_SIZES as $i => $size) {
    $label = "SM4-CBC 解密 ({$size}B)";
    $throughput = $sm4DecResults[$i]['avg'] > 0 ? formatThroughput($size / $sm4DecResults[$i]['avg']) : '-';
    printf("  %-30s  %15s  %15s  %15s\n", $label, formatTime($sm4DecResults[$i]['avg']), formatTime($sm4DecResults[$i]['p50']), $throughput);
}

// SM2 签名
foreach ([16, 256, 1024] as $i => $size) {
    $label = "SM2 签名 ({$size}B)";
    $throughput = $sm2SignResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2SignResults[$i]['avg']) : '-';
    printf("  %-30s  %15s  %15s  %15s\n", $label, formatTime($sm2SignResults[$i]['avg']), formatTime($sm2SignResults[$i]['p50']), $throughput);
}

// SM2 验签
foreach ([16, 256, 1024] as $i => $size) {
    $label = "SM2 验签 ({$size}B)";
    $throughput = $sm2VerifyResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2VerifyResults[$i]['avg']) : '-';
    printf("  %-30s  %15s  %15s  %15s\n", $label, formatTime($sm2VerifyResults[$i]['avg']), formatTime($sm2VerifyResults[$i]['p50']), $throughput);
}

// SM2 加密
foreach ([16, 64, 256] as $i => $size) {
    $label = "SM2 加密 ({$size}B)";
    $throughput = $sm2EncResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2EncResults[$i]['avg']) : '-';
    printf("  %-30s  %15s  %15s  %15s\n", $label, formatTime($sm2EncResults[$i]['avg']), formatTime($sm2EncResults[$i]['p50']), $throughput);
}

// SM2 解密
foreach ([16, 64, 256] as $i => $size) {
    $label = "SM2 解密 ({$size}B)";
    $throughput = $sm2DecResults[$i]['avg'] > 0 ? formatThroughput($size / $sm2DecResults[$i]['avg']) : '-';
    printf("  %-30s  %15s  %15s  %15s\n", $label, formatTime($sm2DecResults[$i]['avg']), formatTime($sm2DecResults[$i]['p50']), $throughput);
}

echo "\n测试完成。\n";
