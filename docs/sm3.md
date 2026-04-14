# SM3 算法使用指南

## 概述

SM3 是中国密码杂凑算法标准 (GM/T 0004-2012)，产生 256 位的哈希值。

本实现特性：
- **OpenSSL 加速**：自动检测 `openssl_digest('sm3')`，可用时使用 C 原生实现（比纯 PHP 快 100-300 倍）
- **纯 PHP 回退**：当 OpenSSL 不支持 SM3 时自动回退
- **流式哈希**：支持分块更新，适用于大文件等场景
- **HMAC-SM3**：RFC 2104 标准的 HMAC 实现

## 基本用法

### 一次性哈希

```php
use CryptoSm\SM3\Sm3;

$data = 'Hello World';
$hash = Sm3::sm3($data);

// $hash 是一个 64 字符的十六进制字符串（256 位）
echo $hash; // 44ac98b4e10ed7e22c0e7b9b4f8e4a1...
```

### 哈希不同类型数据

```php
use CryptoSm\SM3\Sm3;

// 字符串
$hash = Sm3::sm3('test string');

// 二进制数据
$hash = Sm3::sm3("\x00\x01\x02\x03");

// 空字符串
$hash = Sm3::sm3('');
// 返回: 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
```

## 流式哈希

对于大文件或分块数据，使用流式 API 逐步更新哈希状态：

```php
use CryptoSm\SM3\Sm3;

$hasher = new Sm3();

// 分块更新（支持方法链）
$hasher->update('chunk1')
       ->update('chunk2')
       ->update('chunk3');

// 最终计算
$hash = $hasher->finalize();
echo $hash; // 64 字符十六进制

// finalize 后自动重置，可复用
$hash2 = $hasher->update('new data')->finalize();
```

### 大文件哈希

```php
use CryptoSm\SM3\Sm3;

$hasher = new Sm3();
$handle = fopen('large_file.bin', 'rb');

while (!feof($handle)) {
    $chunk = fread($handle, 8192);
    $hasher->update($chunk);
}
fclose($handle);

$hash = $hasher->finalize();
echo "文件 SM3 哈希: $hash\n";
```

> **性能提示**：流式哈希同样享受 OpenSSL 加速（在 `finalize` 时一次性计算），性能与一次性哈希接近。

## HMAC-SM3

HMAC-SM3 遵循 RFC 2104 标准，使用 SM3 作为底层哈希函数：

### 一次性计算

```php
use CryptoSm\SM3\HmacSm3;

$key = 'my_secret_key';
$data = 'message to authenticate';

$hmac = HmacSm3::hmac($key, $data);
echo $hmac; // 64 字符十六进制
```

### 流式计算

```php
use CryptoSm\SM3\HmacSm3;

$hmac = HmacSm3::create($key);

$hmac->update('chunk1')
     ->update('chunk2');

$result = $hmac->finalize();
echo $result; // 64 字符十六进制

// finalize 后自动重置，可复用
$result2 = $hmac->update('new data')->finalize();
```

### 使用场景

```php
use CryptoSm\SM3\HmacSm3;

// API 请求签名
$apiKey = 'server_assigned_key';
$payload = json_encode(['action' => 'transfer', 'amount' => 100]);
$signature = HmacSm3::hmac($apiKey, $payload);

// 消息完整性验证
$secret = 'shared_secret';
$message = 'important data';
$hmac = HmacSm3::hmac($secret, $message);

// 验证方
$expected = HmacSm3::hmac($secret, $receivedMessage);
if (hash_equals($hmac, $expected)) {
    echo '消息完整且来源可信';
}
```

## 使用 SmCrypto 门面类

```php
use CryptoSm\SmCrypto;

// SM3 一次性哈希
$hash = SmCrypto::sm3('Hello World');

// SM3 流式哈希
$hasher = SmCrypto::sm3Stream();
$hasher->update('chunk1')->update('chunk2')->update('chunk3');
$hash = $hasher->finalize();

// HMAC-SM3
$hmac = SmCrypto::hmacSm3('key', 'data');

// HMAC-SM3 流式
$hmacStream = SmCrypto::hmacSm3Stream('key');
$hmacStream->update('chunk1')->update('chunk2');
$result = $hmacStream->finalize();
```

## 完整示例

```php
<?php

declare(strict_types=1);

require_once 'vendor/autoload.php';

use CryptoSm\SM3\Sm3;
use CryptoSm\SM3\HmacSm3;

echo "SM3 哈希示例\n\n";

// 1. 一次性哈希
echo "一次性哈希:\n";
echo "  'Hello World' => " . Sm3::sm3('Hello World') . "\n";
echo "  ''            => " . Sm3::sm3('') . "\n\n";

// 2. 流式哈希
echo "流式哈希:\n";
$hasher = new Sm3();
$hasher->update('Hello')->update(' World');
echo "  'Hello' + ' World' => " . $hasher->finalize() . "\n\n";

// 3. HMAC-SM3
echo "HMAC-SM3:\n";
$key = 'secret_key';
echo "  一次性 => " . HmacSm3::hmac($key, 'message') . "\n";

$hmac = HmacSm3::create($key);
$hmac->update('mes')->update('sage');
echo "  流式   => " . $hmac->finalize() . "\n";
```

## 技术细节

- **输出长度**: 256 位（64 个十六进制字符）
- **分组大小**: 512 位（64 字节）
- **算法结构**: Merkle-Damgård 结构
- **标准**: GM/T 0004-2012、ISO/IEC 10118-3:2018
- **OpenSSL 加速**: 自动检测 `openssl_digest('sm3')`，PHP 8.1+ / OpenSSL 1.1.1+ 支持
- **流式哈希性能**: OpenSSL 可用时与一次性哈希性能接近（~400 MB/s）

## 安全注意事项

1. SM3 适用于数字签名、消息认证和完整性验证
2. **不建议单独用于密码哈希**（密码哈希请使用 bcrypt 或 Argon2）
3. HMAC-SM3 的密钥应使用密码学安全随机数生成
4. 对于加密目的，请确保正确的密钥管理和安全的随机数生成
5. 使用 `hash_equals()` 进行 HMAC 比较以防止时序攻击
