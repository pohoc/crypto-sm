# Crypto-SM

[![PHP Version](https://img.shields.io/badge/PHP-8.0%20~%208.5-blue.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/pohoc/crypto-sm/actions/workflows/php.yml/badge.svg)](https://github.com/pohoc/crypto-sm/actions/workflows/php.yml)

国密算法 SM2、SM3、SM4 的 PHP 实现。

**PHP 国密库** — 支持 SM2 密钥交换、PEM 导入/导出、HMAC-SM3、SM3 流式哈希、SM4 全 6 种模式（ECB/CBC/CFB/OFB/CTR/GCM）和 5 种填充模式。

## 安装

```bash
composer require pohoc/crypto-sm
```

## 环境要求

- PHP 8.0 ~ 8.5
- GMP 扩展
- OpenSSL 扩展

### 安装 GMP 扩展

**Ubuntu/Debian:**
```bash
sudo apt-get install php-gmp
```

**CentOS/RHEL:**
```bash
sudo yum install php-gmp
```

**macOS (Homebrew):**
```bash
brew install php@gmp
```

**Windows:**
在 php.ini 中启用 php_gmp.dll 扩展（取消注释）:
```ini
extension=php_gmp.dll
```

**验证安装:**
```php
<?php
var_dump(extension_loaded('gmp'));
```

## 支持的算法

### SM2
中国椭圆曲线公钥密码算法 (GM/T 0003-2012)
- 密钥生成
- 加密/解密（C1C3C2 / C1C2C3 模式）
- 签名/验签（RS 拼接 / DER 格式，自动检测）
- PEM 导入/导出（SEC 1 / PKCS#8 / SubjectPublicKeyInfo）
- 密钥交换（GM/T 0003-2012 Section 6）

### SM3
中国密码杂凑算法 (GM/T 0004-2012)
- 哈希计算（OpenSSL 加速 + 纯 PHP 回退）
- 流式哈希（支持大文件分块处理）
- HMAC-SM3（RFC 2104）

### SM4
中国分组密码算法 (GM/T 0002-2012)
- 加密/解密
- ECB / CBC / CFB / OFB / CTR / GCM 模式
- PKCS5/PKCS7 / Zero / ISO 10126 / ANSI X9.23 / None 填充
- GCM 认证加密（OpenSSL 优先 + 纯 PHP 回退）

## 快速开始

### SM2

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Keypair;
use CryptoSm\SM2\SignatureOptions;

// 生成密钥对
$keypair = Sm2::generateKeyPairHex();
$privateKey = $keypair->getPrivateKey();
$publicKey = $keypair->getPublicKey();

// 加密
$ciphertext = Sm2::doEncrypt('Hello World', $publicKey);

// 解密
$plaintext = Sm2::doDecrypt($ciphertext, $privateKey);

// 签名（不哈希）
$signature = Sm2::doSignature('Message', $privateKey);
$isValid = Sm2::doVerifySignature('Message', $signature, $publicKey);

// 签名（哈希并指定用户 ID）
$options = (new SignatureOptions())
    ->setHash(true)
    ->setPublicKey($publicKey);
$signature = Sm2::doSignature('Message', $privateKey, $options);
$isValid = Sm2::doVerifySignature('Message', $signature, $publicKey, $options);

// DER 格式签名
$options = (new SignatureOptions())->setDer(true);
$signature = Sm2::doSignature('Message', $privateKey, $options);
$isValid = Sm2::doVerifySignature('Message', $signature, $publicKey, $options);
```

#### SM2 PEM 导入/导出

```php
use CryptoSm\SM2\Pem;

// 导出私钥 — SEC 1 格式（BEGIN EC PRIVATE KEY）
$pem = Pem::exportPrivateKey($privateKey, $publicKey);

// 导出私钥 — PKCS#8 格式（BEGIN PRIVATE KEY）
$pem = Pem::exportPrivateKeyPkcs8($privateKey);

// 导出公钥（BEGIN PUBLIC KEY）
$pem = Pem::exportPublicKey($publicKey);

// 导入私钥（自动识别 SEC 1 / PKCS#8 格式）
$keys = Pem::importPrivateKey($pem);
$privateKey = $keys['privateKey']; // 64 字符十六进制
$publicKey = $keys['publicKey'];   // 128 字符十六进制

// 导入公钥
$publicKey = Pem::importPublicKey($pem);
```

#### SM2 密钥交换

```php
use CryptoSm\SM2\KeyExchange;

// 发起方 A
$keypairA = Sm2::generateKeyPairHex();     // 静态密钥对
$ephemeralA = KeyExchange::generateEphemeralKeyPair(); // 临时密钥对

// 响应方 B
$keypairB = Sm2::generateKeyPairHex();     // 静态密钥对
$ephemeralB = KeyExchange::generateEphemeralKeyPair(); // 临时密钥对

// 交换临时公钥后，双方各自计算共享密钥
$klen = 32; // 期望密钥长度（字节）

$sharedKeyA = KeyExchange::initiatorComputeKey(
    $keypairA->getPrivateKey(),   // dA
    $ephemeralA->getPrivateKey(), // rA
    $keypairB->getPublicKey(),    // PB
    $ephemeralB->getPublicKey(),  // RB
    $klen
);

$sharedKeyB = KeyExchange::responderComputeKey(
    $keypairB->getPrivateKey(),   // dB
    $ephemeralB->getPrivateKey(), // rB
    $keypairA->getPublicKey(),    // PA
    $ephemeralA->getPublicKey(),  // RA
    $klen
);

// $sharedKeyA === $sharedKeyB ✓
```

### SM3

```php
use CryptoSm\SM3\Sm3;

// 一次性哈希
$hash = Sm3::sm3('Hello World');

// 流式哈希（适合大文件）
$hasher = new Sm3();
$hasher->update($chunk1)
       ->update($chunk2)
       ->update($chunk3);
$hash = $hasher->finalize();
```

#### HMAC-SM3

```php
use CryptoSm\SM3\HmacSm3;

// 一次性计算
$mac = HmacSm3::hmac('secret_key', 'message');

// 流式计算
$hmac = HmacSm3::create('secret_key');
$hmac->update($chunk1)
     ->update($chunk2);
$mac = $hmac->finalize();
```

### SM4

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210'; // 32 位十六进制，128 bit
$data = 'Hello World';

// CBC 模式（默认）
$iv  = '000102030405060708090a0b0c0d0e0f';
$options = (new Sm4Options())->setIv($iv);
$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);

// ECB 模式（不推荐，仅用于兼容旧系统）
$options = (new Sm4Options())->setMode(Sm4::MODE_ECB);
$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);

// CFB 模式（流式，无需填充）
$options = (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv);
$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);

// OFB 模式
$options = (new Sm4Options())->setMode(Sm4::MODE_OFB)->setIv($iv);
$ciphertext = Sm4::encrypt($data, $key, $options);

// CTR 模式
$options = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv);
$ciphertext = Sm4::encrypt($data, $key, $options);

// GCM 模式（认证加密，推荐）
$options = (new Sm4Options())
    ->setMode(Sm4::MODE_GCM)
    ->setIv($iv)                // 推荐 12 字节（24 十六进制字符）
    ->setAad('additional data') // 附加认证数据
    ->setTagLength(16);         // 认证标签长度（4/8/12/13/14/15/16 字节）
$ciphertext = Sm4::encrypt($data, $key, $options);
// 密文格式：ciphertext_hex + tag_hex
$plaintext = Sm4::decrypt($ciphertext, $key, $options);

// GCM 预热（消除首次调用建表延迟，可选）
Sm4::warmupGcm($key);
```

#### SM4 填充模式

```php
// PKCS5/PKCS7 填充（默认）
$options = (new Sm4Options())->setPadding('pkcs5');

// 零填充
$options = (new Sm4Options())->setPadding('zero');

// ISO 10126 填充（随机填充字节）
$options = (new Sm4Options())->setPadding('iso10126');

// ANSI X9.23 填充
$options = (new Sm4Options())->setPadding('ansix923');

// 无填充（数据长度必须是 16 的倍数）
$options = (new Sm4Options())->setPadding('none');
```

## 使用 SmCrypto 门面类

```php
use CryptoSm\SmCrypto;

// SM2 密钥生成
$keypair = SmCrypto::generateKeyPair();

// SM2 加密/解密
$ciphertext = SmCrypto::encrypt($data, $publicKey);
$plaintext = SmCrypto::decrypt($ciphertext, $privateKey);

// SM2 签名/验签
$signature = SmCrypto::sign($data, $privateKey);
$isValid = SmCrypto::verify($data, $signature, $publicKey);

// SM2 公钥推导
$publicKey = SmCrypto::getPublicKey($privateKey);

// SM2 PEM 导入/导出
$pem = SmCrypto::exportPrivateKeyPem($privateKey, $publicKey);
$pem = SmCrypto::exportPrivateKeyPkcs8($privateKey);
$pem = SmCrypto::exportPublicKeyPem($publicKey);
$keys = SmCrypto::importPrivateKeyPem($pem);
$pubKey = SmCrypto::importPublicKeyPem($pem);

// SM2 密钥交换
$ephemeral = SmCrypto::generateExchangeKeyPair();
$sharedKey = SmCrypto::initiatorKeyExchange($dA, $rA, $PB, $RB, 32);
$sharedKey = SmCrypto::responderKeyExchange($dB, $rB, $PA, $RA, 32);

// SM3 哈希
$hash = SmCrypto::sm3($data);

// SM3 流式哈希
$hasher = SmCrypto::sm3Stream();
$hasher->update($chunk1)->update($chunk2);
$hash = $hasher->finalize();

// HMAC-SM3
$mac = SmCrypto::hmacSm3('secret_key', $data);

// HMAC-SM3 流式
$hmac = SmCrypto::hmacSm3Stream('secret_key');
$hmac->update($chunk1)->update($chunk2);
$mac = $hmac->finalize();

// SM4 加密/解密
$ciphertext = SmCrypto::sm4Encrypt($data, $key, $options);
$plaintext = SmCrypto::sm4Decrypt($ciphertext, $key, $options);
```

## 特性

- **零运行时依赖** — 仅需 `ext-gmp` 和 `ext-openssl`
- **OpenSSL 加速** — SM3 和 SM4（CBC/ECB/CFB/OFB/CTR）使用 OpenSSL 原生实现，不可用时自动回退到纯 PHP；SM4-GCM 优先使用 OpenSSL，回退到纯 PHP GHASH 实现
- **标准合规** — 全部通过 GM/T 0002/0003/0004 标准测试向量验证（529 测试，1,000,000+ 断言）
- **安全** — GCM 认证标签时序安全比较、DER 签名自动检测、安全随机数生成、SM2 签名 60000+ 次零失败验证
- **优雅 API** — 门面 + 子系统双层 API，选项对象链式调用，GCM warmup 预热接口

## 性能基准

> 测试环境：PHP 8.4.4 / macOS / OpenSSL 3.4.1 / Apple M 系列  
> 运行方式：`php scripts/benchmark.php`

### SM3 哈希

| 数据大小 | 平均耗时 | P50 | 吞吐量 |
|----------|----------|-----|--------|
| 16 B | ~0.7 μs | 0.6 μs | ~22 MB/s |
| 256 B | ~1.1 μs | 1.1 μs | ~220 MB/s |
| 1 KB | ~2.6 μs | 2.5 μs | ~370 MB/s |
| 4 KB | ~9 μs | 8.2 μs | ~430 MB/s |

> SM3 使用 OpenSSL `sm3` 原生实现加速，吞吐量随数据增大趋近 ~400 MB/s。

### HMAC-SM3

| 数据大小 | 平均耗时 | 吞吐量 |
|----------|----------|--------|
| 256 B | ~2.5 μs | ~100 MB/s |
| 1 KB | ~4 μs | ~240 MB/s |
| 4 KB | ~10 μs | ~380 MB/s |

### SM4 对称加密

| 操作 | 数据大小 | 平均耗时 | 吞吐量 |
|------|----------|----------|--------|
| ECB 加密 | 1 KB | ~7.5 μs | ~130 MB/s |
| CBC 加密 | 1 KB | ~8.8 μs | ~110 MB/s |
| CBC 解密 | 1 KB | ~10 μs | ~93 MB/s |
| CFB 加密 | 1 KB | ~8.5 μs | ~115 MB/s |
| OFB 加密 | 1 KB | ~8.5 μs | ~115 MB/s |
| CTR 加密 | 1 KB | ~8.5 μs | ~115 MB/s |
| GCM 加密 | 1 KB | ~240 μs | ~4 MB/s |
| GCM 解密 | 1 KB | ~250 μs | ~4 MB/s |

> \* GCM 纯 PHP 回退路径（本测试环境 OpenSSL 不支持 SM4-GCM），使用 8-bit 查表 + 16 层移位表优化。首次调用含建表开销（~1.7ms），可通过 `Sm4::warmupGcm($key)` 预热消除。若 OpenSSL 支持 SM4-GCM，性能将与其他模式相当。

### SM4 模式吞吐量对比（1 KB 数据）

```
ECB  ████████████████████████████████████████  ~130 MB/s
CBC  ████████████████████████████████████      ~110 MB/s
CFB  █████████████████████████████████████     ~115 MB/s
OFB  █████████████████████████████████████     ~115 MB/s
CTR  █████████████████████████████████████     ~115 MB/s
GCM  █                                         ~4 MB/s (纯PHP, 8-bit查表)
```

### SM2 非对称操作

| 操作 | 数据大小 | 平均耗时 |
|------|----------|----------|
| 密钥生成 | - | ~1.2 ms |
| 签名 | 16 B | ~1.1 ms |
| 签名 | 1 KB | ~1.1 ms |
| 验签 | 16 B | ~2.3 ms |
| 加密 | 64 B | ~2.3 ms |
| 解密 | 64 B | ~1.2 ms |
| 密钥交换（完整流程） | 32 B | ~11.5 ms |

### SM2 PEM 导入/导出

| 操作 | 平均耗时 |
|------|----------|
| SEC1 私钥导出 | ~2.5 μs |
| PKCS#8 私钥导出 | ~3.5 μs |
| 公钥导出 | ~3.5 μs |
| 私钥导入 | ~1.1 ms |
| 公钥导入 | ~2.7 μs |

> 私钥导入耗时较高是因为需要验证密钥范围并推导公钥（椭圆曲线点乘运算）。

### 运行基准测试

```bash
php scripts/benchmark.php
```

## 测试

```bash
composer install
vendor/bin/phpunit
```

529 测试，1,000,000+ 断言，覆盖全部标准测试向量。

## 代码质量

```bash
# 静态分析（PHPStan level 8）
vendor/bin/phpstan analyse

# 代码风格检查
vendor/bin/php-cs-fixer fix --dry-run --diff

# 代码风格修复
vendor/bin/php-cs-fixer fix

# 一键检查全部
composer check
```

## CI

GitHub Actions 自动化流水线，每次 push/PR 自动运行：

- **多版本测试** — PHP 8.0 / 8.1 / 8.2 / 8.3 / 8.4 / 8.5 矩阵测试
- **静态分析** — PHPStan level 8 + PSR-12 代码风格检查
- **安全审计** — Composer audit 依赖漏洞扫描

## 文档

- [SM2 详细文档](docs/sm2.md) — 密钥生成、加密/解密、签名/验签、PEM、密钥交换
- [SM3 详细文档](docs/sm3.md) — 哈希计算、流式哈希、HMAC-SM3
- [SM4 详细文档](docs/sm4.md) — 6 种加密模式、5 种填充方式
- [变更日志](CHANGELOG.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)

## 许可证

[MIT](LICENSE)
