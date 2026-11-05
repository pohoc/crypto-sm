# Crypto-SM

[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

国密算法 SM2、SM3、SM4 的 PHP 实现。

**PHP 国密库** — 支持 SM2 密钥交换、PEM 导入/导出、HMAC-SM3、PBKDF2-HMAC-SM3、SM3 流式哈希、SM4 门面的 6 种模式（ECB/CBC/CFB/OFB/CTR/GCM），并提供独立的 CCM AEAD API。

## 安装

```bash
composer require pohoc/crypto-sm
```

## 环境要求

- PHP 8.2+
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

## 兼容性策略

- 最低支持 PHP `8.2`；CI 覆盖 PHP `8.2` 到 `8.5`
- 常规矩阵使用 `composer install` 验证锁定依赖
- 最低版本兼容 job 使用 `composer update --prefer-lowest --prefer-stable` 验证最低依赖组合
- 测试用例需要兼容 `PHPUnit 9/10/11`

从旧版本升级前，请阅读[升级迁移指南](docs/migration.md)，重点检查 SM2 签名默认值、SM4 密文格式以及 PHP 版本要求。

## 支持的算法

### SM2
中国椭圆曲线公钥密码算法 (GM/T 0003-2012)
- 密钥生成
- 加密/解密（默认使用 GB/T 32918.4-2016 的 C1C3C2 与 SEC1 `04||x||y` 点编码；兼容 C1C2C3 和无前缀输入）
- 签名/验签（RS 拼接 / DER 格式，自动检测）
- PEM 导入/导出（SEC 1 / PKCS#8 / SubjectPublicKeyInfo）
- 密钥交换（GM/T 0003-2012 Section 6）

### SM3
中国密码杂凑算法 (GM/T 0004-2012)
- 哈希计算（OpenSSL 加速 + 纯 PHP 回退）
- 流式哈希（支持大文件分块处理）
- HMAC-SM3（RFC 2104）
- PBKDF2-HMAC-SM3（RFC 8018）

### SM4
中国分组密码算法 (GM/T 0002-2012)
- 加密/解密
- ECB / CBC / CFB / OFB / CTR / GCM 模式
- 独立的 SM4-CCM AEAD API（`CryptoSm\Crypto\Ccm`）
- PKCS5/PKCS7 / Zero / ISO 10126 / ANSI X9.23 / None 填充
- GCM 认证加密（可执行时使用 OpenSSL SM4-GCM；否则使用 OpenSSL SM4-ECB 或纯 PHP SM4 分组加密，并由本库计算 GHASH）

#### SM4-GCM 性能预期

- OpenSSL 可执行 `SM4-GCM` 时使用原生 AEAD；否则 GCM 的 CTR/GHASH 由本库实现，分组加密优先调用 OpenSSL `SM4-ECB`
- OpenSSL 不支持所需 SM4 后端时会使用纯 PHP SM4 分组实现
- GCM 路径会显著慢于 `CBC/CFB/OFB/CTR`，属于预期行为
- 高吞吐 AEAD 场景应先通过基准测试确认性能满足业务要求

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

// 标准 SM2 消息签名（默认使用 SM3(ZA || M)）
$signature = Sm2::doSignature('Message', $privateKey);
$isValid = Sm2::doVerifySignature('Message', $signature, $publicKey);

// 仅在上游已按协议计算 SM2 摘要时关闭内部哈希；输入必须恰好 32 字节
$legacyOptions = (new SignatureOptions())->setHash(false);
$precomputedDigest = hex2bin($digestHex); // 64 个十六进制字符
$legacySignature = Sm2::doSignature($precomputedDigest, $privateKey, $legacyOptions);

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

> **安全注意：** 下方 `initiatorComputeKey()` / `responderComputeKey()` 只派生共享密钥，
> 不执行对端密钥确认。仅比较双方算出的密钥是否相同不是协议确认步骤；在网络协议中，
> 不要在收到并验证确认值前使用派生密钥。请使用带确认值的 API，并严格遵循
> [`docs/sm2.md` 中的 S_A/S_B 交互顺序](docs/sm2.md#密钥确认便捷方法)：响应方先发送
> S_B，发起方验证后才发送 S_A，双方分别在完成各自的确认步骤后使用密钥。

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
$valid = HmacSm3::verify('secret_key', 'message', $receivedMac); // hash_equals 安全比较

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

$cbcKey = '0123456789abcdeffedcba9876543210'; // 每种模式使用独立密钥
$ecbKey = '1123456789abcdeffedcba9876543210';
$cfbKey = '2123456789abcdeffedcba9876543210';
$ofbKey = '3123456789abcdeffedcba9876543210';
$ctrKey = '4123456789abcdeffedcba9876543210';
$gcmKey = '5123456789abcdeffedcba9876543210';
$data = 'Hello World';

// CBC 兼容模式（需显式选择；不提供密文完整性）
$iv  = '000102030405060708090a0b0c0d0e0f';
$options = (new Sm4Options())->setMode(Sm4::MODE_CBC)->setIv($iv);
$ciphertext = Sm4::encrypt($data, $cbcKey, $options);
$plaintext = Sm4::decrypt($ciphertext, $cbcKey, $options);

// ECB 模式（不推荐，仅用于兼容旧系统）
$options = (new Sm4Options())->setMode(Sm4::MODE_ECB);
$ciphertext = Sm4::encrypt($data, $ecbKey, $options);
$plaintext = Sm4::decrypt($ciphertext, $ecbKey, $options);

// CFB 模式（流式，无需填充；仅加密、不认证，需另加 MAC）
$options = (new Sm4Options())->setMode(Sm4::MODE_CFB)->setIv($iv);
$ciphertext = Sm4::encrypt($data, $cfbKey, $options);
$plaintext = Sm4::decrypt($ciphertext, $cfbKey, $options);

// OFB 模式（仅加密、不认证，需另加 MAC）
$options = (new Sm4Options())->setMode(Sm4::MODE_OFB)->setIv($iv);
$ciphertext = Sm4::encrypt($data, $ofbKey, $options);

// CTR 模式（仅加密、不认证，需另加 MAC）
$options = (new Sm4Options())->setMode(Sm4::MODE_CTR)->setIv($iv);
$ciphertext = Sm4::encrypt($data, $ctrKey, $options);

// GCM 模式（认证加密，推荐）
$gcmIv = '000102030405060708090a0b'; // 推荐 12 字节（24 十六进制字符）
$options = (new Sm4Options())
    ->setMode(Sm4::MODE_GCM)
    ->setIv($gcmIv)
    ->setAad('additional data') // 附加认证数据
    ->setTagLength(16);         // 认证标签长度（12/13/14/15/16 字节）
$ciphertext = Sm4::encrypt($data, $gcmKey, $options);
// 密文格式：ciphertext_hex + tag_hex
$plaintext = Sm4::decrypt($ciphertext, $gcmKey, $options);

// 自包含 payload API（推荐用于业务封装，自动携带 IV/tag 元数据）
$payload = Sm4::encryptPayload($data, $gcmKey, (new Sm4Options())->setMode(Sm4::MODE_GCM));
$plaintext = Sm4::decryptPayload($payload, $gcmKey);
```

同一密钥不能跨 SM4 模式复用；示例中的每个模式使用独立密钥。CBC/CFB/OFB/CTR 不提供完整性保护，新业务优先选择 GCM。

### SM4-CCM

CCM 通过低层 API 单独提供，密钥与 GCM 或其他 SM4 模式分开使用。生产部署若跨进程复用密钥，应在启动时配置共享 nonce、标签长度和分组用量追踪器，详见 [SM4 安全与追踪器指南](docs/sm4.md)。

```php
use CryptoSm\Crypto\Ccm;

$ccmKey = hex2bin('6123456789abcdeffedcba9876543210');
$nonce = random_bytes(12); // 同一 key 下每次加密必须唯一
$ccm = Ccm::fromKey($ccmKey);
$sealed = $ccm->encrypt('Hello World', $nonce, '', 16);
$plaintext = $ccm->decrypt($sealed['ciphertext'], $sealed['tag'], $nonce, '', 16);
```

#### SM4 填充模式

```php
// PKCS5/PKCS7 填充（默认）
$options = (new Sm4Options())->setPadding('pkcs5');

// 零填充（有歧义，仅用于兼容旧数据；新代码不要使用）
$options = (new Sm4Options())->setPadding('zero');

// ISO 10126 填充（已废弃：无法在解密侧校验，将在未来大版本移除）
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

> `Sm4::encrypt()` 和 `Sm4Options` 默认使用 GCM。无选项时返回 `SM4GCM2` 自包含格式（版本标记、IV、密文和认证标签），可直接传回解密；仍支持解密 `SM4GCM1` 和旧版自包含 CBC 密文。需使用 CBC 的既有调用应显式指定 `MODE_CBC`，因为 CBC 不认证密文。

## 特性

- **轻量运行依赖** — 仅需 PHP 扩展 `ext-gmp` 和 `ext-openssl`
- **OpenSSL 加速** — SM3 和 SM4（CBC/ECB/CFB/OFB/CTR）优先使用 OpenSSL 原生实现；OpenSSL 不支持 SM4 时自动回退到纯 PHP
- **标准合规** — 通过 GM/T 0002/0003/0004 标准测试向量与 RFC 8998 SM4-GCM 官方向量验证
- **安全** — PHP/GMP GCM 回退在解密前用 `hash_equals()` 比较标签，原生 OpenSSL GCM 后端执行认证解密；门面与低层 `Gcm` 默认检测进程内重复 key/IV；CTR 默认拒绝进程内重叠计数器区间（跨进程保证需配置共享 tracker）；解密缺 IV 显式报错、DER 签名自动检测、安全随机数生成
- **正确性锚定** — GCM 另有 NIST SP 800-38D 规范直译参考模型差分测试（GcmReferenceModelTest）与解析器模糊测试（FuzzTest）
- **优雅 API** — 门面 + 子系统双层 API，选项对象链式调用

## 性能基准

> 运行方式：`php scripts/benchmark.php`  
> 基线阈值：[scripts/benchmark-baseline.json](scripts/benchmark-baseline.json)

性能高度依赖运行环境的国密加速能力，请先确认后端再对照数据：

```php
var_dump(in_array('sm3', array_map('strtolower', hash_algos()), true)); // SM3 原生加速
$sm4Methods = array_map('strtolower', openssl_get_cipher_methods());
var_dump(in_array('sm4-ecb', $sm4Methods, true)); // OpenSSL 宣告支持 SM4-ECB
```

基准脚本会自动探测并如实标注后端；基线阈值仅在所需后端可用时参与比较
（缺失时标记 `SKIP` 而非 `WARN`）。

### 环境 A：OpenSSL 原生国密加速（参考值）

要求 `hash_algos()` 含 `sm3` 且 OpenSSL 含 `sm4-ecb`（方法名按小写规范化；常见于链接 OpenSSL 1.1.1+/3.x 的 Linux 发行版 PHP）。库还会实际探测 OpenSSL 能否执行该分组密码；仅出现在方法列表中不代表可执行。
下表为该类环境的历史参考量级：

| 操作 | 数据大小 | 平均耗时 | 吞吐量 |
|------|----------|----------|--------|
| SM3 哈希 | 4 KB | ~9 μs | ~430 MB/s |
| SM4 CBC 加密 | 1 KB | ~8.8 μs | ~110 MB/s |
| SM2 签名 | 16 B | ~1.1 ms | — |

### 环境 B：纯 PHP 回退（Apple M 系列 / PHP 8.4.4 实测）

无任何原生国密支持时的实测数据（负载 ~4 的 macOS 开发机，2026-08）：

**SM3 / HMAC-SM3**

| 操作 | 16 B | 1 KB | 4 KB |
|------|------|------|------|
| SM3 哈希 | ~192 μs | ~3.2 ms | ~12.6 ms (~320 KB/s) |
| HMAC-SM3 | ~0.77 ms | ~4.1 ms | ~13.0 ms |

**SM4 对称加密（1 KB）**

| 模式 | 平均耗时 | 吞吐量 |
|------|----------|--------|
| ECB | ~2.2 ms | ~450 KB/s |
| CBC 加密 / 解密 | ~2.2 ms / ~2.1 ms | ~430 KB/s |
| CFB / OFB / CTR | ~2.2 ms | ~450 KB/s |
| **GCM 加密 / 解密** | ~6.1 ms / ~6.6 ms | ~165 KB/s |

> GCM 的 GHASH 为 GF(2^128) 规范直译实现（正确性优先，经 RFC 8998 向量验证），
> 显著慢于其它模式属预期；吞吐敏感场景请优先确认 OpenSSL 原生后端可用。

**SM2 非对称操作**

| 操作 | 平均耗时 |
|------|----------|
| 密钥生成 | ~1.5 ms |
| 签名 / 验签 (16 B) | ~1.9 ms / ~3.2 ms |
| 加密 / 解密 (64 B) | ~4.5 ms / ~2.9 ms |
| 密钥交换（完整流程，32 B） | ~23.5 ms |

**PEM 导入/导出**：导出 ~10–27 μs；私钥导入 ~1.6–3.2 ms（含曲线点乘推导公钥）；公钥导入 ~21 μs。

### 性能基线

脚本内置核心指标阈值用于识别性能退化：`SM3 哈希 (4096B)`、`HMAC-SM3 (4096B)`、
`SM4-CBC 加密 (1024B)`、`SM4-GCM 加密 (1024B)`、`SM2 签名 (16B)`。

- 后端可用且超阈值 → `WARN`
- 所需后端缺失 → `SKIP`（回退环境下比较无意义）
- 达标 → `PASS`

### 运行基准测试

```bash
php scripts/benchmark.php
```

## 测试

```bash
composer install
vendor/bin/phpunit
```

当前测试套件超过 1,000 项测试和 1,000,000 条断言，并包含标准向量与独立参考模型测试。

## 代码质量

```bash
# 静态分析（PHPStan level 9）
vendor/bin/phpstan analyse

# 代码风格检查
vendor/bin/php-cs-fixer fix --dry-run --diff

# 代码风格修复
vendor/bin/php-cs-fixer fix

# 一键检查全部
composer check
```

## CI

GitHub Actions 在推送到 `main`、向 `main` 提交 PR 时运行；发布流程从 `main` 手动启动，CI 通过后创建版本 tag 并发布。操作步骤见[发布流程](docs/RELEASE.md)。

- **多版本测试** — PHP 8.2 / 8.3 / 8.4 / 8.5 矩阵测试
- **静态分析** — PHPStan level 9 + PSR-12 代码风格检查
- **安全审计** — Composer audit 依赖漏洞扫描

## 文档

- [SM2 详细文档](docs/sm2.md) — 密钥生成、加密/解密、签名/验签、PEM、密钥交换
- [SM3 详细文档](docs/sm3.md) — 哈希计算、流式哈希、HMAC-SM3、PBKDF2-HMAC-SM3
- [SM4 详细文档](docs/sm4.md) — 六种门面模式、CCM、填充方式与安全追踪器
- [发布流程](docs/RELEASE.md) — 发布前检查、版本 tag、changelog、恢复和标签保护
- [变更日志](CHANGELOG.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)

## 许可证

[MIT](LICENSE)
