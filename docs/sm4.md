# SM4 算法使用指南

## 概述

SM4 是中国分组密码算法标准 (GM/T 0002-2012)，是一种 128 位分组密码，密钥长度也为 128 位。

本实现特性：
- **6 种加密模式**：ECB、CBC、CFB、OFB、CTR、GCM
- **5 种填充模式**：PKCS5/PKCS7、Zero、ISO 10126、ANSI X9.23、None
- **OpenSSL 加速**：ECB/CBC/CFB/OFB/CTR 优先使用 OpenSSL C 原生实现
- **纯 PHP 回退**：OpenSSL 不支持 SM4 时，ECB/CBC/CFB/OFB/CTR/GCM 自动使用纯 PHP SM4 block fallback
- **GCM 后端**：优先使用 OpenSSL SM4-ECB 做块加密，并由 `Gcm` 实现 CTR/GHASH（`GcmPure` 已废弃别名）
- **GCM 预热**：`Sm4::warmupGcm($key)` 可消除首次调用建表延迟

## 实现与性能预期

- GCM 当前由本库实现 CTR/GHASH，底层块加密优先调用 OpenSSL `SM4-ECB`
- OpenSSL 不支持 SM4 时会自动回退到纯 PHP SM4 block
- GCM 路径的性能会显著低于 `CBC/CFB/OFB/CTR`
- 如果业务依赖高吞吐 AEAD，应先通过基准测试确认性能满足业务要求

## 基本用法

### CBC 模式（默认，推荐）

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210'; // 32 字符 hex
$iv = 'fedcba9876543210fedcba9876543210';  // 32 字符 hex
$options = (new Sm4Options())
    ->setMode('cbc')
    ->setIv($iv);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

> **注意**：默认模式已从 ECB 改为 CBC。ECB 模式不安全，仅建议在兼容旧系统时使用。
> 不传 `Sm4Options` 时，默认 CBC 返回 `iv_hex + ciphertext_hex`，可直接传给 `Sm4::decrypt()`；显式传入 `Sm4Options` 时返回值只包含密文，调用方必须保存 IV。

## 加密模式

### ECB 模式（不推荐）

电子密码本模式 — 每个分组独立加密。**注意：ECB 模式不安全，相同明文会产生相同密文。**

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$options = (new Sm4Options())->setMode('ecb');

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

### CBC 模式（推荐）

密码块链接模式 — 每个分组与前一个密文分组进行 XOR 操作。

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = 'fedcba9876543210fedcba9876543210';
$options = (new Sm4Options())
    ->setMode('cbc')
    ->setIv($iv);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

### CFB 模式

密码反馈模式 — 将分组密码转换为流密码，支持不等长数据处理。

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = 'fedcba9876543210fedcba9876543210';
$options = (new Sm4Options())
    ->setMode('cfb')
    ->setIv($iv);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

### OFB 模式

输出反馈模式 — 生成密钥流与明文 XOR，适合噪声信道传输。

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = 'fedcba9876543210fedcba9876543210';
$options = (new Sm4Options())
    ->setMode('ofb')
    ->setIv($iv);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

### CTR 模式

计数器模式 — 将分组密码转换为流密码，支持并行加密。

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = 'fedcba9876543210fedcba9876543210';
$options = (new Sm4Options())
    ->setMode('ctr')
    ->setIv($iv);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

### GCM 模式

Galois/Counter 模式 — 提供加密 + 认证（AEAD），是当前最推荐的加密模式。

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = '000102030405060708090a0b';       // 12 字节 IV（推荐）
$options = (new Sm4Options())
    ->setMode('gcm')
    ->setIv($iv);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

#### GCM + 附加认证数据（AAD）

GCM 支持附加认证数据（AAD），可以保护不被加密但需要完整性验证的数据：

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = '000102030405060708090a0b';
$aad = 'associated_data_to_protect';

$options = (new Sm4Options())
    ->setMode('gcm')
    ->setIv($iv)
    ->setAad($aad);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

#### GCM 标签长度

GCM 认证标签长度默认 16 字节，可自定义（4/8/12/13/14/15/16）：

```php
$options = (new Sm4Options())
    ->setMode('gcm')
    ->setIv($iv)
    ->setTagLength(12); // 12 字节标签
```

> **注意**：GCM 密文格式为 `ciphertext_hex + tag_hex`。认证标签验证失败会抛出 `CryptoException`。

#### GCM 预热

GCM 首次调用时需要构建查表（约 1.7ms），可通过预热消除此延迟：

```php
use CryptoSm\SM4\Sm4;

// 在应用启动时预热（可选）
Sm4::warmupGcm($key);

// 后续 GCM 操作无建表延迟
$ciphertext = Sm4::encrypt($data, $key, $options);
```

#### GCM 使用约束

- 同一把密钥下，IV 不能重复使用
- 推荐使用 12 字节 IV
- GCM 路径的正确性通过测试向量覆盖，但吞吐量会低于 CBC/CTR
- 如果你看到 GCM 明显慢于 CBC/CTR，这是当前实现的预期性能特征

## 填充模式

### PKCS5/PKCS7 填充（默认）

最常用的填充方式，当数据长度不是 16 的倍数时自动填充：

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$options = (new Sm4Options())->setPadding('pkcs5');
$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

### Zero 填充

用零字节填充到块大小。该模式无法区分真实尾部 `\0` 和填充字节，仅用于兼容旧数据；新代码应使用 PKCS5/PKCS7 或 GCM。

```php
$options = (new Sm4Options())->setPadding('zero');
```

### ISO 10126 填充

随机字节填充（除最后一个字节为填充长度），提供一定的随机性：

```php
$options = (new Sm4Options())->setPadding('iso10126');
```

### ANSI X9.23 填充

零字节填充（除最后一个字节为填充长度）：

```php
$options = (new Sm4Options())->setPadding('ansix923');
```

### 无填充

数据长度必须是 16 的倍数：

```php
$data = str_pad('', 16, 'x'); // 必须是 16 的倍数
$options = (new Sm4Options())->setPadding('none');
```

## 使用 SmCrypto 门面类

```php
use CryptoSm\SmCrypto;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';

// CBC 加密（默认）
$ciphertext = SmCrypto::sm4Encrypt('Hello World', $key);
$plaintext = SmCrypto::sm4Decrypt($ciphertext, $key);

// 自包含 payload API（推荐）：自动携带 IV/tag 元数据
$payload = SmCrypto::sm4EncryptPayload('Hello World', $key, (new Sm4Options())->setMode(Sm4::MODE_GCM));
$plaintext = SmCrypto::sm4DecryptPayload($payload, $key);

// GCM 加密
$options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv('000102030405060708090a0b');
$ciphertext = SmCrypto::sm4Encrypt('Hello World', $key, $options);
$plaintext = SmCrypto::sm4Decrypt($ciphertext, $key, $options);

// 自定义选项
$options = (new Sm4Options())
    ->setMode(Sm4::MODE_CBC)
    ->setIv('fedcba9876543210fedcba9876543210')
    ->setPadding('pkcs5');
$ciphertext = SmCrypto::sm4Encrypt('Hello World', $key, $options);
```

## 完整示例

### CBC 模式

```php
<?php

declare(strict_types=1);

require_once 'vendor/autoload.php';

use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = 'fedcba9876543210fedcba9876543210';
$plaintext = 'Hello World';

$options = (new Sm4Options())
    ->setMode('cbc')
    ->setIv($iv);

$ciphertext = Sm4::encrypt($plaintext, $key, $options);
echo "密文: $ciphertext\n";

$decrypted = Sm4::decrypt($ciphertext, $key, $options);
echo "解密: $decrypted\n";
```

### GCM 模式

```php
<?php

declare(strict_types=1);

require_once 'vendor/autoload.php';

use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210';
$iv = '000102030405060708090a0b';
$plaintext = 'Hello World';

$options = (new Sm4Options())
    ->setMode('gcm')
    ->setIv($iv)
    ->setAad('additional data');

$ciphertext = Sm4::encrypt($plaintext, $key, $options);
echo "密文: $ciphertext\n";

$decrypted = Sm4::decrypt($ciphertext, $key, $options);
echo "解密: $decrypted\n";

// 篡改密文会导致认证失败
try {
    $tampered = substr_replace($ciphertext, "\xff", 0, 1);
    Sm4::decrypt($tampered, $key, $options);
} catch (\CryptoSm\Exception\CryptoException $e) {
    echo "认证失败: " . $e->getMessage() . "\n";
}
```

## 密钥和 IV 要求

| 模式 | 密钥长度 | IV 长度 | 推荐 | 说明 |
|------|----------|---------|------|------|
| **GCM** | 32 hex | 24 hex (12B) | ⭐ 推荐 | AEAD 加密+认证 |
| **CBC** | 32 hex | 32 hex (16B) | ✅ 可用 | 需配合HMAC保证完整性 |
| **CTR** | 32 hex | 32 hex (16B) | ✅ 可用 | 流密码模式 |
| **CFB** | 32 hex | 32 hex (16B) | ✅ 可用 | 流密码模式 |
| **OFB** | 32 hex | 32 hex (16B) | ✅ 可用 | 流密码模式 |
| **ECB** | 32 hex | 无 | ❌ 不推荐 | 不安全 |

## 技术细节

- **分组大小**: 128 位（16 字节）
- **密钥长度**: 128 位（16 字节）
- **轮数**: 32 轮
- **标准**: GM/T 0002-2012
- **GCM 实现**: 优先使用 OpenSSL SM4-ECB 做块加密；不可用时使用纯 PHP SM4 block fallback；CTR/GHASH 由本库 `Gcm` 类实现
- **GCM GHASH**: 使用 8-bit 查表法 + 16 层移位表 + reduction table 优化
- **GcmPure**: 已废弃别名，继承自 `Gcm`，将在未来版本移除

## 安全注意事项

1. **推荐使用 GCM 模式** — 提供加密 + 认证（AEAD），是目前最安全的选择
2. **CBC 模式**需配合 HMAC 等机制保证完整性
3. **ECB 模式不安全**，相同明文产生相同密文，仅用于兼容旧系统
4. 在 CBC/CFB/OFB/CTR 模式下，每次加密操作都应使用随机的 IV
5. GCM 模式的 IV 绝不能重复使用同一密钥加密不同数据
6. 显式传入 `Sm4Options` 时，密文不内嵌 IV，调用方必须单独保存并在解密时设置同一个 IV
7. 安全存储密钥（使用环境变量或安全的密钥管理）

## 错误处理

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\Exception\CryptoException;
use CryptoSm\Exception\InvalidKeyException;

try {
    $ciphertext = Sm4::encrypt($data, $key, $options);
    $plaintext = Sm4::decrypt($ciphertext, $key, $options);
} catch (InvalidKeyException $e) {
    echo "密钥无效: " . $e->getMessage();
} catch (CryptoException $e) {
    // GCM 认证失败也会抛出 CryptoException
    echo "加密/解密错误: " . $e->getMessage();
}
```
