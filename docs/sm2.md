# SM2 算法使用指南

## 概述

SM2 是中国椭圆曲线公钥密码算法标准 (GM/T 0003-2012)，提供以下功能：
- 密钥对生成
- 公钥加密/解密（C1C3C2 / C1C2C3）
- 数字签名与验证（RS拼接 / DER格式）
- PEM 格式密钥导入/导出（SEC 1 / PKCS#8 / SubjectPublicKeyInfo）
- DER 二进制格式密钥导入/导出
- 密钥交换（GM/T 0003 第6部分 ECDH 协议）

## 密钥生成

```php
use CryptoSm\SM2\Sm2;

// 生成新的密钥对
$keypair = Sm2::generateKeyPairHex();

$privateKey = $keypair->getPrivateKey(); // 64 个十六进制字符
$publicKey = $keypair->getPublicKey();    // 128 个十六进制字符
```

## 加密和解密

### 基本用法

```php
use CryptoSm\SM2\Sm2;

// 公钥加密
$publicKey = '...'; // 128 个十六进制字符
$plaintext = 'Hello World';
$ciphertext = Sm2::doEncrypt($plaintext, $publicKey);

// 私钥解密
$privateKey = '...'; // 64 个十六进制字符
$decrypted = Sm2::doDecrypt($ciphertext, $privateKey);
```

### 密码模式

SM2 支持两种密码模式：

- 模式 1（默认，推荐）：C1 || C3 || C2
- 模式 0（旧版兼容）：C1 || C2 || C3

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Sm2CipherOptions;

// 使用密码模式 0（旧版）
$options = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0);
$ciphertext = Sm2::doEncrypt($plaintext, $publicKey, $options);
$decrypted = Sm2::doDecrypt($ciphertext, $privateKey, $options);
```

## 数字签名

### 不带哈希的签名

```php
use CryptoSm\SM2\Sm2;

// 签名
$privateKey = '...'; // 64 个十六进制字符
$message = '待签名消息';
$signature = Sm2::doSignature($message, $privateKey);
// 签名为 128 个十六进制字符 (r || s)

// 验证
$publicKey = '...'; // 128 个十六进制字符
$isValid = Sm2::doVerifySignature($message, $signature, $publicKey);
```

### 带哈希和用户 ID 的签名

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;

// 使用哈希和公钥签名
$options = (new SignatureOptions())
    ->setHash(true)
    ->setPublicKey($publicKey);

$signature = Sm2::doSignature($message, $privateKey, $options);

// 使用相同选项验证
$isValid = Sm2::doVerifySignature($message, $signature, $publicKey, $options);
```

### 自定义用户 ID

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;

// 自定义用户 ID（默认为 '1234567812345678'，即 GM/T 0009-2012 标准）
$options = (new SignatureOptions())
    ->setHash(true)
    ->setPublicKey($publicKey)
    ->setUserId('custom_user_id');

$signature = Sm2::doSignature($message, $privateKey, $options);
```

### DER 格式签名

SM2 支持 DER 编码的签名格式，验签时自动检测 RS 拼接或 DER 格式：

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;

// 使用 DER 格式签名
$options = (new SignatureOptions())->setDer(true);
$signature = Sm2::doSignature($message, $privateKey, $options);

// 验签自动检测格式
$isValid = Sm2::doVerifySignature($message, $signature, $publicKey, $options);
```

## PEM 格式密钥导入/导出

SM2 支持三种 PEM 格式的密钥导入/导出，方便与 OpenSSL、OpenSSL 兼容系统互操作。

### 导出私钥

```php
use CryptoSm\SM2\Pem;

// SEC 1 格式（EC PRIVATE KEY）
$pem = Pem::exportPrivateKey($privateKey);

// SEC 1 格式 + 公钥
$pem = Pem::exportPrivateKey($privateKey, $publicKey);

// PKCS#8 格式（PRIVATE KEY）
$pem = Pem::exportPrivateKeyPkcs8($privateKey);
```

### 导出公钥

```php
use CryptoSm\SM2\Pem;

// SubjectPublicKeyInfo 格式（PUBLIC KEY）
$pem = Pem::exportPublicKey($publicKey);
```

### 导入私钥

```php
use CryptoSm\SM2\Pem;

// 自动识别 SEC 1 或 PKCS#8 格式
$result = Pem::importPrivateKey($pem);
$privateKey = $result['privateKey']; // 64 字符 hex
$publicKey  = $result['publicKey'];  // 128 字符 hex（自动推导）
```

### 导入公钥

```php
use CryptoSm\SM2\Pem;

$publicKey = Pem::importPublicKey($pem); // 128 字符 hex
```

## DER 二进制格式导入/导出

如果需要处理原始 DER 二进制数据（不包含 PEM 头尾和 Base64 编码），可以使用以下方法：

```php
use CryptoSm\SM2\Pem;

// 导出 DER 二进制
$der = Pem::exportPrivateKeyDer($privateKey, $publicKey);
$der = Pem::exportPrivateKeyPkcs8Der($privateKey);
$der = Pem::exportPublicKeyDer($publicKey);

// 导入 DER 二进制
$result = Pem::importPrivateKeyFromDer($der); // 自动识别 SEC 1 / PKCS#8
$publicKey = Pem::importPublicKeyFromDer($der);
```

## 密钥交换

SM2 密钥交换遵循 GM/T 0003-2012 第6部分，实现 ECDH 风格的密钥协商协议：

```php
use CryptoSm\SM2\KeyExchange;
use CryptoSm\SM2\Sm2;

// 双方各自生成静态密钥对
$keypairA = Sm2::generateKeyPairHex();
$keypairB = Sm2::generateKeyPairHex();

// 双方各自生成临时密钥对
$ephemeralA = KeyExchange::generateEphemeralKeyPair();
$ephemeralB = KeyExchange::generateEphemeralKeyPair();

// 交换临时公钥后，双方各自计算共享密钥
$klen = 32; // 期望密钥长度（字节）

// 发起方（A）计算共享密钥
$sharedKeyA = KeyExchange::initiatorComputeKey(
    $keypairA->getPrivateKey(),   // dA
    $ephemeralA->getPrivateKey(), // rA
    $keypairB->getPublicKey(),    // PB
    $ephemeralB->getPublicKey(),  // RB
    $klen
);

// 响应方（B）计算共享密钥
$sharedKeyB = KeyExchange::responderComputeKey(
    $keypairB->getPrivateKey(),   // dB
    $ephemeralB->getPrivateKey(), // rB
    $keypairA->getPublicKey(),    // PA
    $ephemeralA->getPublicKey(),  // RA
    $klen
);

// $sharedKeyA === $sharedKeyB
```

### 密钥确认

GM/T 0003-2012 密钥交换协议包含密钥确认步骤，可验证双方计算结果一致：

```php
use CryptoSm\SM2\KeyExchange;

// 完整密钥交换（含中间值，用于密钥确认）
$resultA = KeyExchange::initiatorComputeKeyFull(
    $keypairA->getPrivateKey(), $ephemeralA->getPrivateKey(),
    $keypairB->getPublicKey(), $ephemeralB->getPublicKey(),
    $klen
);
// $resultA = ['key' => '...', 'xV' => '...', 'yV' => '...']

$resultB = KeyExchange::responderComputeKeyFull(
    $keypairB->getPrivateKey(), $ephemeralB->getPrivateKey(),
    $keypairA->getPublicKey(), $ephemeralA->getPublicKey(),
    $klen
);

// 计算密钥确认哈希
$s1 = KeyExchange::computeInitiatorConfirmation(
    $resultA['xV'],
    $resultA['yV'],
    '1234567812345678',
    '1234567812345678',
    $ephemeralA->getPublicKey(),
    $ephemeralB->getPublicKey(),
    $keypairA->getPublicKey(),
    $keypairB->getPublicKey()
);
$s2 = KeyExchange::computeResponderConfirmation(
    $resultA['xV'],
    $resultA['yV'],
    '1234567812345678',
    '1234567812345678',
    $ephemeralA->getPublicKey(),
    $ephemeralB->getPublicKey(),
    $keypairA->getPublicKey(),
    $keypairB->getPublicKey()
);

// 发起方验证 S2，响应方验证 S1
```

### 自定义 ID

```php
use CryptoSm\SM2\KeyExchange;

// 自定义用户 ID（默认 '1234567812345678'）
$sharedKeyA = KeyExchange::initiatorComputeKey(
    $dA, $rA, $PB, $RB, 32,
    'ID_A', 'ID_B'
);
```

## 使用 SmCrypto 门面类

所有 SM2 功能均可通过 `SmCrypto` 门面类统一调用：

```php
use CryptoSm\SmCrypto;

// 密钥生成
$pair = SmCrypto::generateKeyPair();

// 加密/解密
$ciphertext = SmCrypto::encrypt('Hello', $publicKey);
$plaintext  = SmCrypto::decrypt($ciphertext, $privateKey);

// 签名/验签
$signature = SmCrypto::sign('message', $privateKey);
$valid     = SmCrypto::verify('message', $signature, $publicKey);

// PEM 导入/导出
$pem  = SmCrypto::exportPrivateKeyPem($privateKey, $publicKey);
$keys = SmCrypto::importPrivateKeyPem($pem);

// DER 导入/导出
$der  = SmCrypto::exportPrivateKeyDer($privateKey, $publicKey);
$keys = SmCrypto::importPrivateKeyFromDer($der);

// 密钥交换
$ephemeralA = SmCrypto::generateExchangeKeyPair();
$ephemeralB = SmCrypto::generateExchangeKeyPair();
$sharedKey = SmCrypto::initiatorKeyExchange($dA, $rA, $PB, $RB, 32);
```

## 完整示例

```php
<?php

declare(strict_types=1);

require_once 'vendor/autoload.php';

use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;
use CryptoSm\SM2\Sm2CipherOptions;
use CryptoSm\SM2\Pem;
use CryptoSm\SM2\KeyExchange;

// 1. 生成密钥对
$keypair = Sm2::generateKeyPairHex();
$privateKey = $keypair->getPrivateKey();
$publicKey = $keypair->getPublicKey();

echo "私钥: $privateKey\n";
echo "公钥: $publicKey\n\n";

// 2. 加密/解密
$plaintext = 'Hello World';
$ciphertext = Sm2::doEncrypt($plaintext, $publicKey);
$decrypted = Sm2::doDecrypt($ciphertext, $privateKey);
echo "解密: $decrypted\n\n";

// 3. 数字签名
$message = '测试消息';
$options = (new SignatureOptions())->setHash(true)->setPublicKey($publicKey);
$signature = Sm2::doSignature($message, $privateKey, $options);
$isValid = Sm2::doVerifySignature($message, $signature, $publicKey, $options);
echo "签名验证: " . ($isValid ? '有效' : '无效') . "\n\n";

// 4. PEM 导入/导出
$pem = Pem::exportPrivateKey($privateKey, $publicKey);
echo "PEM 私钥:\n$pem";
$imported = Pem::importPrivateKey($pem);
echo "导入后私钥匹配: " . ($imported['privateKey'] === $privateKey ? '是' : '否') . "\n\n";

// 5. 密钥交换
$pairA = Sm2::generateKeyPairHex();
$pairB = Sm2::generateKeyPairHex();
$ephA = KeyExchange::generateEphemeralKeyPair();
$ephB = KeyExchange::generateEphemeralKeyPair();

$klen = 32;
$sharedA = KeyExchange::initiatorComputeKey(
    $pairA->getPrivateKey(), $ephA->getPrivateKey(),
    $pairB->getPublicKey(), $ephB->getPublicKey(), $klen
);
$sharedB = KeyExchange::responderComputeKey(
    $pairB->getPrivateKey(), $ephB->getPrivateKey(),
    $pairA->getPublicKey(), $ephA->getPublicKey(), $klen
);
echo "密钥交换共享密钥匹配: " . ($sharedA === $sharedB ? '是' : '否') . "\n";
```

## 错误处理

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\Exception\InvalidKeyException;
use CryptoSm\Exception\CryptoException;

try {
    $ciphertext = Sm2::doEncrypt('data', $publicKey);
    $decrypted = Sm2::doDecrypt($ciphertext, $privateKey);
} catch (InvalidKeyException $e) {
    echo "密钥无效: " . $e->getMessage();
} catch (CryptoException $e) {
    echo "加密错误: " . $e->getMessage();
}
```

## 技术细节

- **曲线**: SM2 推荐曲线（256位素数域）
- **OID**: 1.2.156.10197.1.301
- **点乘优化**: 8-bit 窗口法 + 基点预计算缓存（255 条目）+ 变基点缓存（最多 16 条目）
- **签名默认用户 ID**: `1234567812345678`（GM/T 0009-2012）
- **DER 签名**: 验签时自动检测 RS 拼接 vs DER 格式
- **标准**: GM/T 0003-2012

## 注意事项

1. 私钥必须为 64 个十六进制字符（256 位）
2. 公钥必须为 128 个十六进制字符（512 位，X||Y 坐标）
3. 密文格式：C1(128字符) + C3(64字符) + C2(可变长度)（模式1）
4. 签名：128 个十六进制字符 (r||s) 或 DER 格式
5. PEM 格式支持 SEC 1、PKCS#8（私钥）和 SubjectPublicKeyInfo（公钥）
6. 密钥交换双方必须使用相同的用户 ID 和密钥长度参数
