# SM2 算法使用指南

## 概述

SM2 是中国椭圆曲线公钥密码算法标准 (GM/T 0003-2012)，提供以下功能：
- 密钥对生成
- 公钥加密/解密（默认 C1C3C2，C1 为 SEC1 `04||x||y`；兼容无前缀输入和 C1C2C3）
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
- 模式 0（GM/T 0003.4-2012 顺序兼容）：C1 || C2 || C3

默认密文中的 C1 使用 SEC1 未压缩点编码 `04 || x || y`，符合 GB/T 32918.1-2016 的点编码规则。需要兼容旧调用方只接收 `x || y` 的密文时，可设置 `setIncludePointPrefix(false)`；解密端同时接受带前缀和不带前缀的 C1。

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\Sm2CipherOptions;

// 使用密码模式 0（旧版）
$options = (new Sm2CipherOptions())->setCipherMode(Sm2::CIPHER_MODE_0);
$ciphertext = Sm2::doEncrypt($plaintext, $publicKey, $options);
$decrypted = Sm2::doDecrypt($ciphertext, $privateKey, $options);
```

## 数字签名

### 默认 SM2 消息签名

```php
use CryptoSm\SM2\Sm2;

// 默认按 SM2 标准计算 SM3(ZA || M) 后签名
$privateKey = '...'; // 64 个十六进制字符
$message = '待签名消息';
$signature = Sm2::doSignature($message, $privateKey);
// 签名为 128 个十六进制字符 (r || s)

// 验证
$publicKey = '...'; // 128 个十六进制字符
$isValid = Sm2::doVerifySignature($message, $signature, $publicKey);
```

### 签署预计算摘要

仅当调用方已经按协议算好 32 字节摘要时，才显式关闭消息哈希。此模式会把这 32 字节直接作为签名公式的输入；不要传入任意长度的原始消息。

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;

// 仅用于已计算好的 32 字节摘要
$digest = hex2bin('...'); // 恰好 32 字节
$options = (new SignatureOptions())
    ->setHash(false)
    ->setPublicKey($publicKey);

$signature = Sm2::doSignature($digest, $privateKey, $options);

$isValid = Sm2::doVerifySignature($digest, $signature, $publicKey, $options);
```

### 自定义用户 ID

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;

// 自定义用户 ID（默认为 '1234567812345678'，即 GM/T 0009-2023 第 10 章规定值）
$options = (new SignatureOptions())
    ->setHash(true)
    ->setPublicKey($publicKey)
    ->setUserId('custom_user_id');

$signature = Sm2::doSignature($message, $privateKey, $options);
```

> **长度限制（GM/T 0009-2023 第 8.1 节）**：ENTL 是固定 16 位字段，用户 ID 的
> 位长不得超过 0xFFFF，即**最长 8191 字节**。超长 ID 会抛出 `CryptoException`
> 而非静默截断——否则 Z 值结构与其它国密实现不兼容。

### DER 格式签名

SM2 支持 DER 编码的签名格式，验签时自动检测 RS 拼接或 DER 格式：

```php
use CryptoSm\SM2\Sm2;
use CryptoSm\SM2\SignatureOptions;

// 使用 DER 格式签名
$options = (new SignatureOptions())->setDer(true);
$signature = Sm2::doSignature($message, $privateKey, $options);

// 验签自动检测格式；若 64 字节输入同时符合 DER 与 r||s 外形，会分别验证两种候选而不按长度猜格式。
$isValid = Sm2::doVerifySignature($message, $signature, $publicKey, $options);
```

若需严格限定 DER 输入，可在验签选项中设置 `setDer(true)`。

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

> **协议边界**：这里的 API 实现 GM/T 0003 密钥交换，不是 TLS 1.3 的 key exchange。RFC 8998 明确规定，其 TLS 配置不得使用 SM2 密钥交换协议；该配置使用 TLS 1.3 自身的 SM2 曲线 ECDHE 与 TLS key schedule。不要把下方 API 直接接入 TLS 握手。

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

> **临时密钥必须一次性使用**：每次密钥交换、每个参与方都必须生成新的临时密钥对。不得跨会话、跨对端或跨协议角色复用临时私钥 `rA`/`rB`。API 同时接受调用方传入的标量，无法可靠检测跨进程或进程重启后的复用；调用方必须负责生成、隔离并在会话结束后停止使用该临时密钥。静态密钥不得代替临时密钥。

> **klen 取值范围**：1 字节 ≤ klen ≤ `KeyExchange::MAX_KLEN`（4 KiB）。为避免纯 PHP SM3 KDF 被超大输出长度放大为高 CPU 与内存消耗，请只派生协议实际需要的密钥长度。
> 超出范围抛出 `InvalidKeyException`（上界为防滥用保护，远超合法用途）。

### 密钥确认便捷方法

除上述分步 API 外，还提供一步到位的确认变体：

```php
use CryptoSm\SM2\KeyExchange;

// A 在收到 RB 后计算密钥、预期的 S1（响应方的 SB，前缀 0x02）和 SA（前缀 0x03）。
// 此时 SA 只能保存在本地，不能发送。
$resultA = KeyExchange::initiatorComputeKeyWithConfirmation(
    $dA, $rA, $PB, $RB, $klen, $ida, $idb
);
// 返回 ['key' => ..., 'xV' => ..., 'yV' => ..., 's1' => ..., 'sa' => ...]

// B 收到 RA 后计算密钥、发送给 A 的 SB（前缀 0x02）和预期的 S2（A 的 SA，前缀 0x03）
$resultB = KeyExchange::responderComputeKeyWithConfirmation(
    $dB, $rB, $PA, $RA, $klen, $ida, $idb
);
// 返回 ['key' => ..., 'xV' => ..., 'yV' => ..., 's2' => ..., 'sb' => ...]

// B -> A：发送 (RB, resultB['sb'])。A 先验证响应方确认；失败时立即中止。
$receivedSB = $resultB['sb']; // 实际协议中取自 B 的消息
if (!KeyExchange::verifyResponderConfirmationForInitiator($resultA['s1'], $receivedSB)) {
    throw new RuntimeException('SM2 key confirmation failed');
}

// 只有 S1 == SB 后，A 才能发送 SA 给 B。
$receivedSA = $resultA['sa']; // 实际协议中此时才发送并由 B 接收
if (!KeyExchange::verifyInitiatorConfirmationForResponder($resultB['s2'], $receivedSA)) {
    throw new RuntimeException('SM2 key confirmation failed');
}

// A 在验证 SB 后、B 在验证 SA 后，双方才可使用 resultA/resultB 中的协商密钥。
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

// A 本地计算预期 S1；0x02 对应响应方发出的 SB。
$s1 = KeyExchange::computeResponderConfirmation(
    $resultA['xV'],
    $resultA['yV'],
    '1234567812345678',
    '1234567812345678',
    $ephemeralA->getPublicKey(),
    $ephemeralB->getPublicKey(),
    $keypairA->getPublicKey(),
    $keypairB->getPublicKey()
);
// B 本地计算预期 S2；0x03 对应发起方发出的 SA。
$s2 = KeyExchange::computeInitiatorConfirmation(
    $resultB['xV'],
    $resultB['yV'],
    '1234567812345678',
    '1234567812345678',
    $ephemeralA->getPublicKey(),
    $ephemeralB->getPublicKey(),
    $keypairA->getPublicKey(),
    $keypairB->getPublicKey()
);

// B 计算并发送 SB；A 从收到的协议消息中取出 receivedSB。
$sb = KeyExchange::computeResponderConfirmation(
    $resultB['xV'],
    $resultB['yV'],
    '1234567812345678',
    '1234567812345678',
    $ephemeralA->getPublicKey(),
    $ephemeralB->getPublicKey(),
    $keypairA->getPublicKey(),
    $keypairB->getPublicKey()
);
// A 必须先验证收到的 SB。失败时中止，不计算/发送 SA，也不使用协商密钥。
if (!KeyExchange::verifyResponderConfirmationForInitiator($s1, $receivedSB)) {
    throw new RuntimeException('SM2 key confirmation failed');
}

// 只有验证 SB 成功后，A 才计算并发送 SA；B 从收到的协议消息中取出 receivedSA。
$sa = KeyExchange::computeInitiatorConfirmation(
    $resultA['xV'],
    $resultA['yV'],
    '1234567812345678',
    '1234567812345678',
    $ephemeralA->getPublicKey(),
    $ephemeralB->getPublicKey(),
    $keypairA->getPublicKey(),
    $keypairB->getPublicKey()
);

// B 验证收到的 SA。方法内部按固定长度十六进制进行恒定时间比较。
if (!KeyExchange::verifyInitiatorConfirmationForResponder($s2, $receivedSA)) {
    throw new RuntimeException('SM2 key confirmation failed');
}

// A 在验证 SB 后、B 在验证 SA 后，双方才可使用协商密钥。
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
- **签名默认用户 ID**: `1234567812345678`（GM/T 0009-2023 第 10 章）
- **DER 签名**: 验签时自动检测 RS 拼接 vs DER 格式
- **标准**: GM/T 0003-2012

## 注意事项

1. 私钥必须为 64 个十六进制字符（256 位）
2. 公钥必须为 128 个十六进制字符（512 位，X||Y 坐标）
3. 密文格式：C1(130字符，SEC1 `04||x||y`) + C3(64字符) + C2(可变长度)（模式1）；可通过 `setIncludePointPrefix(false)` 输出旧式 128 字符 C1
4. 签名：128 个十六进制字符 (r||s) 或 DER 格式
5. PEM 格式支持 SEC 1、PKCS#8（私钥）和 SubjectPublicKeyInfo（公钥）
6. 密钥交换双方必须使用相同的用户 ID 和密钥长度参数
7. 签名用户 ID 最长 8191 字节（ENTL 为 16 位字段，超长直接拒绝）
8. PEM 导入只接受单个完整密钥块（块外仅允许空白），避免前后缀或多个 PEM 块造成解析器选取不同密钥；DER 导入要求结构严格匹配。SubjectPublicKeyInfo 和 SEC1/PKCS#8 中的可选公钥支持压缩点（0x02/0x03 开头），并会解压后验证曲线点及私钥/公钥匹配

### 侧信道边界

本库以 PHP/GMP 实现椭圆曲线运算，不保证常数时间。当前窗口点乘会依据标量值访问预计算表，因此签名随机数、私钥等秘密标量的运算可能暴露于本地时序或缓存侧信道。若威胁模型包含本地攻击者，或要求严格侧信道防护，请改用经过审查的原生密码库、HSM，或隔离的签名服务；详见 [安全策略](../SECURITY.md#side-channel-boundary)。
