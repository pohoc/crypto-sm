# 升级迁移指南

本文说明升级到当前版本时需要核对的兼容性变化，以及多进程部署中 SM4 追踪器的接入要求。

## PHP 版本

当前 Composer 要求 PHP `^8.2`（即 PHP 8.2 或更高的 8.x 版本），并需要 GMP 和 OpenSSL 扩展。PHP 8.0/8.1 不再受支持。部署前请在目标 PHP 版本执行 `composer check-platform-reqs`。

## SM2 签名

当前 `Sm2::doSignature()` / `doVerifySignature()` 默认按标准计算 `SM3(ZA || M)`。旧版本默认关闭哈希，并把输入字节作为整数直接代入签名公式。这种旧行为对任意长度输入都可能产生签名，不能与当前标准消息签名互换。

- 新签名使用默认选项，并用新签名重新签署需要长期验证的数据。
- 若协议已经提供恰好 32 字节的预计算摘要，显式使用 `SignatureOptions::setHash(false)`；摘要必须按双方约定生成，不能把任意原始消息直接传入。
- 旧版 `setHash(false)` 对任意长度原始字节生成的签名，不保证能由当前 API 验证。当前 API 有意拒绝非 32 字节输入。需要验证这类历史签名时，应在隔离的旧版验证程序中按旧规则验证，完成核对后再迁移签名数据；不要为了兼容而放宽新 API 的输入校验。
- 旧版默认签名仅在新旧双方使用相同的原始输入、密钥和签名编码时才可能继续互验；升级前应使用真实存档签名做兼容性清点。

## SM4 默认密文格式

当前 `Sm4::encrypt()`、`Sm4Options` 和 `Sm4::encryptPayload()` 默认使用 GCM。无选项 `Sm4::encrypt()` 输出自包含的 `SM4GCM2` 格式，包含版本标记、IV、密文和认证标签。旧版本默认使用 CBC，旧自包含 CBC 密文应通过 `Sm4::decryptLegacyCbc($ciphertext, $key)` 读取；这是未认证的兼容解密入口，应用应在可信数据迁移流程中使用。

- 默认模式已改变。需要保持旧 CBC 写入协议的调用点，必须显式创建 `Sm4Options` 并设置 `Sm4::MODE_CBC`，同时自行确保 IV 安全性和密文完整性保护。
- 新 GCM 密文不可被旧版 CBC 默认解密器读取。滚动升级期间应先部署能读取新旧格式的解密端，再切换写入端；旧版实例不得解密新版本写出的 GCM 数据。
- 结构化 payload 的解密模式必须来自可信配置。不要根据未认证密文中的字段自动切换模式。
- 当前仍支持读取 `SM4GCM1` 旧 GCM 格式和自包含旧 CBC 格式；其他外部封装或自定义 CBC payload 应按旧协议显式解析，并验证其完整性后再解密。

## 多进程和长驻 worker 的共享追踪器

GCM/CCM 默认追踪器只在当前 PHP 进程内有效。容量达到 65,536 条时会失败关闭；重启会丢失本地历史。因此不能把默认配置用于跨 Worker、容器实例或重启仍复用同一密钥的全局唯一性保证。应用应实现 `CryptoSm\Interfaces` 中的追踪器接口，并在任何相关加密或解密操作前，于每个 worker 的启动阶段完成配置。配置在首次相关操作后锁定。

| 接口 | 必须共享并原子维护的状态 |
| --- | --- |
| `GcmIvTrackerInterface` | 每把密钥下的 IV 唯一记录，以及该密钥最多 `2^32` 次加密调用的预算 |
| `GcmTagLengthTrackerInterface` | 每把密钥固定的 GCM 标签长度 |
| `CcmNonceTrackerInterface` | 每把密钥下的 nonce 唯一记录 |
| `CcmTagLengthTrackerInterface` | 每把密钥固定的 CCM 标签长度 |
| `CcmBlockUsageTrackerInterface` | 每把密钥累计 CCM 分组调用数，不超过 `2^61`；加密和解密都计数，认证失败也计数 |

实现要求：

1. 每个 `claim` 操作必须对共享存储具备原子性。并发的重复 key/IV 或 key/nonce 只能有一个调用成功；计数器必须原子检查上限并递增，不能采用“先读后写”的非事务流程。
2. 把传入的原始 16 字节 SM4 密钥转换为稳定的不可逆标识后再作为存储键，例如 `SHA-256(key)`；不要把接口收到的原始密钥持久化到追踪表或日志。IV/nonce 也可用摘要作为索引，但须保留无碰撞假设并避免把敏感业务数据写入日志。
3. 后端超时、不可用、结果不确定或原子写入失败时，抛出异常并拒绝本次密码操作。只有接口明确返回 `false` 时才按已重复、策略冲突或预算耗尽拒绝；不能在共享存储故障时回退到本地表。
4. 所有共享同一密钥的进程必须连接到同一逻辑状态域，并采用一致的密钥指纹算法、键版本命名空间和保留期。密钥轮换应使用新密钥指纹，不能删除仍在使用密钥的历史记录。
5. CCM 的 nonce、标签长度和分组调用追踪器需要协调同一密钥生命周期；GCM 的 IV 追踪器必须负责接口注释要求的单密钥调用总数上限。单独部署 nonce/IV 表不足以实现完整策略。

示例（应用提供实现类）：

```php
use CryptoSm\Crypto\Ccm;
use CryptoSm\Crypto\Gcm;

Gcm::setIvTracker($applicationGcmIvTracker);
Gcm::setTagLengthTracker($applicationGcmTagLengthTracker);

Ccm::setNonceTracker($applicationCcmNonceTracker);
Ccm::setTagLengthTracker($applicationCcmTagLengthTracker);
Ccm::setBlockUsageTracker($applicationCcmBlockUsageTracker);
```

上述示例中的变量由应用创建，库不内置 PDO、Redis 或其他共享存储适配器。接口单测只能验证库对 `true`、`false` 和异常的处理，不能证明应用后端在多进程竞争、故障转移、数据恢复或网络分区时仍满足原子性和一致性。应用应针对实际数据库/缓存集群做并发竞争与故障注入验证。

## 发版前清单

- 运行环境为 PHP 8.2+，并安装 GMP、OpenSSL。
- 盘点所有 SM2 默认签名调用以及以 `setHash(false)` 验证的存档签名。
- 盘点依赖默认 CBC 或旧密文格式的 SM4 调用点，按读写切换顺序部署。
- 若密钥跨进程或重启复用，为 GCM/CCM 配置应用级共享追踪器；无法提供可靠共享状态时，使用单一加密进程或按实例隔离密钥。
- 确认共享追踪器把后端错误作为拒绝处理，不允许本地回退，并在目标部署环境验证竞争与重启场景。
