# SM4 算法使用指南

## 概述

SM4 是中国分组密码算法标准 (GM/T 0002-2012)，是一种 128 位分组密码，密钥长度也为 128 位。

本实现特性：
- **6 种加密模式**：ECB、CBC、CFB、OFB、CTR、GCM
- **独立 CCM API**：`CryptoSm\Crypto\Ccm` 提供 CCM AEAD；它不属于 `Sm4` 门面的六种模式
- **5 种填充模式**：PKCS5/PKCS7、Zero、ISO 10126、ANSI X9.23、None
- **OpenSSL 加速**：ECB/CBC/CFB/OFB/CTR 优先使用 OpenSSL C 原生实现
- **纯 PHP 回退**：OpenSSL 不支持可用的 SM4 后端时，分组加密可回退到纯 PHP SM4 实现
- **平台要求**：纯 PHP SM4 回退需要 64 位 PHP；32 位 PHP 若无 OpenSSL SM4 支持，会明确抛出 `CryptoException`，不会继续产生不可靠的密码结果
- **GCM 后端**：运行时可执行 OpenSSL `SM4-GCM` 时使用原生 AEAD；否则由 `Gcm` 实现 CTR/GHASH，并优先使用 OpenSSL `SM4-ECB` 加密分组（`GcmPure` 已废弃别名）
- **GCM 预热**：`Sm4::warmupGcm($key)` 为兼容 API；当前无建表开销，但会校验密钥并创建/更新进程内 GCM 缓存，无需为性能调用

## 实现与性能预期

- OpenSSL 可执行 `SM4-GCM` 时使用原生 AEAD；否则由本库实现 CTR/GHASH，并优先调用 OpenSSL `SM4-ECB`
- OpenSSL 不支持所需 SM4 后端时，分组加密会回退到纯 PHP SM4 实现
- GCM 路径的性能会显著低于 `CBC/CFB/OFB/CTR`
- 如果业务依赖高吞吐 AEAD，应先通过基准测试确认性能满足业务要求

## 基本用法

### CBC 模式（显式兼容，无认证）

本页 CBC/CFB/OFB/CTR 示例中的固定 IV 只用于展示 API，不可直接用于生产。CBC 和 CFB 的 IV 必须在对应明文确定前不可预测，并且不可复用；OFB 的 IV 必须唯一；CTR 必须确保同一密钥下所有消息的计数器块都不重复。IV 不需要保密。省略 IV 时，库会为这些模式生成随机 IV；显式调用 `setIv()` 时，调用方必须按所选模式保证上述条件。此要求来自 [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final) 的 IV 与计数器块约束。

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;

$key = '0123456789abcdeffedcba9876543210'; // 32 字符 hex
$iv = 'fedcba9876543210fedcba9876543210';  // 32 字符 hex
$options = (new Sm4Options())
    ->setMode(Sm4::MODE_CBC)
    ->setIv($iv);

$ciphertext = Sm4::encrypt($data, $key, $options);
$plaintext = Sm4::decrypt($ciphertext, $key, $options);
```

> **安全边界**：CBC 只提供保密性，不验证密文完整性。攻击者可篡改 IV 以可控地翻转首个明文分组中的位；除非外层另有认证机制，否则新业务应使用下文的 GCM。CBC 默认仅为兼容既有调用保留。库会拒绝同一进程中重复使用的 CBC `(key, IV)`；无共享 tracker 时最多追踪 65,536 对，达到上限后失败关闭。跨进程部署应在启动时配置 `Sm4FeedbackIvTrackerInterface`。
> ECB 模式也不安全，仅建议在兼容旧系统时使用。
> `Sm4::encrypt()` 和 `Sm4Options` 默认使用 GCM。无选项调用返回 `SM4GCM2` 自包含格式（版本标记、IV、密文和标签），可直接解密；库仍接受 `SM4GCM1` 旧格式和旧版自包含 CBC 解密。使用 CBC 时必须显式选择该模式；CBC 不提供完整性保护。`Sm4::encryptPayload()` 同样默认 GCM。

结构化 payload 的 `decryptPayload()` 默认只接受 GCM。解密其他模式时，第三个参数须由可信配置指定，例如 `Sm4::decryptPayload($payload, $key, Sm4::MODE_CBC)`；不要从 payload 自身读取该参数。非 GCM 模式不认证密文。非 GCM 的填充策略也须由可信配置指定：默认要求 `pkcs5`，如加密使用 `none` 或 `ansix923`，须作为第六个参数传入，例如 `Sm4::decryptPayload($payload, $key, Sm4::MODE_CBC, 16, '', 'none')`。payload 中的 padding 只用于一致性校验，不作为策略来源。结构化 payload 解密拒绝 `zero` 与 `iso10126` 填充，因为前者无法区分尾部 NUL，后者无法验证填充字节。

GCM 标签长度默认要求 16 字节；使用其他受支持长度时，应从可信配置传入第四个参数，例如 `Sm4::decryptPayload($payload, $key, Sm4::MODE_GCM, 12)`。不要使用 payload 中的 `tagLength` 作为预期值。同一把密钥必须始终使用同一标签长度（NIST SP 800-38D §5.2.1.2）；加密或成功认证解密后，本进程会固定该 key 的标签长度并拒绝切换。跨进程部署应配置 `GcmTagLengthTrackerInterface` 共享追踪器，或由可信配置强制所有 worker 使用同一标签长度。`GcmIvTrackerInterface` 只协调 IV 唯一性，不负责同步标签长度策略。本地标签档案最多记录 65,536 把密钥；容量报错后不能在当前进程补配 tracker，需在启动时配置共享 tracker 并重启。

NIST SP 800-38D Appendix B 指出，系统/协议应监控并在必要时限制每把密钥的 GCM 失败验证次数；标签越短、单条密文和 AAD 越长，伪造风险增长越快。本库没有对失败次数做跨进程累计或自动限流。若解密输入可被攻击者反复提交，应用必须按密钥在所有 worker/重启间共享失败计数或速率限制，耗尽预算后拒绝后续验证并轮换密钥；对外应避免通过状态码、响应体或明显时序差异泄漏认证结果。当前 GCM 只支持 96–128 位标签，NIST Appendix C 对 32/64 位短标签的表格限制不适用于这些标签，但 Appendix B 的一般失败尝试建议仍适用。

直接使用 `CryptoSm\Crypto\Ccm` 时，同一把密钥必须始终使用同一标签长度（NIST SP 800-38C §5.3）。加密接口会在当前进程内拒绝同一密钥切换 CCM 标签长度；跨进程部署应配置实现 `CcmTagLengthTrackerInterface` 的共享追踪器，并在加密与成功解密时原子确认 key/tag-length 档案。`CcmNonceTrackerInterface` 只协调 nonce 唯一性，不负责同步标签长度策略。若未配置共享标签追踪器，跨进程标签长度一致性仍由可信部署配置保证。

CCM 还要求每把密钥生命周期内底层分组密码调用总数不超过 `2^61`（NIST SP 800-38C §5.1）。本库按 CCM 实际 MAC 与 CTR 块数计费，并在加密及解密认证尝试前预留用量；认证失败也会计入。默认计数只保存在当前进程，进程重启会清零。凡是密钥跨 worker 或重启复用，必须在首次 CCM 运算前配置实现 `CcmBlockUsageTrackerInterface` 的持久化原子追踪器；该追踪器应与 nonce/tag-length 追踪器共享同一密钥生命周期。未配置共享用量追踪器时，本地最多追踪 65,536 把密钥，容量耗尽后 fail closed。

CCM 的分组调用预算和 nonce 追踪不等同于失败认证次数限流。若远程用户能反复提交无效 CCM 标签，应由应用另外按密钥累计并限制认证失败；跨进程服务须使用持久化共享状态，达到阈值后拒绝验证并轮换密钥。不要将 `2^61` 分组调用上限当作在线标签猜测预算。

CCM 加密会在当前进程内拒绝重复的 key/nonce 对；未配置共享追踪器时，本地历史最多记录 65,536 对，达到上限后会 fail closed。长驻或多进程部署应在首次 CCM 处理前配置实现 `CcmNonceTrackerInterface` 的共享原子追踪器，持续协调同一密钥的 nonce 唯一性；还应配置上述分组调用用量追踪器与标签长度追踪器。nonce 历史、标签档案和分组调用计数在首次相关操作后锁定配置；容量报错后不能在当前进程补配 tracker，需在启动时配置共享追踪器并重启。未共享 nonce 追踪时，调用方仍须确保全生命周期内 nonce 不重复。解密不登记 nonce，但认证尝试会计入分组调用预算。

解密时默认要求空 AAD；如加密时设置了 AAD，调用方须从可信业务上下文传入第五个参数，例如 `Sm4::decryptPayload($payload, $key, Sm4::MODE_GCM, 16, $expectedAad)`。不要从待解密 payload 复制该值，否则无法防止不同上下文之间替换完整密文。

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

### CBC 模式（仅用于兼容；不提供完整性）

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

> **安全边界**：CFB 只提供保密性，不验证密文完整性。新业务请使用 GCM；兼容协议若必须使用 CFB，应采用 Encrypt-then-MAC 并先验证 MAC 再解密。

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

> **安全边界**：OFB 只提供保密性，不验证密文完整性。新业务请使用 GCM；兼容协议若必须使用 OFB，应采用 Encrypt-then-MAC 并先验证 MAC 再解密。

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

> **安全边界**：CTR 只提供保密性，不验证密文完整性。新业务请使用 GCM；兼容协议若必须使用 CTR，应采用 Encrypt-then-MAC 并先验证 MAC 再解密。

CTR 加密会按密钥登记实际消耗的 128 位计数器区间；CFB/OFB 加密会逐块登记该消息实际使用的每个分组密码输入，避免另一条消息把先前的反馈输入直接用作 IV。跨进程也需要此保证时，应配置 `Sm4StreamBlockTrackerInterface`；旧的 `Sm4FeedbackIvTrackerInterface` 只协调消息初始 IV。CCM/GCM 计数器及 CBC/ECB 分组输入也不由此 tracker 协调。为避免不同模式间发生可控的分组输入重用，本库在进程内 fail closed：同一把密钥只能用于其中一种模式；直接调用 `Sm4PurePhp::setKey()` 使用分组原语时，该密钥会被登记为 `raw-block`，也不能与其他模式共用。解密不登记范围，正常往返不会被拒绝。本地最多追踪 65,536 个区间，模式 key 表最多记录 65,536 把 key；达到任一上限后都会拒绝新记录。

跨进程或重启仍复用 SM4 key 时，必须在应用启动阶段配置持久化的 `Sm4KeyModeTrackerInterface`，并让所有 worker 共享同一原子 key-to-mode 记录。它收到的是原始 32 字节 SHA-256 key 指纹和模式名；同一 key 的同模式重复 claim 必须成功，跨模式 claim 必须失败。加密会原子 claim 模式；解密只调用只读 `isModeAllowed()`，不会因未认证输入创建或修改记录，因此解密专用的既有 key 必须由可信配置通过 `Sm4::registerKeyMode()` 预登记。不要用未经认证的 payload 元数据选择解密模式。该接口负责协调 ECB、CBC、CFB、OFB、CTR、GCM、CCM 与 `raw-block`，但不能代替各模式自己的 IV、nonce、计数器及用量 tracker。

追踪器的职责按模式区分：`Sm4KeyModeTrackerInterface` 独立负责模式隔离；`Sm4StreamBlockTrackerInterface` 只接管 CTR/CFB/OFB 的分组输入追踪。配置后，CTR 专用 `Sm4CtrCounterTrackerInterface` 和 CFB/OFB 初始 IV 的 `Sm4FeedbackIvTrackerInterface` 调用会被覆盖；CBC 走独立的 `claimCbcIv()` 路径，不受统一流 tracker 覆盖，仍由 `Sm4FeedbackIvTrackerInterface` 跨进程去重。因此混合部署可以同时配置统一流 tracker 和反馈 IV tracker：前者负责 CTR/CFB/OFB，后者仍负责 CBC。未配置统一流 tracker 时，CTR 才能使用专用 CTR tracker；CFB/OFB 的反馈 IV tracker 只协调初始 IV，进程内反馈输入范围仍由库登记。不要把统一流 tracker 当作 CBC IV 保护，也不要同时配置统一流 tracker 和被覆盖的 CTR/CFB/OFB 专用追踪器并假定它们会叠加。

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\Interfaces\Sm4KeyModeTrackerInterface;
use CryptoSm\Interfaces\Sm4StreamBlockTrackerInterface;
use CryptoSm\Interfaces\Sm4FeedbackIvTrackerInterface;

Sm4::setKeyModeTracker($sharedKeyModeTracker);
Sm4::setStreamBlockTracker($sharedStreamBlockTracker); // CTR、CFB、OFB 分组输入
Sm4::setFeedbackIvTracker($sharedFeedbackIvTracker);   // CBC 跨进程 IV 去重仍由它负责
// 仅解密的旧 key 按真实历史模式登记，不能一律登记为 GCM：
Sm4::registerKeyMode($oldCbcKeyHex, Sm4::MODE_CBC);
Sm4::registerKeyMode($existingGcmKeyHex, Sm4::MODE_GCM); // 另一把 key
```

同一服务同时运行流模式和 CBC 时，也应让不同模式使用不同密钥；统一流 tracker 只协调 CTR/CFB/OFB，不能代替 CBC 的反馈 IV tracker。

如果部署仅使用 CTR，且没有配置 `Sm4StreamBlockTrackerInterface`，可使用 CTR 专用 tracker。它负责跨进程协调 CTR 区间并替代本地 CTR 区间历史，因此不会受本地 65,536 条区间上限影响。配置统一流 tracker 时，此专用 tracker 不会被调用。它不会协调 CFB/OFB，也不替代 key-mode tracker 的跨模式隔离：

```php
use CryptoSm\SM4\Sm4;
use CryptoSm\Interfaces\Sm4CtrCounterTrackerInterface;

Sm4::setCtrCounterTracker($sharedCounterRangeTracker);
```

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

GCM 认证标签长度默认 16 字节，可自定义为 12/13/14/15/16 字节。通用 API 不支持 4/8 字节短标签：NIST SP 800-38D 仅允许在附录 C 的消息大小及密钥生命周期限制下使用短标签，本库无法替调用方执行跨请求的协议级计数限制。对同一密钥应固定使用一种标签长度：

```php
$options = (new Sm4Options())
    ->setMode('gcm')
    ->setIv($iv)
    ->setTagLength(12); // 12 字节标签
```

> **注意**：GCM 密文格式为 `ciphertext_hex + tag_hex`。认证标签验证失败会抛出 `CryptoException`。

#### GCM 预热

`Sm4::warmupGcm($key)` / `Gcm::warmup()` 保留为兼容 API。当前实现无建表开销，
预热不再是必需的优化手段。门面方法会校验密钥并创建或更新进程内 GCM 实例缓存，
缓存满时可能淘汰最早缓存项；它不会加密数据或登记 IV：

```php
use CryptoSm\SM4\Sm4;

Sm4::warmupGcm($key); // 可选；仅预热进程内缓存，不执行加密或登记 IV
$ciphertext = Sm4::encrypt($data, $key, $options);
```

#### GCM 使用约束

- 同一把密钥下，IV 不能重复使用（NIST SP 800-38D：这是 GCM 安全性的硬性要求）
- 按 NIST SP 800-38D §8.3，随机构造 IV 时同一密钥最多执行 `2^32` 次 GCM 加密；未配置共享 tracker 时，本库在当前进程内对显式和自动生成的 IV 合并计数，达到上限后拒绝加密。配置共享 tracker 后由 tracker 原子维护该限制
- 该限制跨进程、实例和重启按密钥累计。若密钥会跨 worker 或重启继续使用，必须配置共享 tracker 并在密钥轮换前持续维护同一计数；部署端还应在到达上限前轮换密钥
- **`Sm4` 门面的显式 IV 重用检测始终开启**：同一进程内用相同 key+IV 加密第二次会抛出 `CryptoException`。`Sm4::enableGcmIvTracking(false)` 会抛出 `CryptoException`，因为关闭防重会允许灾难性的 GCM nonce 重用。可在首次 GCM 加密前通过 `Sm4::resetGcmIvTracking()` 清空记录
- **直接使用低层 `CryptoSm\Crypto\Gcm` 时，默认也会检测本进程内重复的 key/IV**；门面显式 IV 与低层 API 共用最多 65536 项的追踪表。该保护无法跨进程或重启协调；需要分布式唯一性保证时，须在首次加密前配置 `Gcm::setIvTracker()`，并由 tracker 原子拒绝重复 key/IV
- 推荐使用 12 字节 IV
- **RFC 8998 的 TLS_SM4_GCM_SM3 profile 固定要求 12 字节 nonce、16 字节标签，并按 TLS 1.3 记录层规则生成 nonce**（[RFC 8998 §3.5.1](https://www.rfc-editor.org/rfc/rfc8998.html#section-3.5.1)，[RFC 8446 §5.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.3)）。本库通用门面的自动 IV 是 16 字节 `SM4R || 96-bit random`，`Sm4::encrypt()` 也不实现 TLS 记录层；这些 API 不构成 RFC 8998 TLS profile 实现。单独传入 12 字节 IV 也不会替代 TLS 规定的 nonce 派生和记录处理
- GCM 路径的正确性通过测试向量覆盖，但吞吐量会低于 CBC/CTR
- 如果你看到 GCM 明显慢于 CBC/CTR，这是当前实现的预期性能特征

#### GCM IV 重用检测

IV 重用对 GCM 是灾难性的（会泄露认证密钥并破坏保密性）。本库默认在进程内追踪已使用的 key+IV 组合：

```php
use CryptoSm\SM4\Sm4;

// 默认已开启，无需调用；此处仅作演示
Sm4::enableGcmIvTracking(true);

try {
    Sm4::encrypt($data, $key, $options);   // 第一次：正常
    Sm4::encrypt($data, $key, $options);   // 第二次同 IV：抛出 CryptoException
} catch (\CryptoSm\Exception\CryptoException $e) {
    // GCM IV reuse detected ...
}

```

> **注意**：
> - 未配置共享 tracker 时，本地 IV 唯一性追踪和每密钥调用计数是**进程内**保护，跨进程重启无法覆盖。随机 IV 降低碰撞概率，但不取消 NIST 规定的每密钥最多 `2^32` 次加密限制
> - 本地 key/IV 追踪表最多保存 65536 项，达到上限后会拒绝新的显式 IV；该进程在首次加密后已锁定 tracker 配置，容量报错后不能在线补配，需在启动时配置共享 tracker 并重启。自动生成 GCM IV（包括通过 `Sm4Options::getIv()` 提前物化的 IV）使用 `SM4R || 96-bit CSPRNG output`（128-bit IV），不占用显式追踪表。该 16-byte 命名空间保留给内部随机 IV，显式加密接口拒绝此类 IV，避免从加密结果取出 IV 后经其他入口重复使用。旧的 `SM4GCM1` payload（96-bit IV）仍可解密。GCM 支持非 96-bit IV；NIST 建议优先使用 96-bit IV 以提升互操作性，128-bit IV 在标准允许范围内。所有加密仍受每密钥调用上限约束；高频或跨进程业务应配置共享 tracker。
> - 推荐业务直接使用 `Sm4::encryptPayload()`，
>   它每次自动生成全新随机 IV 并随密文一起存储
> - `Sm4::enableGcmIvTracking(false)` 始终拒绝关闭追踪；`Sm4::resetGcmIvTracking()` 只能在首次 GCM 加密前调用，开始加密后历史锁定
> - 默认低层 GCM 与门面显式 IV 的重复追踪只覆盖当前进程；长生命周期或多进程服务请在首次加密前配置共享 tracker，或使用自动随机 IV

长生命周期服务需要跨 worker 或重启使用同一把密钥时，应通过 `Sm4::setGcmIvTracker()` 注入实现 `GcmIvTrackerInterface` 的共享追踪器，并通过 `Sm4::setGcmTagLengthTracker()` 注入实现 `GcmTagLengthTrackerInterface` 的共享标签长度追踪器。IV 追踪器必须以原子操作登记二进制 key/IV 组合，并按密钥累计所有 IV 长度和所有实例的 GCM 加密次数，在达到 `2^32` 次时拒绝后续调用；标签追踪器必须以原子操作固定每把密钥的标签长度。配置后 IV 追踪器会替代本地显式 IV 重用表和本地 per-key 计数。本地默认计数表最多保留 65536 把密钥，新密钥超限时 fail-closed。若直接使用底层 `CryptoSm\Crypto\Gcm`，可通过 `Gcm::setIvTracker()` 和 `Gcm::setTagLengthTracker()` 配置。请在应用启动时完成配置，并在该密钥到达上限前轮换。

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

### ISO 10126 填充（已废弃）

随机字节填充（除最后一个字节为填充长度）。

> **⚠️ 已废弃**：ISO 10126 已于 2007 年被 ISO 撤销，且随机填充字节无法在解密侧
> 校验完整性。运行时会触发 `E_USER_DEPRECATED`，计划在未来大版本移除。
> 新代码请使用 PKCS7 或 GCM 模式。

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

$gcmKey = '0123456789abcdeffedcba9876543210';

// 无选项时默认 GCM，自包含格式可直接往返
$ciphertext = SmCrypto::sm4Encrypt('Hello World', $gcmKey);
$plaintext = SmCrypto::sm4Decrypt($ciphertext, $gcmKey);

// 自包含 payload API（推荐）：自动携带 IV/tag 元数据
$payload = SmCrypto::sm4EncryptPayload('Hello World', $gcmKey, (new Sm4Options())->setMode(Sm4::MODE_GCM));
$plaintext = SmCrypto::sm4DecryptPayload($payload, $gcmKey);

// GCM 加密
$options = (new Sm4Options())->setMode(Sm4::MODE_GCM)->setIv('000102030405060708090a0b');
$ciphertext = SmCrypto::sm4Encrypt('Hello World', $gcmKey, $options);
$plaintext = SmCrypto::sm4Decrypt($ciphertext, $gcmKey, $options);

// 自定义选项
$options = (new Sm4Options())
    ->setMode(Sm4::MODE_CBC)
    ->setIv('fedcba9876543210fedcba9876543210')
    ->setPadding('pkcs5');
$cbcKey = '1123456789abcdeffedcba9876543210'; // CBC 与 GCM 使用不同密钥
$ciphertext = SmCrypto::sm4Encrypt('Hello World', $cbcKey, $options);
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
| **CTR** | 32 hex | 32 hex (16B) | ⚠️ 兼容 | 仅保密，不认证；需配合 MAC |
| **CFB** | 32 hex | 32 hex (16B) | ⚠️ 兼容 | 仅保密，不认证；需配合 MAC |
| **OFB** | 32 hex | 32 hex (16B) | ⚠️ 兼容 | 仅保密，不认证；需配合 MAC |
| **ECB** | 32 hex | 无 | ❌ 不推荐 | 不安全 |

## 技术细节

- **分组大小**: 128 位（16 字节）
- **密钥长度**: 128 位（16 字节）
- **轮数**: 32 轮
- **标准**: GM/T 0002-2012
- **GCM 实现**: 运行时可执行 OpenSSL `SM4-GCM` 时使用原生 AEAD；否则优先用 OpenSSL SM4-ECB 做块加密，并由本库 `Gcm` 类实现 CTR/GHASH；SM4-ECB 也不可用时回退到纯 PHP SM4 分组实现
- **GCM GHASH**: GF(2^128) 乘法采用 NIST SP 800-38D Algorithm 1 的规范直译实现；
  正确性由 RFC 8998 官方向量与独立参考模型差分测试（GcmReferenceModelTest）双重锚定
- **GcmPure**: 已废弃别名，继承自 `Gcm`，将在未来版本移除

## 安全注意事项

1. **推荐使用 GCM 模式** — 提供加密 + 认证（AEAD），是目前最安全的选择
2. **CBC 模式**需配合 HMAC 等机制保证完整性
   CBC 解密的填充校验会扫描完整尾块以减少填充长度相关的耗时差异，但 PHP 运行时不保证严格常数时间；
   不要把未认证 CBC 解密暴露为可区分成功/失败的远程接口。新协议请使用 GCM，兼容协议应先验证 Encrypt-then-MAC 再解密。
3. **ECB 模式不安全**，相同明文产生相同密文，仅用于兼容旧系统
4. CBC/CFB 的 IV 必须在对应明文确定前不可预测；OFB 的 IV 必须唯一；CTR 必须确保同一密钥下所有消息的计数器块不重复。每种模式必须使用不同密钥，包括 CCM 与 GCM；当前进程会拒绝同一密钥跨模式使用，直接分组原语 `Sm4PurePhp::setKey()` 也作为独立 key-use 类别处理。非空解密只检查已有模式登记，不会创建登记，也不会因失败解密污染状态。若解密专用 key 从未在本进程由加密操作登记，且没有用共享 tracker 预登记，库无法从解密请求推断可信模式；调用方必须从可信配置保证该 key 不跨模式复用。绝不能依据未认证 payload 元数据或外部请求动态选择解密模式；应从可信配置指定模式，并使用 `Sm4::decryptPayload($payload, $key, $expectedMode)` 校验 payload 模式。`Sm4StreamBlockTrackerInterface` 协调 CTR 计数器区间，并逐块协调 CFB/OFB 加密实际使用的反馈输入；它不协调 CCM/GCM、CBC、ECB 的分组输入。跨进程部署必须自行遵守密钥分离。该检查不证明 IV 不可预测，CFB 显式 IV 仍必须由调用方保证不可预测。`Sm4Options` 自动生成随机 IV，并在同一实例再次加密时刷新；显式设置 IV 时仍须遵守对应模式的 IV 条件
5. GCM 模式的 IV 绝不能重复使用同一密钥加密不同数据（本库默认检测并拒绝）
6. 显式传入 `Sm4Options` 时，密文不内嵌 IV，调用方必须单独保存并**在解密时通过 `setIv()` 传回同一个 IV**；
   解密时未设置 IV 会直接抛出 `InvalidKeyException`（不会静默生成随机 IV 导致乱码）
7. **侧信道边界**：纯 PHP SM4 回退在密钥扩展和分组运算中通过密钥相关的 S-box 索引访问表。若当前 PHP/OpenSSL 可实际执行原生 `SM4-GCM`，本库会把完整 AEAD 运算交给 OpenSSL；否则 GHASH 在 PHP/GMP 中对密钥派生状态执行条件分支。OpenSSL 的 SM4 实现本身也不保证常数时间。因此，本库任何后端都不应被视为能抵御本地时序或缓存侧信道攻击。高保证场景应使用经审查的常数时间原生实现、HSM 或隔离的密码服务。
8. 安全存储密钥（使用环境变量或安全的密钥管理）
9. 推荐业务封装直接使用 `Sm4::encryptPayload()` / `Sm4::decryptPayload()`：自动生成新 IV、自动携带 IV/tag 元数据，
   从根本上避免 IV 管理错误

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
