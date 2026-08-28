# 变更日志

本文件由脚本自动生成，基于 git tag 和 commit 记录。

## [v0.2.3] - 2026-05-28

### 修复
- SM2 密钥交换规范修正、Keypair 私钥脱敏、PEM DER 严格校验
- ASN.1 DER 解析器严格校验，拒绝非规范编码

### 新增
- 新增 SM4 自包含 payload API 与纯 PHP 模式回退，默认 CBC 自携带 IV
- 新增纯 PHP SM4 分组密码引擎，GCM 自适应块加密后端

### 变更
- SM3 流式哈希改用 hash_init/hash_update 增量接口
- 强化 CI 供应链安全，固定 Actions 依赖版本，升级 PHPStan 至 level 9

### 文档
- 同步文档至最新实现，补充纯 PHP 回退与 payload API 说明

## [v0.2.2] - 2026-05-14

### 变更
- 修复 SM2 随机数与点校验安全问题

## [v0.2.1] - 2026-05-14

### 修复
- Pem.php parseDerLength添加边界检查防止越界读取
- 修复11项安全漏洞

## [v0.2.0] - 2026-05-06

### 修复
- phpdocs 对齐格式
- (pem) DER 边界检查 + OID 验证 + 辅助模块改进
- (sm2) 修复 DER 签名自动检测误判 + 签名循环重构 + 密钥确认
- CI 工作流修复 - 支持 PHP 8.0+，Release 依赖 CI 通过
- 修复 PHPStan chr() 类型收窄错误
- 安全修复 - ASN.1边界检查、SM2随机数k范围约束、Hex输入校验等

### 新增
- 新增 SM2 密钥交换/PEM、HMAC-SM3、SM4 CFB/OFB/CTR/GCM 模式

### 变更
- 完善质量体系：补齐兼容性约束、边界测试与性能基线
- 优化发布流程：移除 Release 对 main 的回写
- 修复测试：兼容 PHPUnit 9 的 DataProvider 解析
- 修复 CI：使用兼容 PHPUnit 9/10/11 的调试参数
- 修复 CI：兼容 PHPUnit 9 的测试参数
- 优化工作流：增强 CI 错误输出并精简 Release 流程
- 修复 CI：移除 Gcm 中触发 PHPStan 恒假判断的分支
- 修复 CI：处理 PHPStan chr 字节范围与 PHP 8.1 GMP 布尔转换致命错误
- 移除冗余 ci.yml（php.yml 已是超集）
- 支持 PHP 8.4/8.5 + release 改为 draft
- 添加 CI 工作流 + 测试更新
- (sm4/gcm) reduction table 优化 + warmup 预热 + 实例缓存
- (sm3) 流式哈希 OpenSSL 加速 + 内存优化 + 接口补充
- 工程化配置更新

### 文档
- 更新性能基准 + GCM warmup 文档 + 安全说明
- 更新文档，新增性能基准数据

### 测试
- 移除 ECB deprecation 测试（error_handler 与 PHP 8.2 兼容性问题）
- 补充 KeyExchange/Keypair/Gcm/Sm4/Sm2 等未覆盖测试
- 新增功能测试，迁移至 PHPUnit 11 属性

## [v0.1.1] - 2026-04-10

### 变更
- SM3 OpenSSL 加速 + SM2 窗口法点乘优化 (v0.1.1)

## [v0.1.0] - 2026-04-10

### 新增
- 升级 PHPStan 至 level 8、修复 SM2 d=n-1 边界、迁移 Interface→Interfaces、更新 CI

## [v0.0.3] - 2026-04-09

### 修复
- 修复 SM2 验签 DER 自动检测误判导致偶发验证失败
- 修复 PHPStan 静态分析错误
- 修复安全漏洞与代码质量，增加国密标准测试向量
- 完善 SmCrypto 门面类方法并修正文档中的密钥长度错误
- 替换 metcalfc/changelog-generator 为原生 git 命令生成 changelog

### 新增
- 完善项目工程化与代码质量

## [v0.0.2] - 2026-03-19

### 新增
- 添加自定义异常类、接口定义及代码改进

### 变更
- Fix SM2/SM3/SM4 to GM/T standards and add vectors
- Add SM4 standard test vectors for ECB, CBC, Padding, Key Length, Block Size, and Round Count testing
- Add SM2 standard test vectors for key pair validation, encryption/decryption, and signature tests
- Add SM3 standard vectors test file
- 更新信息
- 更新流程

### 文档
- 新增 gmp 的安装操作

## [v0.0.1] - 2026-03-06

### 新增
- (all) 完成 SM2/SM3/SM4 国密算法实现


[v0.0.1]: https://github.com/pohoc/crypto-sm/releases/tag/v0.0.1
[v0.0.2]: https://github.com/pohoc/crypto-sm/compare/v0.0.1...v0.0.2
[v0.0.3]: https://github.com/pohoc/crypto-sm/compare/v0.0.2...v0.0.3
[v0.1.0]: https://github.com/pohoc/crypto-sm/compare/v0.0.3...v0.1.0
[v0.1.1]: https://github.com/pohoc/crypto-sm/compare/v0.1.0...v0.1.1
[v0.2.0]: https://github.com/pohoc/crypto-sm/compare/v0.1.1...v0.2.0
[v0.2.1]: https://github.com/pohoc/crypto-sm/compare/v0.2.0...v0.2.1
[v0.2.2]: https://github.com/pohoc/crypto-sm/compare/v0.2.1...v0.2.2
[v0.2.3]: https://github.com/pohoc/crypto-sm/compare/v0.2.2...v0.2.3
