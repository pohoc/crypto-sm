# 变更日志

## [v0.1.1] - 2026-04-10

### 性能优化
- SM3: 优先使用 `openssl_digest('sm3')` C 原生实现，性能提升 100-300 倍
- SM3: 纯 PHP 回退路径内联优化，性能提升 20-30%
- SM2: pointMultiply 改用 4-bit 窗口法，减少点加次数约 50%
- SM2: 基点预计算表，避免签名时重复计算 i*G
- SM2: 新增 pointMultiplyInternal 返回 GMP 对象，消除 str↔GMP 反复转换
- SM2: 缓存 gmp_init(2)/gmp_init(3) 常量，避免循环内重复创建

### 修复
- 修复 phpstan level 8 静态分析错误
- 修复 PHP-CS-Fixer 代码风格问题

### 新增
- SM3: OpenSSL 与纯 PHP 路径一致性测试、纯 PHP 标准向量测试
- SM2: 窗口法点乘一致性、签名验签、hash 模式、加解密往返验证测试
- scripts/benchmark.php 性能基准测试脚本

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
