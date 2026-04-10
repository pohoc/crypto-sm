# 变更日志

本文件由脚本自动生成，基于 git tag 和 commit 记录。

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
