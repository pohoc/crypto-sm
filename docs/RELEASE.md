# 发布流程

维护者在 GitHub Actions 手动运行 **Release**，选择 `main` 并输入不带 `v` 的版本号，例如 `0.4.1`。也可使用：

```bash
gh workflow run "Release" --ref main -f version=0.4.1
```

工作流依次校验 SemVer 和 main 提交，核验该提交已有的完整 CI 结果，创建版本 tag，并然后生成变更日志，通过 PR 更新 main，运行 CI 并合并该 PR，最后发布 GitHub Release 和启动 Packagist 安装验收。预发布版本自动标记为 Pre-release。发布说明由版本变更日志生成，并链接该 tag 对应的迁移指南。

## 仓库配置

仓库管理员需要在 **Settings → Actions → General → Workflow permissions** 中允许 GitHub Actions 创建 pull request。`GITHUB_TOKEN` 需要获得 workflow 中声明的 `contents`、`actions` 和 `pull-requests` 权限；main 规则必须允许通过 PR 合并自动生成的 changelog，并允许该 PR 使用手动触发的 CI 检查。若规则要求独立审批或不接受这些检查，自动合并会失败，需要管理员处理，工作流不会绕过规则。

发布 workflow 不再使用需要人工审批的 `release` Environment；启动一次 Release 即授权创建 tag 和发布 Release。tag 保护应继续禁止更新和删除。Packagist 应保持 GitHub 自动同步，workflow 只读取公开数据，不使用 Packagist token。

## 失败恢复

- 创建 tag 前失败：修复原因后重新运行 Release。
- tag 已创建：不要移动或删除 tag。在 Actions 重新运行 **Release**，输入相同版本号；已有 changelog 分支或 PR 会被检查并复用。
- changelog PR 无法创建或合并：检查 Actions 创建 PR 权限、main 规则和 CI 状态，然后重跑 Release。已有分支内容不一致时需人工核对。
- Release 已存在：检查实际状态后处理；工作流不会覆盖已存在的发布说明。已有 Draft 需人工核对后发布或删除。
- Packagist 验收失败：检查同步和安装日志；同步后核实同步后重新检查已发布版本。

`v0.4.0` 包含 PHP 8.2 最低版本、SM2 签名和 SM4 默认格式变化，升级前请阅读[迁移指南](migration.md)。
