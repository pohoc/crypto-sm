# 发布流程

发布采用与 `sa-token` 相同的两阶段流程：**手动启动 → 完整 CI → 创建版本 tag → dispatch Release workflow → changelog PR 人工合并 → 创建 Draft Release → 人工审核并发布 → Packagist/Composer 验收**。

## 一键启动

1. 确认待发布代码已合并到 `main`。
2. 在 GitHub Actions 运行 **Start Release**，运行分支选择 `main`，输入不带 `v` 的严格 SemVer，例如 `0.4.0-rc.1` 或 `0.4.0`。也可以运行：

   ```bash
   gh workflow run "Start Release" --ref main -f version=0.4.0-rc.1
   ```

3. 工作流检查版本格式、前导零、预发布标识和现有版本优先级；记录 `main` SHA 后运行完整 PHP 8.2–8.5、最低/最高依赖矩阵、Composer、静态分析/风格及安全审计。
4. CI 通过后再次确认 `main` SHA 未变化，再创建不可变的 `v*` annotated tag。若 tag push 的响应不确定，工作流会查询远端 tag 指向；仅当 SHA 与测试 SHA 相同才继续，不会覆盖已有 tag。
5. 因为 `GITHUB_TOKEN` 推送的 tag 不会自动触发另一个 `push` workflow，Start Release 会显式发送 `repository_dispatch`。人工推送的 `v*` tag 则由 `push.tags` 触发 Release workflow。

## Release 与人工审核

- Release workflow 确认 tag 位于 `main` 历史中，并要求同一 SHA 上的汇总检查 `full-ci / CI Gate` 成功。Gate 仅在 Composer 验证、全部 PHP 矩阵、质量检查和审计均成功时通过；失败、取消、跳过或缺失都阻止发布。
- 工作流运行 `composer changelog` 更新版本日志，并创建只包含 `CHANGELOG.md` 的 PR；它会对 PR 手动触发 CI，但**不会自动合并**。维护者需检查并合并该 PR，然后在 Actions 用同一 tag 重新运行 **Release**。
- changelog 已进入 `main` 后，工作流创建 GitHub **Draft Release**，包括 Breaking Changes、Migration Guide、Security Fixes、Upgrade Requirements 和提交变更章节。RC/Beta tag 会标为 Pre-release。
- 维护者需在 Draft 中核对 tag、SHA、版本说明与迁移内容，补完章节后手动发布。正式版不会由 workflow 自动公开；发布时应确认是否设为 Latest。预发布版不得设为 Latest。
- 相同 tag 的 Release 已存在时，workflow 检查状态并幂等退出，不会覆盖已有说明或创建第二个 Release。API 状态无法确认时会停止并要求先检查 GitHub 实际状态。

## 失败恢复

- tag 创建前失败：修复原因后重跑 **Start Release**。
- tag 已存在但 Release 尚未创建：用 **Release** workflow 选择 `main` 并输入同一 tag。工作流会验证 tag SHA 和既有 CI Gate，再继续。
- changelog PR 已创建但尚未合并：检查并人工合并该 PR，然后以相同 tag 重跑 **Release**。
- Draft Release 已创建：直接在 GitHub 审核和编辑原 Draft；不要用重跑覆盖人工修改。
- GitHub API 写入结果不确定：先检查 tag/Release 页面。只在远端状态确认后恢复；不要删除或移动现有 tag。
- Packagist 尚未同步：检查 Packagist 的 GitHub 自动更新连接，必要时在 Packagist 页面手动触发 **Update**；同步后用同一个已发布 tag 手动运行 **Post-release verification**。

## Packagist 与安装验收

当前 `pohoc/crypto-sm` 在 Packagist 显示为自动同步包，发布 workflow 不使用 Packagist token，也不调用写入 API。GitHub Release 发布后，**Post-release verification** 会有限重试公开 Packagist 元数据，确认版本的 `dist.reference` 与 tag commit SHA 一致，然后在空白 Composer 项目中安装该精确版本，并再次核对 `composer.lock` 的版本和 SHA。

若 Packagist 仍未出现目标 SHA，验收 workflow 会失败并提示人工同步；不会无限重试或报告成功。Composer 安装失败时，确认 PHP 8.4、GMP、OpenSSL 和 Packagist 同步状态后，用同一 tag 重跑 **Post-release verification**。

## GitHub 仓库手动配置

这些配置需要仓库管理员在 **Settings** 中完成；本地 workflow 不会改写仓库规则。

1. **Protect main**：当前规则只要求 `full-ci / Composer validation`、`full-ci / Static analysis and style`、`full-ci / Composer audit`。在新 Gate 首次成功出现后，将 `full-ci / CI Gate` 加为 Required status check；确认后再考虑移除旧的三个检查。保留旧检查直到 Gate 可选取，避免规则引用不存在的检查。将 Required approving reviews 设为至少 1，尤其是本 PR 包含密码算法实现改动。
2. **Protect release tags**：当前 `v*` tag 规则已有禁止删除、更新及非快进，但还没有 Required status check，且当前用户可绕过。保留现有限制，增加 `full-ci / CI Gate`，并移除日常账号的绕过权限。应先确认该 check 已在 tag 目标 commit 上成功出现，再启用要求，避免阻塞发布。
3. **release Environment**：创建或检查名为 `release` 的 Environment，为发布任务配置至少一名 Required reviewer，并限制允许部署的分支为 `main`。本环境审批覆盖创建 tag 和 Draft Release 两个 workflow job；最终公开仍由维护者手动发布 Draft。
4. **Review**：确认 PR #3 至少有一位独立维护者审阅。当前 main Ruleset 的必需批准数为 0；仓库 API 连接不能读取 branch protection/environment 的全部设置，需在 GitHub UI 验证以上项目。

## 版本建议

当前正式版本为 `v0.3.0`。本次包含 PHP 最低版本提高至 8.2、SM4 默认格式与模式变化、SM2 签名默认语义变化等兼容性影响，建议以 `v0.4.0` 作为稳定版本目标。可先发布 `v0.4.0-rc.1` 做迁移验证，再审核和发布 `v0.4.0`。此处是版本建议，不会自动创建 tag 或 Release。
