# 发布流程

正式发布由两个 GitHub Actions workflow 协作完成：维护者手动启动发布，工作流在 CI 通过后创建版本 tag，再由 Release workflow 生成变更日志并创建 GitHub Release。

## 发布前准备

1. 确认要发布的代码已经合并到 `main`，且 `main` 上的 CI 全部通过。
2. 确认版本号遵循 SemVer，输入时不带 `v`，例如 `0.3.1`。
3. 检查提交标题。`scripts/changelog.php` 根据 tag 之间的提交标题生成变更日志：`feat`、`fix`、`docs`、`test` 等类型会分组；无法识别的提交归入“变更”，`style` 提交会忽略。

## 标准发布

1. 在 GitHub Actions 选择 **Start Release**，运行分支选 `main`，输入版本号，例如 `0.3.1`。也可以用 GitHub CLI 启动：

   ```bash
   gh workflow run "Start Release" --ref main -f version=0.3.1
   ```

2. **Start Release** 校验 `main`、版本号、未完成的发布和重复 tag，然后在记录的 `main` 提交上运行完整 CI。若 CI 期间 `main` 前进，工作流会停止，不会把 tag 指向未经验证的提交。
3. CI 通过后，工作流创建不可变的 annotated tag（例如 `v0.3.1`），并发送 `repository_dispatch` 启动 **Release** workflow。
4. **Release** 验证 tag 指向 `main` 上的提交，并检查 PHP 8.2、8.3、8.4、8.5 的最低/最高依赖测试、Composer 验证、静态分析/风格检查和 Composer audit 均通过。
5. Release 调用 `composer changelog`（即 `php scripts/changelog.php`），根据 tag 和提交记录生成完整的 `CHANGELOG.md`，再从新版本章节提取 GitHub Release notes。
6. 工作流创建 `release/changelog-v0.3.1` 分支和仅更新 `CHANGELOG.md` 的 PR，手动启动该 PR 的 CI。检查通过后工作流自动合并 PR，并在 `main` 确认该版本章节存在后创建 GitHub Release。

如果仓库的 `release` environment 配置了 required reviewers，发布 job 会等待审批。`GITHUB_TOKEN` 推送 tag 不会自动启动另一个 `push` workflow，因此标准流程显式发送 `repository_dispatch`；手动推送 tag 则由 `push.tags: v*` 触发 Release workflow。

## 直接推送 tag

已有 `main` CI 检查通过时，也可以手动创建并推送 tag：

```bash
git tag -a v0.3.1 -m "Release v0.3.1"
git push origin v0.3.1
```

Release workflow 会复核 tag 格式、`main` 祖先关系和 CI 检查；校验不通过时不会创建 GitHub Release。由于 tag 已经创建，修复后应使用 **Release** workflow 手动恢复同一个 tag，不要移动或删除 tag。

## 失败恢复

- **Start Release 在创建 tag 前失败：**修复失败原因后重新运行 **Start Release**。只有远端尚无该版本 tag 时才能重新开始。
- **tag 已创建，但 Release workflow 没启动或中途失败：**在 Actions 手动运行 **Release**，运行分支选 `main`，输入已有 tag（如 `v0.3.1`）。不要再次创建 tag。
- **变更日志 PR 已存在：**修复或等待同一个 PR；重新运行 Release 时会检查 PR 内容是否与该 tag 生成结果一致，并再次执行 CI。
- **变更日志 PR 已合并，但 GitHub Release 创建失败：**用同一 tag 重新运行 **Release**。工作流会识别 `main` 中已有的版本章节，然后继续发布。
- **工作流等待环境审批：**在 GitHub Actions 对当前发布运行完成审批，不要并行启动另一个版本发布。
- **tag 或发布说明有误：**不要重写或删除已发布 tag；准备修正版版本号并走一次新发布。

## 标签保护（一次性配置）

仓库提供 `scripts/setup-tag-protection.sh`，为 `v*` tag 配置 ruleset：要求上述 CI 检查成功，并禁止删除或更新 tag。需要仓库管理员 token；先确保 CI 已经运行过，以便 GitHub 已识别这些检查名称，然后执行：

```bash
GH_TOKEN=YOUR_REPOSITORY_ADMIN_TOKEN bash scripts/setup-tag-protection.sh
```

脚本会创建或更新名为 `release-tags-require-ci` 的规则。规则在 GitHub 仓库级生效；该配置不是 workflow 自动完成的，执行后应到 **Settings → Rules → Rulesets** 确认规则状态和目标为 `v*` 的 tag。

## 发布范围

本仓库的 Release workflow 创建 GitHub Release，不直接调用 Packagist 发布 API。若 Packagist 已配置从 GitHub 自动同步，请在发布后确认新版本已同步；标签本身不会替代 Packagist 侧的同步配置。
