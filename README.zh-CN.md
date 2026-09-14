# ShareSafe

**文件离开本机之前的本地、离线隐私门。**

ShareSafe 会在分享文件、目录或发布包之前，检查可能的泄露风险和覆盖缺口。它不只看正文：文件名可能暴露身份，源码可能带着密钥，文档属性可能留下作者信息，Office 包或嵌套压缩包里还可能藏有批注、修订、备注与其他材料。CLI 会生成证据已遮罩的机器可读报告；配套 Codex Skill 则让代理始终按同一套谨慎流程操作。

> [!IMPORTANT]
> `no_findings` 只表示“已经完成的检查没有命中规则”，**不等于**“安全、匿名、合规或获准发布”。遇到不支持、加密、损坏、解析失败或资源限制的内容时，覆盖状态必须是 `incomplete`。

ShareSafe 目前是 alpha 软件。分享敏感内容前，请同时审阅报告、覆盖缺口和文件本身。

[English](README.md) · [格式支持矩阵](SUPPORT_MATRIX.md) · [威胁模型](THREAT_MODEL.md) · [架构](docs/architecture.md) · [调研](docs/research.md)

## v0.1 解决什么问题

- 分享前审计文本、代码、配置、OOXML（`.docx`、`.xlsx`、`.pptx`）、ZIP、PDF、JPEG 和 PNG。
- 查找疑似个人信息、凭据、带身份信息的用户主目录/UNC 路径、身份元数据以及部分隐藏文档结构。
- 将所选根目录和空目录纳入清单，扫描容器名称/评论，并在防御性资源上限内递归检查嵌套 ZIP。
- 在发现结果产生的边界就遮罩敏感值，避免报告再次泄密。
- 仅对少数高置信元数据变换创建**新副本**。
- 立即重新扫描输出，并保留残余发现或覆盖不完整状态。
- 为脚本、CI 和代理工作流提供稳定 JSON 与明确退出码。

ShareSafe 不是完整的文档脱敏器。v0.1 的 `sanitize` 不改写正文，不做视觉涂黑，不运行 OCR，也不会自动删除 Office 批注、修订、演讲者备注或隐藏工作表，更不会保证所有身份线索都已消失。需要修改正文时，应使用专业脱敏工具并进行人工复核。

## 一分钟理解结果

| 结果 | 含义 | 发布动作 |
|---|---|---|
| `no_findings` | 已完成的检查未发现规则命中。 | 仍需核对范围并人工检查文件。 |
| `review` | 存在需要人工判断的发现。 | 分享前逐项审阅。 |
| `block` | 高风险发现达到配置阈值。 | 不要按原样分享。 |
| `incomplete` | 至少一项相关检查无法完成。 | 视为尚未放行；先解决缺口或换工具复核。 |

覆盖状态按每个工件分别记录。`incomplete` 优先于普通发现，因为“看起来干净但其实只检查了一部分”比明确告警更危险。

## 安装

ShareSafe 需要 Python 3.11 或更高版本。核心扫描器没有运行时依赖；完整安装会增加可选的 PDF 和图片适配器。

```bash
git clone https://github.com/motanwenzhu/sharesafe.git
cd sharesafe
```

请直接使用虚拟环境中的解释器完成创建和安装，不依赖 shell 是否已激活：

```bash
# macOS / Linux
python3 -m venv .venv
./.venv/bin/python -m pip install ".[full]"
```

```powershell
# Windows PowerShell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[full]"
```

激活虚拟环境后可直接调用 `sharesafe`。不激活时，请用上面对应平台的虚拟环境 Python 路径加 `-m sharesafe`；下文示例默认已经激活。

只安装零依赖核心：

```bash
# macOS / Linux
./.venv/bin/python -m pip install .
```

```powershell
# Windows PowerShell
.\.venv\Scripts\python.exe -m pip install .
```

缺少可选能力时，`doctor` 会明确报告；如果它影响当前输入，就会形成覆盖缺口，而不是被悄悄算作扫描成功。

## 快速开始

先查看当前机器上的真实能力：

```bash
sharesafe doctor --json
sharesafe formats --json
sharesafe rules --json
```

只读扫描文件或目录：

```bash
sharesafe scan ./bundle --json --report ./sharesafe-report.json
```

生成独立的净化副本并自动复扫：

```bash
sharesafe sanitize ./bundle --out ./bundle.sanitized --json --report ./sharesafe-sanitize-report.json
```

比较原始输入和拟发布副本：

```bash
sharesafe verify ./bundle ./bundle.sanitized --json --report ./sharesafe-verify-report.json
```

`sanitize` 已经返回带可信变换记录的前后验证。独立 `verify` 用于保守比较另行处理的副本；它没有可认证的变换清单，因此只要字节发生变化，即使发现数减少，也仍会标记为 `unverified`。

运行内置合成数据自检：

```bash
sharesafe self-test --json
```

执行 `sharesafe COMMAND --help` 可查看当前参数，包括 `--fail-on` 接受的扫描阈值。

## CLI 契约

```text
sharesafe scan PATH [PATH ...] [--json] [--report FILE] [--fail-on LEVEL]
sharesafe sanitize PATH --out NEW_PATH [--json] [--report FILE]
sharesafe verify ORIGINAL PREPARED [--json] [--report FILE]
sharesafe doctor [--json]
sharesafe rules [--json]
sharesafe formats [--json]
sharesafe self-test [--json]
```

扫描类 JSON 使用 `sharesafe.report/v1`，包含 `tool`、`run`、`summary`、`artifacts`、`findings`、`gaps`、`errors` 和 `dependencies`。展示路径使用相对路径；报告不得包含扫描根目录的绝对路径、裸文件摘要或未遮罩证据。字节身份只用本次运行临时 HMAC 生成的内容令牌表示，让成对扫描可比较字节，又不会发布可离线枚举的 SHA-256。发现 ID 必须唯一且可重复生成，但不能对敏感值本身做哈希后当作标识。

`sanitize` 和 `verify` 包装结果还包含 `verification.integrity`。工件被删除/新增、媒体类型改变、内容令牌或大小变化无法解释，或变换状态为 skipped/partial/unsupported 时，验证都会是 `incomplete`；发现数量减少本身绝不等于变换有效。

退出码适合自动化：

| 退出码 | 含义 |
|---:|---|
| `0` | 操作完成，且没有发现达到配置阈值。 |
| `1` | 至少一项发现达到阈值，或验证未通过。 |
| `2` | 覆盖不完整。 |
| `3` | 参数无效，或请求的操作不安全。 |
| `4` | 文件系统或未预期的内部错误；未产生安全结论。 |

不要让自动化只凭退出码 `0` 就直接发布。还应确认报告 schema、结论、覆盖状态以及本次发布所需的人工策略。

## 净化边界

`sanitize` 刻意比 `scan` 窄：

- 必须写入新的目标位置，并拒绝不安全的覆盖关系。
- 原始输入保持不变。
- 只可能从受支持的 OOXML、JPEG 和 PNG 副本中移除高置信元数据。v0.1 对 PDF 只做审计；PDF 可能被原样复制进输出目录，但 ShareSafe 会把它的元数据变换标为不支持，不会称其已经净化。
- 不会悄悄改正文，也不会代替人做披露决策。
- 输出会立即复扫，残余发现和覆盖缺口仍会显示。
- 在平台允许时，输出的访问时间和修改时间会被设为固定值；ShareSafe 不保证归一化 Windows 创建时间（birth time）。在有相应语义的平台上，普通文件权限只保留“可执行/不可执行”类别；精确 mode、所有者、ACL、扩展属性、备用数据流及其他平台元数据不会被照搬或净化。新输出按操作系统规则从目标父目录获得或继承安全属性。

“文件成功生成”不等于“验证成功”。各格式的精确边界见 [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md)。

## 作为 Codex Skill 使用

仓库在 `skills/sharesafe` 中提供一个轻量配套 Skill。它会指导 Codex 先检查能力、默认执行只读扫描、保护遮罩后的证据、把所有变换写入独立路径，并避免把部分结果说成“安全”。确定性的检测和报告生成由 Skill 内置的 Python 实现完成。

这个 Skill 可以独立运行：`scripts/run_sharesafe.py` 会加载同一目录内自带的实现。只有在希望从 shell 全局调用 `sharesafe` 命令时，才需要另行安装 wheel。

仓库公开后，推荐在 Codex 中调用 `$skill-installer`，并让它安装：

```text
https://github.com/motanwenzhu/sharesafe/tree/main/skills/sharesafe
```

若已经克隆仓库，也可以把目录手工复制到官方当前定义的用户级位置：

```bash
# macOS / Linux
mkdir -p "$HOME/.agents/skills"
cp -R skills/sharesafe "$HOME/.agents/skills/sharesafe"
```

```powershell
# Windows PowerShell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
Copy-Item -Recurse -Force ".\skills\sharesafe" "$env:USERPROFILE\.agents\skills\sharesafe"
```

Codex 通常会自动发现新 Skill；只有未出现时才需重启。随后可以这样提问：“用 ShareSafe 审计这个待发布目录，并解释每一个覆盖缺口。”最新发现与安装方式见 [OpenAI 官方 Build skills 文档](https://learn.chatgpt.com/docs/build-skills)。

## 隐私与安全属性

- 正常扫描和净化按无网络访问的本地运行方式设计。
- 适配器接收不可变字节和仅用于展示的虚拟路径，不执行嵌入内容。
- 报告在序列化之前遮罩证据，并避免写入源文件绝对路径。
- 在创建大量 ZIP 条目对象之前，先预检普通/ZIP64 中央目录；随后继续限制条目数、解压字节量、压缩比和嵌套深度。
- 发现结果、PNG 块/解压文本和压缩包评论文本都有明确上限；截断或结构损坏会得到 `incomplete`。
- CLI 失败响应只使用稳定且不含路径的消息，避免诊断信息成为二次泄露。
- 解析器失败会变成明确缺口，而不会只消失在日志里。
- 净化不承诺安全擦除原件、临时文件、备份或文件系统历史。

使用真实敏感材料前请阅读 [SECURITY.md](SECURITY.md)；在高风险流程中依赖 ShareSafe 前请阅读 [THREAT_MODEL.md](THREAT_MODEL.md)。

## 开发

测试只允许使用合成工件。禁止提交真实个人数据、凭据、私人文档或由它们生成的报告。

```bash
python -m pip install -e ".[full,dev]"
python -m pytest
sharesafe self-test --json
python -m build
```

行为变更必须保持 `docs/design-contract.md` 的契约，或显式提升相应 schema/语义版本。适配器、遮罩、fixture 和发布要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 项目状态与非目标

v0.1 的目标是可靠的“分享前审计层”，不是大而全的自动脱敏。近期工作应优先提升经过测试的覆盖范围、规则精度、报告稳定性，以及与成熟专业工具的协作能力，而不是把 `no_findings` 包装成认证。

ShareSafe 不提供法律意见、恶意软件扫描、取证级匿名保证、隐写检测、安全擦除或合规认证。它输出的是发布决策所需的证据，不是决策本身。

## 许可证与链接

采用 [Apache-2.0](LICENSE) 许可证。

- 仓库：https://github.com/motanwenzhu/sharesafe
- 问题反馈：https://github.com/motanwenzhu/sharesafe/issues
- 安全报告：https://github.com/motanwenzhu/sharesafe/security/advisories/new
