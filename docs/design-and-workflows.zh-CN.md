# ShareSafe v0.3 设计方案与各部分流程

本文解释 ShareSafe 从扫描/窄净化底座升级到 v0.2“可信内核与可复现决策”，再到 v0.3“可验证分享包构建器”的设计目标、组件职责、信任边界、数据模型和端到端流程。全文以 v0.3 实现、CLI、schema 和合成测试为准。本文是中文导览，不替代规范性文件：实现发生变化时，应优先以 [设计契约](design-contract.md)、[架构基线](architecture.md)、[支持矩阵](../SUPPORT_MATRIX.md)、[威胁模型](../THREAT_MODEL.md)、版本化 JSON schema 和对应 [GitHub Release](https://github.com/motanwenzhu/sharesafe/releases) 为准。

## 目录

1. [问题与设计目标](#1-问题与设计目标)
2. [核心原则和不可破坏的不变量](#2-核心原则和不可破坏的不变量)
3. [总体架构](#3-总体架构)
4. [代码与文档组件职责](#4-代码与文档组件职责)
5. [核心数据模型](#5-核心数据模型)
6. [扫描流程](#6-扫描流程)
7. [格式适配器流程](#7-格式适配器流程)
8. [检测、遮罩与报告流程](#8-检测遮罩与报告流程)
9. [结论和退出码流程](#9-结论和退出码流程)
10. [净化流程](#10-净化流程)
11. [验证流程](#11-验证流程)
12. [Codex Skill 流程](#12-codex-skill-流程)
13. [路径、文件系统与提交安全](#13-路径文件系统与提交安全)
14. [资源限制和恶意输入防护](#14-资源限制和恶意输入防护)
15. [JSON schema 和自动化边界](#15-json-schema-和自动化边界)
16. [测试体系](#16-测试体系)
17. [CI、打包与发布前门禁](#17-ci打包与发布前门禁)
18. [扩展和变更流程](#18-扩展和变更流程)
19. [主要设计取舍](#19-主要设计取舍)
20. [规范来源与维护规则](#20-规范来源与维护规则)
21. [v0.2 快照绑定、safe I/O 与格式不变量](#21-v02-快照绑定safe-io-与格式不变量)
22. [v0.2 policy/check、deep doctor 与精确 rules](#22-v02-policycheckdeep-doctor-与精确-rules)
23. [v0.2 报告预算、卫生与结构差异](#23-v02-报告预算卫生与结构差异)
24. [v0.3 prepare 数据模型与完整流程](#24-v03-prepare-数据模型与完整流程)
25. [数据分级、威胁边界与故障恢复](#25-数据分级威胁边界与故障恢复)

## 1. 问题与设计目标

### 1.1 要解决的问题

文件在离开本机之前，泄露风险不只存在于正文：

- 文件名和目录名可能包含姓名、邮箱、电话或本机用户名；
- 源码和配置可能包含凭据、私钥或服务 token；
- Office、PDF 和图片可能保留作者、公司、软件、设备、GPS、时间和修订信息；
- 批注、修订、演讲者备注、隐藏工作表/幻灯片和嵌入对象可能不在普通阅读视图中；
- ZIP、wheel 等容器可能嵌套其他文件、评论、危险路径或极端压缩内容；
- 扫描器自身的报告、错误信息和文件摘要也可能形成二次泄露；
- 自动化可能只看退出码 `0`，忽略其实未完成的检查。

ShareSafe 被设计为放在“可信本地边界”与“上传、发送、发布”之间的证据门。它要回答三个问题：

1. 检测到了哪些可能的披露风险？
2. 哪些相关表示没有被完整检查？
3. 如果创建了新副本，实际改变了什么，输出又被检查到了什么？

它不回答“是否依法可以发布”，也不生成绝对无风险证明。

### 1.2 v0.2 的目标

- 本地、离线、确定性地检查支持的文件表示。
- 让覆盖缺口和发现一样成为一等数据。
- 在发现产生的边界立刻遮罩证据。
- 默认只读；任何变换都写入新路径并保留原件。
- 净化能力窄于检测能力，只做允许列表内的高置信元数据变换。
- 变换后立即复扫，并通过工件完整性比较防止“删除内容后发现变少”的假改进。
- 将前扫、变换输入、预期输出和后扫四个精确字节快照绑定到同进程受信 receipt。
- 把输出名称、字段、gap/error 和总报告纳入可观察资源预算，超限仍失败闭合。
- 用 `sharesafe.check/v1` 记录 effective policy、ruleset version、policy digest、技术结论和实际退出决策。
- 用 `doctor --deep` 执行离线合成能力 probe，用 `rules --detail` 暴露可版本化 exact catalog。
- 提供稳定、可版本化的 JSON 和明确退出码。
- 让 Codex Skill 只负责编排和解释，不把隐私判断变成模型自由发挥。

### 1.3 v0.3 的目标

- 不改动原边界，从它构建一个全新、准确的分享边界。
- 为 source inventory 的每一项分配且只分配一个 copy/omit/rename/strip/manual/block 动作。
- 把“检测建议”、“人的批准”和“实际执行”分成 plan/inspect/approve/apply 信任边界。
- 在 apply 前发现 source/plan/approval 漂移，在 apply 后精确验证动作关系并复扫最终输出。
- 将敏感本地控制工件与可审阅的遮罩摘要分离。

### 1.4 明确非目标

- 恶意软件检测或主动内容安全执行；
- OCR、视觉/音频/视频语义分析；
- 完整正文或像素级不可逆脱敏；
- 合规认证、法律意见或组织审批替代；
- PDF 改写、所有格式解析或任意归档重建；
- 安全擦除、文件系统取证匿名化或对操作系统/备份服务的防护。

## 2. 核心原则和不可破坏的不变量

| 原则 | 不变量 |
|---|---|
| 本地优先 | 正常扫描、报告、净化和验证不需要网络；适配器不获取外部关系 |
| 默认只读 | `scan`、`verify` 不修改输入；`sanitize` 只创建不同且不存在的输出 |
| 覆盖诚实 | 不支持、加密、损坏、解析失败、依赖缺失和资源耗尽必须成为 gap |
| 失败关闭 | 相关 gap、error 或 partial 工件使总体结论为 `incomplete`，退出码优先为 `2` |
| 证据先遮罩 | 裸 PII、凭据、用户名、主机名、绝对根路径和元数据值不能进入公共报告 |
| 内容不执行 | 不运行宏、脚本、公式、外链或嵌入对象，不把归档成员当作可执行路径 |
| 变换有允许列表 | 只允许受审查的 OOXML/PNG/JPEG 元数据变换，其他内容复制或明确拒绝 |
| 输出必复扫 | 创建副本不等于验证成功；`sanitize` 必须包含 after scan 和完整性比较 |
| 版本化契约 | 破坏 JSON 字段或语义必须提升 schema 或作显式版本决策 |
| 范围不扩张 | 扫描一个路径不授权扫描兄弟目录、安装依赖、创建副本或上传结果 |

## 3. 总体架构

ShareSafe 分成“交互编排层”和“确定性执行层”。

```mermaid
flowchart LR
    U[用户 / CI] --> E{入口}
    C[Codex 用户] --> S[ShareSafe Skill]
    S --> W[run_sharesafe.py]
    E -->|sharesafe 或 python -m sharesafe| CLI[cli.py]
    W --> CLI

    CLI --> P[参数与路径预检]
    P --> SC[Scanner / engine.py]
    SC --> D[safe_io.py<br/>先安全打开再核对句柄身份]
    D --> SN[sniff.py 类型识别]
    SN --> A[格式适配器]
    A --> DET[detectors.py]
    DET --> RED[redaction.py 立即遮罩]
    RED --> RB[ReportBuilder / models.py]
    A --> RB
    RB --> RH[report_hygiene.py<br/>输出前机械门禁]
    RH --> OUT[版本化 JSON + 退出码]

    CLI --> POL[policy.py]
    POL --> CHK[check.py<br/>check/v1 决策 wrapper]
    SC --> CHK
    CHK --> RH

    CLI --> SAN[sanitize.py 新副本流水线]
    SAN --> SC
    SAN --> REC[receipts.py<br/>四快照 + preserved facets]
    REC --> VER[verify.py 完整性比较]
    VER --> OUT

    CLI --> PREP[prepare<br/>plan / inspect / approve / apply / verify]
    PREP --> REC
    PREP --> SC
```

### 3.1 两层的边界

**Skill 层负责：**

- 判断何时使用 ShareSafe；
- 保留用户授权范围；
- 先检查能力，再选择 scan/sanitize/verify 或完整 prepare 流程；
- 解释遮罩发现、gap 和退出码；
- 避免把结果扩大为发布许可。

**Python 层负责：**

- 路径安全、稳定读取、类型判断和资源计数；
- 格式解析、规则检测和证据遮罩；
- 报告 schema、ID、HMAC 内容令牌、结论和退出码；
- staging、允许列表变换、无覆盖提交和前后验证。

这样设计是为了让隐私关键逻辑可单元测试、可跨平台复现，而不是依赖每次对话的表述。

## 4. 代码与文档组件职责

### 4.1 入口和编排

| 路径 | 职责 | 关键边界 |
|---|---|---|
| `skills/sharesafe/SKILL.md` | Skill 的触发范围、必需流程和授权规则 | 保持简短；不复制检测逻辑 |
| `skills/sharesafe/agents/openai.yaml` | UI 名称、简介、默认提示和隐式调用策略 | 必须与 SKILL 描述一致 |
| `scripts/run_sharesafe.py` | 从 Skill 目录启动内置 Python 包 | 不依赖全局安装的同名包 |
| `sharesafe/__main__.py` | `python -m sharesafe` 入口 | 交给 CLI 统一处理 |
| `sharesafe/cli.py` | 参数、报告目标预检、输出格式、退出码和稳定错误包络 | JSON stdout 可解析；异常路径不外泄 |

### 4.2 扫描核心

| 模块 | 职责 | 关键不变量 |
|---|---|---|
| `engine.py` | 路径发现、目录遍历、稳定读取、工件清单、类型分派 | 不跟随链接；绝对根不进报告 |
| `safe_io.py` | 读取任何字节前比较 discovery stat 与已打开 descriptor 身份，读后复核 | POSIX 可用时使用 `O_NOFOLLOW`；不可证明的父目录锚定必须由 capability 显式声明 |
| `path_safety.py` | 路径包含关系和 Windows ADS 判断 | 输入、输出和报告关系失败关闭 |
| `limits.py` | 输入、容器、文本、名称、finding/gap/error 和总报告共享预算 | 达到限制产生 gap，不静默截断；为控制状态预留空间 |
| `sniff.py` | 根据字节签名和受限结构判断媒体类型 | 扩展名只作辅助；错配产生发现 |
| `catalog.py` | `rules` 与 `formats` 的稳定公开目录 | 文档和 CLI 能发现能力边界 |
| `detectors.py` | 确定性规则、校验器和结构化命中 | 不负责序列化裸证据 |
| `redaction.py` | 遮罩、展示路径处理、临时 HMAC 令牌 | 报告不可包含裸匹配或原始摘要 |
| `models.py` | Artifact/Finding/Gap、汇总、结论和退出码 | `incomplete` 优先；ID 不基于敏感值 |
| `reporting.py` | JSON/人类摘要及报告文件原子写入 | 报告只创建不覆盖 |
| `report_hygiene.py` | 对所有公共输出做 schema、evidence、路径、字段和总大小检查 | 不重新打开原文补充证据；不放行底层 exception 原文 |
| `capabilities.py` | 默认 discovery、deep 合成 parser probe 和平台文件系统安全能力 | 不安装依赖、不联网、不读用户工件 |
| `policy.py` | 严格加载、合并、归一化有效策略并生成 digest | 不关 detector、不改 severity、不删 finding、不压 incomplete |
| `check.py` | 将原生 report、effective policy、ruleset 和决策组成 `check/v1` | 不修改嵌套 `report/v1` 或将 technical verdict 重写为策略结论 |

### 4.3 格式适配器

| 模块 | 输入表示 | 主要职责 |
|---|---|---|
| `adapters/text.py` | 解码后的受限文本 | 调用检测规则并记录文本覆盖 |
| `adapters/archive.py` | ZIP 结构和成员字节 | 成员清单、评论、路径风险和受限递归 |
| `zip_safety.py` | ZIP/ZIP64 中央目录字节 | 在创建大量 `ZipInfo` 前预检条目数和结构 |
| `adapters/ooxml.py` | OOXML ZIP/XML 包 | 属性、关系、正文 XML、隐藏/活动结构信号 |
| `ooxml_xml.py` | XML 字节 | 拒绝 DTD/entity，提供确定性结构检查 |
| `adapters/pdf.py` | PDF 字节 | 内置结构/元数据检查和可选 `pypdf` 文本检查 |
| `adapters/image.py` | PNG/JPEG/TIFF/WebP 字节 | 受限块/段/标签检查和可选 Pillow 能力 |

### 4.4 写入和比较

| 模块 | 职责 | 关键不变量 |
|---|---|---|
| `sanitize.py` | 源预检、staging、允许列表变换、独占提交、元数据归一化 | 不覆盖、不改原件、不扩大变换范围 |
| `receipts.py` | 由核心在同进程签发 transform receipt，绑定四快照和格式级 facets | 不信任普通 list/dict 或从外部 JSON 重建的 applied action |
| `verify.py` | 比较前后工件、内容令牌、发现多重集与受信 receipt | 无可信 receipt 时，任何字节变化均为 unverified |
| `prepare_decisions.py` | 严格读取本地 decisions JSON | 未知字段、重复 key、BOM、非有限数和非法 Unicode 失败关闭 |
| `prepare_plan.py` | 完整 inventory、portable path/action 契约、source binding、plan/approval digest | 每个源文件恰好一个动作；空/歧义/冲突计划拒绝 |
| `prepare_io.py` | 本地控制读写与私有临时目录 | 控制文件 owner-only、exclusive publish；staging 权限不可证明则失败 |
| `prepare.py` | source drift、allowlist apply、exclusive commit、精确关系和最终复扫 | 不覆盖、不隐式复制、Scanner 读取绑定、报告预算失败闭合 |

### 4.5 契约和验证材料

| 路径 | 用途 |
|---|---|
| `schemas/*.schema.json` | 扫描、净化和验证的 v1 机器契约 |
| `SUPPORT_MATRIX.md` | 格式和变换的规范性支持边界 |
| `THREAT_MODEL.md` | 资产、信任边界、威胁、缓解和残余风险 |
| `docs/design-contract.md` | 不得无版本决策漂移的行为契约 |
| `tests/` | 只使用合成数据的单元、对抗、集成和回归测试 |
| `.github/workflows/` | 跨平台测试、打包校验和标签发布 |

## 5. 核心数据模型

### 5.1 Artifact

每个被发现的文件、目录、空目录、归档成员或虚拟容器项都可以成为工件。主要字段包括：

- `id`：由非敏感路径身份、媒体类型和出现次序生成的稳定 ID；
- `path`：去除绝对扫描根并经过身份路径遮罩的展示路径；
- `content_token`：本次运行密钥下的 HMAC 字节令牌；目录或未读取项可以为空；
- `size`：已读取工件的字节数；
- `media_type`：按内容识别的媒体类型；
- `status`：`scanned` 或 `partial`；
- `coverage`：`text`、`metadata`、`hidden_content`、`embedded_objects`、`ocr` 的独立状态。

内容令牌不是公开 SHA-256。它使用只存在内存中的临时密钥，因此同一对比运行可以判断字节是否相同，报告持有者却不能用候选文件摘要离线枚举内容。

### 5.2 Finding

Finding 表示已经检测到的风险信号：

- 关联 `artifact_id`；
- 使用稳定 `rule_id`、类别、严重性和置信度；
- 位置是结构化偏移、部件或文件名位置；
- `evidence` 在进入报告对象前已经遮罩；
- `remediation` 只描述是否支持自动处理和建议动作。

Finding ID 由工件身份、规则、结构位置和出现次数生成，不对裸敏感值或原始文件字节做普通哈希。

### 5.3 Gap

Gap 不是低优先级 warning，而是“某项相关能力没有完成”的正式记录：

- `capability` 表明受影响的检查；
- `reason` 提供稳定机器原因；
- `detail` 使用不泄露路径/内容的说明；
- 可以关联单个工件，也可以作用于整个扫描。

一旦出现 gap，工件会被标记为 partial/unsupported，总体结论进入 `incomplete`。

### 5.4 ReportBuilder

`ReportBuilder` 是唯一受支持的扫描报告构建器，负责：

- 确定性添加工件和发现；
- 在单工件或全局发现上限处创建 gap；
- 去重相同 gap；
- 统计严重性和工件状态；
- 计算固定优先级结论；
- 根据用户阈值计算退出码；
- 生成 `sharesafe.report/v1`。

## 6. 扫描流程

```mermaid
flowchart TD
    A[CLI 解析参数] --> B[预检新的 report 路径]
    B --> C[为本次运行生成临时 HMAC 密钥]
    C --> D[逐个解析用户指定路径]
    D --> E{路径类型}
    E -- 链接或 reparse point --> F[记录高风险 finding + content gap]
    E -- 目录 --> G[记录根目录并确定性遍历]
    E -- 普通文件 --> H[读取前 stat]
    E -- 特殊对象 --> I[记录 special_file gap]
    G --> J{VCS 目录/空目录/普通条目}
    J -- VCS --> K[记录历史风险且不遍历]
    J -- 空目录 --> L[加入工件清单并扫描名称]
    J -- 普通文件 --> H
    H --> M[以二进制方式受限读取]
    M --> N[读取后 stat 并检查竞态]
    N --> O[按字节嗅探媒体类型]
    O --> P[扫描文件名并检查扩展错配]
    P --> Q[分派格式适配器]
    Q --> R[规则命中在边界遮罩]
    Q --> S[记录每项覆盖和 gap]
    R --> T[ReportBuilder 汇总]
    S --> T
    T --> U[生成 versioned JSON]
    U --> V[按 gap 优先和 fail-on 计算退出码]
```

### 6.1 参数和报告目标预检

`cli.py` 在扫描前确认 `--report`：

- 不使用 Windows alternate data stream 语法；
- 不覆盖现有文件或符号链接；
- 不在被扫描目录内部；
- 不与扫描文件发生同路径或包含冲突。

预检失败使用稳定 `sharesafe.error/v1` 包络并退出 `3`，不会把底层异常路径复制到输出。

### 6.2 发现与目录边界

`Scanner.scan()` 把命令行路径转为绝对路径仅用于本地访问，但报告只保留相对展示标签。目录项在平台允许时按不区分大小写的排序稳定遍历。

关键处理包括：

- 选中的根目录本身进入清单；
- 空目录进入清单，便于验证时发现删除；
- 如果根目录是系统用户容器下的个人目录，展示名替换为 `<user>`；
- `.git`、`.hg`、`.svn` 不被递归读取，而是产生高风险历史信号和 gap；
- 符号链接、reparse point 和特殊文件不跟随；
- 多输入各自保留独立根标签。

### 6.3 稳定读取

普通文件读取过程使用统一 safe-I/O 层，关键顺序是：

1. 发现阶段记录预期对象身份；
2. 在 POSIX 可用时使用 `O_NOFOLLOW` 打开最终路径分量；
3. 在读取任何字节前，比较 discovery stat 与已打开 descriptor 的 `fstat` 身份；
4. 读取后复核已打开对象和当前路径指向是否仍一致。

设备/inode 或平台等价身份、大小、修改时间发生变化时，即使已有字节被检查，也会增加 `file_changed_during_scan` 类 gap。Windows 不把语义不同的 `st_ctime_ns` 当成 POSIX inode-change-time 比较。读失败、过大或总预算耗尽同样不会被表示为完整。

这一层防止“预检的是 A，真正读的却是后来替换的 B”。它并不等于完整的父目录句柄锚定；当前平台差异由 `doctor --deep` 的 `filesystem_safety` 明示声明。

### 6.4 类型识别与分派

`sniff.py` 先看内容签名和结构，再把扩展名作为辅助信息。这样：

- 改名 ZIP 仍进入归档解析器；
- `invoice.pdf.exe` 一类错配会产生 `SS-GEN-TYPE-MISMATCH`；
- 未知二进制不会被当作普通文本“成功扫描”；
- OOXML 需要同时满足 ZIP/包结构和扩展条件。

## 7. 格式适配器流程

所有适配器接收已经读入的不可变 `bytes`、展示用虚拟路径、Limits、当前递归深度和 ReportBuilder。适配器不得重新打开任意文件、写入磁盘、访问网络或执行内容。

### 7.1 文本

```text
bytes -> 有界解码 -> 可搜索文本 -> deterministic rules
      -> masked finding + text coverage
```

编码无法可靠解释或超出文本预算时，相关文本覆盖变为 partial，而不是返回空结果。

### 7.2 ZIP 和嵌套归档

```mermaid
flowchart TD
    A[ZIP bytes] --> B[手工定位 EOCD / ZIP64 记录]
    B --> C{中央目录结构和条目数可接受}
    C -- 否 --> D[记录 malformed 或 entry_limit gap]
    C -- 是 --> E[才允许 zipfile 构建成员对象]
    E --> F[检查成员路径、加密、方法、大小、比例、重复和链接]
    F --> G[扫描归档/成员评论]
    G --> H[把成员名作为虚拟标签加入清单]
    H --> I{成员受支持且预算足够}
    I -- 是 --> J[受限读取 bytes 并重新进入 sniff/adapter]
    I -- 否 --> K[保留工件并记录 gap]
```

成员从不被提取到其自带路径。虚拟展示路径使用 `container!/member` 形式；全局展开字节预算跨嵌套层级共享。

### 7.3 OOXML

OOXML 适配器把 Word、Excel、PowerPoint 看作受约束的 ZIP/XML 包：

1. 执行 ZIP 预检和成员安全检查；
2. 验证关键包部件和媒体类型；
3. 遍历有界 XML/relationship 部件；
4. 拒绝 DTD/entity，损坏 XML 产生 gap，并对可用原始文本执行受限回退检查；
5. 检查 core/app/custom properties；
6. 检查正文 XML、共享字符串和非 XML 部件名；
7. 识别批注、修订、备注、隐藏表/幻灯片、外链、宏、签名、custom XML、ActiveX 和嵌入对象信号；
8. 对无法解释的嵌入二进制只报告存在，不执行或改写。

“能检测到”不等于“能自动移除”。这一分离是 ShareSafe 最重要的能力边界之一。

### 7.4 PDF

PDF 适配器有两层：

- 内置字节级元数据和结构 token 检查；
- 可选 `pypdf` 的可提取页面文本和基础对象检查。

即使安装 `pypdf`，深层结构仍保持部分覆盖；加密、解析失败、超过页数、图片型页面、附件和复杂增量历史都可能需要其他工具。当前版本没有 PDF 写入适配器。

### 7.5 图片

- PNG 解析器按块遍历，限制总块数，对 zTXt/iTXt 使用严格格式校验和累计解压文本预算。
- JPEG 解析器按 segment 遍历，识别 EXIF、XMP、IPTC、评论和设备信息。
- Pillow 可增加 TIFF/WebP 及更丰富标签检查。
- 像素始终不进入 OCR 或语义识别流程。

## 8. 检测、遮罩与报告流程

```mermaid
sequenceDiagram
    participant A as Adapter
    participant D as detectors.py
    participant R as redaction.py
    participant B as ReportBuilder
    participant J as JSON consumer

    A->>D: 有界文本或结构字段
    D-->>A: DetectorHit（仅进程内含原始范围）
    A->>R: 命中值 + value_class + 临时密钥
    R-->>A: masked evidence + run-scoped token
    A->>B: 规则、位置、遮罩证据、建议
    B->>B: 生成非敏感稳定 ID 和汇总
    B-->>J: sharesafe.report/v1
```

### 8.1 规则层

规则以稳定前缀分组：

- `pii.*`：邮箱、中国大陆手机号、校验通过的居民身份证号和 Luhn 卡号等；
- `secret.*`：私钥标记、特定 provider token、JWT 和凭据赋值；
- `privacy.*`：可能暴露账户身份的用户主目录路径；
- `unicode.*`：双向和零宽控制字符；
- `SS-GEN-*`：文件系统、敏感文件名、链接、VCS、可执行文件和类型错配；
- `SS-ARCHIVE-*`、`SS-OOXML-*`、`SS-PDF-*`、`SS-IMAGE-*`：格式专用结构信号。

规则增加时必须同时定义 ID、类别、严重性、置信度、正反例、边界测试、遮罩策略和误报分析。

### 8.2 遮罩边界

检测命中在转换为 Finding 时立即经过 `redaction.py`。允许保留的只有审阅所需的类别信息，例如：

- 值类型；
- 策略允许的少量前/后缀；
- 长度桶；
- 结构位置；
- 本次运行内的关联 token。

禁止进入报告的内容包括裸匹配、识别出的用户名/主机名、绝对扫描根、原始文件 SHA 摘要和底层异常字符串。

### 8.3 为什么报告仍需保护

即使证据已经遮罩，报告仍可能泄露：

- 相对文件名和目录结构；
- 文件大小和媒体类型；
- 风险类别与数量；
- 组织使用了哪些工具或格式。

因此报告默认保留本地，不自动上传。

## 9. 结论和退出码流程

### 9.1 结论算法

```mermaid
flowchart TD
    A{存在 gap、error 或 partial 工件?}
    A -- 是 --> I[incomplete]
    A -- 否 --> B{存在 high 或 critical?}
    B -- 是 --> C[block]
    B -- 否 --> D{存在任意 finding?}
    D -- 是 --> E[review]
    D -- 否 --> F[no_findings]
```

发现不会因为出现 gap 而丢失。`incomplete` 报告仍保留已经检测到的风险，让用户既看到明确问题，也知道哪些部分尚未检查。

### 9.2 退出码算法

扫描退出码与结论相关但不相同：

```text
if gap or error or partial artifact:
    exit 2
elif fail_on == never:
    exit 0
elif any finding severity >= fail_on:
    exit 1
else:
    exit 0
```

固定参数/操作错误退出 `3`，文件系统或内部失败退出 `4`。结论 `review` 可以在默认 high 阈值下退出 `0`；结论 `block` 也可以在 `--fail-on never` 下退出 `0`。自动化必须检查两者。

## 10. 净化流程

净化是独立编排路径，不是给扫描器开启写权限的开关。

```mermaid
flowchart TD
    A[解析 source / out / report] --> B{输出独立、缺失且关系安全?}
    B -- 否 --> X[退出 3，不写入]
    B -- 是 --> C[用临时密钥扫描 before]
    C --> D[预检源：类型、链接、数量、深度、总字节]
    D --> E[在目标父目录创建私有 staging]
    E --> F[逐文件稳定读取/复制]
    F --> G{内容类型在允许列表?}
    G -- OOXML --> H[清理允许的属性和 ZIP 元数据<br/>计算 protected facets]
    G -- PNG/JPEG --> I[方向安全时清理允许的 metadata<br/>计算 protected facets]
    G -- 其他 --> J[复制并记录 not_needed/unsupported/skipped]
    H --> K[写入 staging]
    I --> K
    J --> K
    K --> L[归一化支持的时间和粗粒度权限]
    L --> M[以无覆盖语义提交 destination]
    M --> N[用同一临时密钥扫描 after]
    N --> O[用核心签发 receipt 绑定<br/>before / transform input / expected after / postscan]
    O --> O2[验证格式级 preserved facets]
    O2 --> P[输出 sanitize/v1]
    P --> Q{after 或 verification 是否 incomplete}
    Q -- 是 --> R[退出 2]
    Q -- 否 --> S{regressed 或未 ready_for_review}
    S -- 是 --> T[退出 1]
    S -- 否 --> U[按 after 的 fail-on 退出]
```

### 10.1 路径预检

`create_sanitized_copy()` 在创建 staging 前拒绝：

- 源不存在；
- 目标已存在或是链接；
- 源与目标相同；
- 目录目标位于源目录内部；
- 源或目标使用 Windows ADS；
- 源是链接/reparse point；
- 源树包含链接、特殊文件，或超过文件数、深度、总字节预算。

### 10.2 Staging 与提交

staging 位于目标父目录中，以减少跨文件系统提交差异。提交策略按平台和工件类型选择：

- 文件优先使用 hardlink no-replace；不可用时使用 `O_EXCL` 独占创建并同步写入；
- Windows 目录使用不替换的 rename；
- POSIX 目录先以独占语义保留目标目录，再迁移成员；失败时回收未完成目标；
- 竞争过程中出现目标时立即拒绝，不覆盖他人创建的数据；
- 已经达到提交点的结果不会在后续异常中被静默删除。

### 10.3 变换允许列表与受信 receipt

验证层只承认三类 `applied` 动作：

- OOXML 的 `remove_ooxml_metadata`；
- PNG 的 `strip_png_metadata`；
- JPEG 的 `strip_jpeg_metadata`。

而且动作路径和前后媒体类型必须一致。v0.2 还要求一份由当前核心进程签发的 receipt，使前扫 token 等于变换输入 token、预期输出 token 等于后扫 token，且格式级 protected facets 全部保持。`skipped`、`partial`、`unsupported`、`failed`、receipt 缺失/伪造或 facet 不符都会造成完整性问题和总体不完整。

### 10.4 OOXML 写入防护

OOXML 在重建 ZIP 前会检查：

- 包结构和主部件匹配；
- 重复/危险成员名、链接、加密和资源预算；
- 所有 XML/relationship 部件都能安全解析且没有 DTD/entity；
- 没有宏、嵌入 OLE/ActiveX 或数字签名；
- 自定义属性引用能够确定性解析。

任一条件不满足都复制原字节并标记 skipped，而不是冒险修改包。

### 10.5 图片方向防护

JPEG/PNG 的 EXIF Orientation 不是普通隐私标签：盲目删除会改变查看器中的显示方向。ShareSafe 只有在 EXIF 结构可解析且方向缺失或为 `1` 时才删除该段；否则保留整个 EXIF，并把动作标记为 skipped/partial。

## 11. 验证流程

### 11.1 比较对象

`verify.py` 比较：

- 前后工件数量和按 path 分组的清单；
- 媒体类型；
- 字节大小；
- 使用同一临时密钥生成的 HMAC 内容令牌；
- Finding 的语义键和出现次数；
- 前后覆盖结论；
- 本次 `sanitize` 在进程内签发的受信 transform receipts。

### 11.2 完整性状态

| 状态 | 条件 |
|---|---|
| `preserved` | 工件一一对应，类型、大小和内容令牌均未改变 |
| `transformed` | 只有同次 sanitize 的 allowlisted 变换能解释变化，且四快照 token 与格式级 preserved facets 全部验证 |
| `unverified` | 工件新增/删除、类型变化、重复身份歧义、未知字节变化或不完整动作 |

### 11.3 发现比较状态

| 状态 | 条件 |
|---|---|
| `unchanged` | 没有发现被解决或新增，覆盖和完整性可比较 |
| `improved` | 有发现消失，且没有新增，完整性得到解释 |
| `regressed` | 出现新的发现 |
| `incomplete` | 任一侧覆盖不完整，或工件完整性为 unverified |

发现比较按多重集处理：同一规则、位置和遮罩 token 的重复出现不会被集合去重掩盖。

### 11.4 sanitize 内置验证与 standalone verify 的差异

```mermaid
flowchart LR
    A[sanitize before scan] -->|同一临时密钥| B[sanitize transform + core-issued receipts]
    B --> C[sanitize after scan]
    C --> D[允许 applied action 解释对应字节变化]

    E[standalone original scan] -->|同一比较密钥| F[standalone prepared scan]
    F --> G[没有可信变换清单]
    G --> H[任何字节变化 => unverified/incomplete]
```

只有正在执行的 `sanitize` 拥有可信的进程内 receipt。这类 receipt 不进入可被外部重建的信任输入；保存在 JSON 中的 action 只是审阅记录。事后独立 `verify` 不能认证过去或第三方工具做了什么，所以故意更保守。

## 12. Codex Skill 流程

```mermaid
sequenceDiagram
    participant U as 用户
    participant S as ShareSafe Skill
    participant C as 本地 CLI
    participant F as 本地文件

    U->>S: 指定要审计的准确路径
    S->>C: doctor --json
    C-->>S: 能力和可选依赖
    S->>C: scan <path> --json
    C->>F: 只读、受限检查
    F-->>C: bytes / metadata
    C-->>S: 遮罩报告 + 退出码
    S-->>U: 严重性、类别、gap、error、边界
    U->>S: 可选：明确授权新输出路径
    S->>C: sanitize ... --out ... --json
    C-->>S: before/actions/after/verification
    S-->>U: 残余风险和验证状态，不自动上传
```

Skill 的渐进披露结构为：

1. `name`/`description` 用于准确触发；
2. `SKILL.md` 保存共同流程和硬边界；
3. `references/workflow.md` 解释命令选择和停止条件；
4. `references/report-contract.md` 供 JSON 消费和自动化读取；
5. `references/security-boundaries.md` 供保证、失败和范围判断。

Skill 不应把每次扫描都加载全部参考资料，也不应在没有写入授权时主动调用 `sanitize`。

## 13. 路径、文件系统与提交安全

### 13.1 展示路径和访问路径分离

扫描器内部可使用绝对路径访问用户明确指定的目标，但传给适配器和报告的是清理后的展示路径。身份型 home/UNC 路径在规则边界遮罩，源根不进入 JSON。

### 13.2 链接和特殊对象

- 扫描不会跟随 symlink/reparse point；
- sanitize 直接拒绝含链接的源树；
- socket、device、FIFO 等特殊对象不读取；
- ZIP 成员名只作为字符串/虚拟标签，从不直接映射为磁盘目标。

### 13.3 竞态

读取前/中/后身份比较负责发现扫描期间替换文件的 TOCTOU 情况。净化的 `_stable_read` 和 `_stable_stream_copy` 也执行对应检查；提交目标采用不覆盖原语应对并发出现的同名路径。

### 13.4 输出父目录是信任边界

ShareSafe 不复制源的全部 ACL、所有者、扩展属性或备用数据流。输出继承目标父目录的安全属性，因此用户必须先选择访问控制合适的位置。净化树是发布副本，不是文件系统保真备份。

## 14. 资源限制和恶意输入防护

| 预算 | 默认值 | 防护对象 |
|---|---:|---|
| `max_file_bytes` | 50 MiB | 单文件读取和内存分配 |
| `max_total_file_bytes` | 1 GiB | 大目录总量 |
| `max_files` | 20,000 | 超大目录/条目枚举 |
| `max_directory_depth` | 64 | 深目录递归 |
| `max_text_bytes` | 16 MiB | 解码和规则扫描 |
| `max_findings_per_artifact` | 1,000 | 单工件报告膨胀 |
| `max_findings_total` | 10,000 | 全局报告膨胀 |
| `max_archive_entries` | 2,000 | ZIP 对象创建和遍历 |
| `max_archive_member_bytes` | 32 MiB | 单成员解压 |
| `max_expanded_bytes` | 256 MiB | 全局嵌套解压总量 |
| `max_compression_ratio` | 200 | 压缩炸弹 |
| `max_archive_depth` | 3 | 嵌套容器递归 |
| `max_xml_bytes` | 16 MiB | OOXML/XML 解析 |
| `max_pdf_pages` | 500 | 可选 PDF 页面遍历 |
| `max_name_bytes` | 4 KiB | 超长文件/成员/部件名 |
| `max_display_path_chars` | 16,384 | 遮罩后路径膨胀 |
| `max_report_field_chars` | 16,384 | 单个 JSON 字段膨胀 |
| `max_gaps_total` | 10,000 | gap 列表膨胀，同时保留截断控制记录 |
| `max_errors_total` | 1,000 | error 列表膨胀 |
| `max_report_bytes` | 32 MiB | 最终序列化 JSON 体积 |

防护采用“两次检查”思路：尽可能先根据声明大小和中央目录拒绝，再在真正读取时限制实际字节。名称遮罩使用有界、近似线性的区间处理；超限名称用固定不可逆 placeholder 替换。达到 finding/gap/error 或报告上限必须保留控制记录并使结果 `incomplete`，防止截断后的报告看起来完整。

## 15. JSON schema 和自动化边界

### 15.1 schema 关系

```mermaid
flowchart TD
    R[sharesafe.report/v1]
    CH[sharesafe.check/v1]
    P[sharesafe.policy/v1]
    S[sharesafe.sanitize/v1]
    V[sharesafe.verify/v1]
    CH -->|report| R
    CH -->|effective policy receipt| P
    S -->|before| R
    S -->|after| R
    S --> A[actions]
    S --> VR[verification]
    V -->|original| R
    V -->|prepared| R
    V --> VR
    PD[sharesafe.prepare-decisions/v1]
    PP[sharesafe.prepare-plan/v1]
    PA[sharesafe.prepare-approval/v1]
    PI[sharesafe.prepare-inspection/v1]
    PC[sharesafe.prepare-control-write/v1]
    PR[sharesafe.prepare-result/v1]
    PD --> PP
    PA -->|plan_digest| PP
    PP --> PI
    PP --> PC
    PA --> PC
    PP --> PR
    PR -->|final_scan| R
```

当前核心 JSON Schema 使用稳定 `$id`：

- `urn:sharesafe:schema:report:v1`
- `urn:sharesafe:schema:sanitize:v1`
- `urn:sharesafe:schema:verify:v1`
- `urn:sharesafe:schema:policy:v1`
- `urn:sharesafe:schema:check:v1`
- `urn:sharesafe:schema:prepare-decisions:v1`
- `urn:sharesafe:schema:prepare-plan:v1`
- `urn:sharesafe:schema:prepare-approval:v1`
- `urn:sharesafe:schema:prepare-control-write:v1`
- `urn:sharesafe:schema:prepare-inspection:v1`
- `urn:sharesafe:schema:prepare-result:v1`

离线消费者应把所有相关本地 schema 注册到以 `$id` 为键的 registry，不允许验证器从网络获取引用。D3 控制 schema 与 D2 遮罩结果 schema 不得混用：plan/approval 不能通过普通 masked-report sink。

### 15.2 CLI 输出边界

- `--json` 时 stdout 只包含机器 JSON；
- 人类诊断写入 stderr；
- 参数、文件系统和内部错误使用 `sharesafe.error/v1` 稳定消息；
- 原始 exception string 不进入公共包络；
- `--report` 只创建新文件，并采用原子写入语义。

### 15.3 消费者规则

消费者必须同时验证 schema、必需字段、已知 verdict/coverage、退出码和 gap。未知版本不能静默按 v1 读取；报告字段永远视为不可信字符串，不能拼接成 HTML、命令或可执行路径。

## 16. 测试体系

全部测试只使用合成数据，分成四层。

### 16.1 单元测试

覆盖规则校验、类型 sniff、遮罩、HMAC、稳定 ID、limits 和结论优先级。典型文件：

- `test_detectors.py`
- `test_engine.py`
- `test_path_safety.py`
- `test_schema.py`

### 16.2 适配器和对抗输入测试

覆盖有效、空、损坏、加密、过大、深层、扩展错配、危险成员名和解析器差异：

- `test_archive.py`
- `test_archive_comments.py`
- `test_zip_preflight.py`
- `test_ooxml.py`
- `test_ooxml_hardening.py`
- `test_png_limits.py`

### 16.3 写入和验证测试

验证原件不变、输出关系拒绝、staging/提交、变换允许列表、复扫和完整性比较：

- `test_sanitize_verify.py`
- `test_malformed_sanitize.py`
- `test_name_inventory.py`

### 16.4 CLI、隐私和回归测试

验证 stdout/stderr、JSON、退出码、路径隐藏、错误卫生和历史缺陷：

- `test_cli.py`
- `test_cli_error_privacy.py`
- `test_security_regressions.py`

v0.2 在此基础上新增的核心回归包括：

- `test_safe_io_races.py`：打开对象被替换时，不读取或扫描替代文件字节；
- `test_transform_receipts.py`：四快照 token、外部伪造 action、输出篡改和 protected facet 误改；
- `test_capabilities.py` / `test_doctor_deep.py`：合成 parser probe 和平台安全能力声明；
- `test_policy_check.py` / `test_policy_cli.py`：严格策略、合并优先级、digest、reason code 和退出决策；
- `test_rule_catalog.py`：exact ruleset catalog 的稳定字段与一致性；
- 报告边界/卫生测试：超长 Unicode、控制字符、超预算输出、原始 canary 和绝对路径注入。

v0.3 测试只使用合成数据，覆盖 plan/approval 篡改、空 inventory、source drift、路径冲突/复活、私有 staging 权限、commit 竞态、额外空目录、omit/rename/copy/strip 关系错误、扫描中换字节、最终复扫 gap、超预算完整降级和本地控制工件分级。

### 16.5 Skill 行为测试

新鲜代理上下文应验证：

- 能否在分享前审计请求中正确触发；
- 是否默认只读并先运行 doctor；
- 是否解释 incomplete 而不说成未发现风险；
- 是否在没有明确输出路径/授权时拒绝写入；
- 是否不索要或复述裸证据；
- 是否正确区分 sanitize 内置验证和 standalone verify。

可复现记录位于 [skill-evaluation.md](skill-evaluation.md)。

## 17. CI、打包与发布前门禁

### 17.1 普通 CI

```mermaid
flowchart LR
    A[代码变更] --> B[Ubuntu + Windows]
    B --> C[Python 3.11 / 3.12 / 3.13]
    C --> D[安装 full + dev]
    D --> E[pytest]
    E --> F[console CLI smoke]
    F --> G[bundled Skill CLI smoke]
    G --> H[官方 Skill validator]
    H --> I[build wheel + sdist]
    I --> J[twine + 内容清单校验]
    J --> K[从 sdist 重建 wheel]
    K --> L[隔离无依赖安装与自测]
    L --> M[保留受控本地/CI 制品]
```

矩阵测试先通过后，单独的 package job 才构建分发包。wheel 和由 sdist 重建的 wheel 都在新虚拟环境中以 `--no-index --no-deps` 安装，并运行 `pip check`、版本、`doctor --deep`、`self-test`、exact rules catalog 和只含合成数据的 smoke check。报告工件默认不离开受控环境。

### 17.2 发布候选制品门禁

```text
冻结候选版本和源摘要
  -> 平台/Python 组合测试
  -> 再次验证 Skill 和完整测试
  -> 构建 wheel + sdist
  -> twine / manifest / version 一致性检查
  -> 从 sdist 重建 wheel并安装验收
  -> 生成 SHA256SUMS
  -> 只有所有门禁通过后，才可由独立授权流程决定是否对外发布
```

本步只生成和验证候选制品，不隐含远程写权限，也不表示任何版本已公开发布。如未另行授权，流水线应停在本地/受控 CI 制品、内容清单和 `SHA256SUMS`。

### 17.3 从候选制品反向验收

一次完整的候选制品验收应从刚刚生成的制品目录重新开始，而不是只信任已安装的开发工作区：

1. 比对制品摘要、`SHA256SUMS` 和本地 SHA-256；
2. 在全新环境用 `--no-index --no-deps` 安装候选 wheel；
3. 运行 `pip check`、version、doctor 和 self-test；
4. 用该 CLI 扫描 wheel；
5. 确认没有未解决的 high/critical、gap 或 error，并保留所有 review 级别结果；
6. 确认版本、源摘要、制品清单和本地工作树状态。

## 18. 扩展和变更流程

### 18.1 新增规则

```text
威胁/用例 -> 稳定 rule ID -> 精确模式与校验
         -> 正例/反例/边界/Unicode 测试
         -> 遮罩策略和裸值缺失断言
         -> catalog / 文档 / changelog
```

短且常见的字符串必须做误报分析；调试时也不能打印裸匹配。

### 18.2 新增格式适配器

需要同时交付：

1. 明确声明检查哪些表示、不检查哪些表示；
2. 内容 sniff 规则，而不是只看扩展名；
3. 不可变 bytes 适配器，不打开任意路径；
4. 加密、损坏、空、过大、错配和嵌套 fixture；
5. 资源预算和 parser exception 到 gap 的映射；
6. 可选依赖缺失行为；
7. 支持矩阵和威胁模型更新。

### 18.3 新增 sanitizer

检测能力不能自动转化为写入授权。新增变换必须先有：

- 高置信、格式精确的允许列表；
- 源不变和路径关系测试；
- 失败原子性/无覆盖提交策略；
- 内容保真或明确允许变化的测试；
- 当前进程可信 action；
- 强制 after scan 和残余/新增发现比较；
- 未支持、partial、skipped 和 parser 缺失的失败关闭行为。

### 18.4 修改报告

- 删除字段、改变字段含义或结论语义需要新 schema 标识；
- 新增可选字段要定义缺失语义；
- schema、测试、报告参考、自动化示例和 changelog 同步更新；
- 所有错误路径继续验证 stdout JSON 和证据/绝对路径缺失。

### 18.5 修改 Skill

Skill 应保持薄层：共享约束放 `SKILL.md`，模式细节放 references，确定性逻辑放 scripts。修改后运行官方 `quick_validate.py`，并用独立代理做真实触发、只读默认、写入授权和不夸大结论的前向测试。

## 19. 主要设计取舍

### 19.1 为什么离线而不是云扫描

ShareSafe 处理的正是用户不愿泄露的内容。离线设计消除了正常路径上的远端传输、服务日志和供应商数据保留边界，也让报告可复现。代价是本机必须承担解析器依赖和资源限制，无法获得云端 OCR/视觉能力。

### 19.2 为什么 fail closed

“没有找到”与“没有看完”不能等价。把 unsupported、parser failure 和 limit hit 提升为 `incomplete` 会增加人工工作，但避免部分扫描在 CI 中伪装成成功。

### 19.3 为什么检测能力大于净化能力

检测一个结构信号通常只需证明它存在；安全删除它还需理解文档语义、签名、关系、显示效果和完整性。ShareSafe 选择少量可验证元数据变换，避免以广覆盖换取不可控内容损坏。

### 19.4 为什么使用临时 HMAC 而不是公开 SHA-256

公开文件摘要可以让报告持有者对小型候选集合做成员测试。临时 HMAC 保留同一比较运行内的字节身份能力，又不把持久原始摘要放入报告。代价是不同独立运行的内容令牌不能直接比较，这是有意的隐私边界。

### 19.5 为什么 standalone verify 对变化失败关闭

仅凭“前后文件”无法知道变化来自可信编辑、意外损坏、删除正文还是攻击。只有当前 sanitize 的进程内 allowlisted action 可以解释对应变化；其他变化作为 `unverified` 暴露给人工流程。

### 19.6 为什么归档成员不落盘

直接提取会引入路径穿越、链接、权限、覆盖和执行风险。ShareSafe 只在内存预算内读取成员 bytes，并用虚拟路径递归扫描，减少新的文件系统攻击面。

### 19.7 为什么 Skill 不直接阅读文件

让模型先打开敏感文件会把原始内容带入对话上下文，也会产生不稳定判断。Skill 只运行本地确定性扫描器并消费遮罩报告，使证据边界可测试。

## 20. 规范来源与维护规则

| 问题 | 规范来源 |
|---|---|
| CLI、退出码、报告和变换公共承诺 | [design-contract.md](design-contract.md) |
| 每种格式能扫描/净化什么 | [SUPPORT_MATRIX.md](../SUPPORT_MATRIX.md) |
| 保护资产、威胁和残余风险 | [THREAT_MODEL.md](../THREAT_MODEL.md) |
| 组件边界和扩展原则 | [architecture.md](architecture.md) |
| 扫描 JSON 字段与消费要求 | [report-contract.md](../skills/sharesafe/references/report-contract.md) 和 `schemas/` |
| Codex 操作选择与停止条件 | [workflow.md](../skills/sharesafe/references/workflow.md) |
| 用户实际操作 | [中文使用手册](user-guide.zh-CN.md) |

维护时遵循以下顺序：

1. 先确定实现变化是否改变公共能力或信任边界；
2. 修改代码和只含合成数据的测试；
3. 更新规范性文件和 schema；
4. 更新本中文导览和用户手册；
5. 运行全测试、Skill validator、打包和隔离安装；
6. 通过候选制品门禁与隔离安装反向验收；对外发布必须是另行授权的后续流程。

如果本文和规范性文件冲突，应修正文档并以更窄、更保守的能力声明为准。

## 21. v0.2 快照绑定、safe I/O 与格式不变量

### 21.1 要关闭的信任缺口

旧的“同路径 + 同媒体类型 + applied action”足以生成有用的审阅记录，但不足以证明扫描、变换和复扫处理的是同一条字节因果链。需要防御三种差错：

```mermaid
sequenceDiagram
    participant S as Source path
    participant B as Before scan
    participant T as Transformer
    participant O as Output path
    participant A as After scan

    S->>B: 读取快照 B0
    Note over S,T: 风险 1：前扫后源被替换
    S->>T: 变换实际输入 T0
    T->>O: 写出预期快照 T1
    Note over O,A: 风险 2：提交后输出被替换
    O->>A: 后扫快照 A1
    Note over T: 风险 3：变换器同时误改正文/像素数据
```

v0.2 的必要条件是 `B0 == T0`、`T1 == A1`，同时变换允许列表以外的格式表示全部保持。任一条不成立，完整性状态必须是 `unverified`，整体必须 `incomplete`。

### 21.2 TransformReceipt 的信任属性

核心内部 receipt 至少包含：

```text
action_id
relative_path
action_kind
media_type_before / media_type_after
before_content_token
transform_input_token
expected_after_token
postscan_content_token
preserved_facets[]
status / reason
```

其安全性不来自 JSON 字段名，而来自“由当前核心在同一进程内签发”。`receipts.py` 可以让 JSON-compatible actions 携带不可序列化的内部证明；普通 list/dict、重新解析的报告或外部伪造字段都不能变成 trusted receipt。

receipt 验证顺序是：

1. 路径在 before/after inventory 中均唯一；
2. receipt issuer 受当前核心信任；
3. action kind 是允许列表成员，并与 before/after media type 精确匹配；
4. before scan token 与 receipt 的 before/transform-input token 相同；
5. receipt 的 expected-after token 与 after scan token 相同；
6. `preserved_facets` 非空且每项都验证为保持；
7. 公开 action status 与内部 receipt 结果一致。

### 21.3 格式级 preserved facets

| 格式 | 允许变化 | 必须保持 |
|---|---|---|
| OOXML | 审查过的 core/app/custom properties、ZIP 条目元数据 | 未允许移除的成员集和成员字节、关系目标、正文/备注/图像等业务内容 |
| PNG | `tEXt`/`zTXt`/`iTXt`/`tIME`，方向安全时 `eXIf` | PNG 签名、IHDR/关键色彩表示、全部 IDAT、顺序敏感块和需保留 Orientation |
| JPEG | COM/APP13/XMP，方向安全时 EXIF | SOF 尺寸/采样、SOS 后编码扫描数据、未列入移除的 segment 序列 |
| Copy-only | 无内容变换 | 整文件 token、size、media type 全部相同 |

preserved facet 是“不可变”的格式层摘要，不应在可分享报告中放入原始部件摘要或持久可枚举的内容指纹。

### 21.4 Safe-I/O 能力与剩余边界

| 阶段 | 已有保证 | 仍需显式承认的边界 |
|---|---|---|
| 文件读取 | 字节读取前比较 discovery/opened descriptor identity，读后复核 | 某些平台无 `O_NOFOLLOW`；父目录仍未统一句柄锚定 |
| 变换读取 | 稳定读取结果与 before token 绑定 | 源父目录并发替换需平台级更强原语 |
| 目标创建 | 目标不存在，采用 exclusive/no-replace 语义 | 目标父目录身份锚定在平台间不等价 |
| 目录提交 | staging 与目标父目录同位，不覆盖 | 多文件目录的原子发布能力因平台而异 |

`doctor --deep` 的 `filesystem_safety` 是 capability receipt，不是安全证书。能力为 `false` 时必须让调用者看到；不能用“大多数时候没有竞态”代替契约。

## 22. v0.2 policy/check、deep doctor 与精确 rules

### 22.1 策略是 disposition，不是 detector 改写器

```mermaid
flowchart LR
    D[内置默认] --> M[严格合并]
    P[./.sharesafe.toml] --> M
    E[显式 --config] --> M
    O[显式 CLI overrides] --> M
    M --> EP[normalized effective policy]
    EP --> DG[canonical policy digest]
    EP --> SC[Scanner config]
    SC --> R[unchanged report/v1]
    R --> CH[check/v1 decision]
    EP --> CH
```

合并优先级固定为内置默认 < 当前工作目录的 `.sharesafe.toml` < 显式 `--config` < CLI overrides。加载器不向上搜索父目录，不读用户级全局文件，不解析环境变量或 glob 来扩张输入。

严格策略只控制：

- severity 阻断阈值；
- 受边界限制的 Limits；
- required capabilities；
- blocking categories；
- optional parser 是否允许；
- 是否需要 exact manifest。

它不允许关闭 detector、删除 finding、改写 severity、将 gap/error 降级，也不允许任意代码/命令/动态 import。

### 22.2 `check/v1` 决策算法

```mermaid
flowchart TD
    A[validate and deep-copy report/v1] --> B[recompute technical signals]
    B --> C{error/gap/partial/dependency issue?}
    C -- 是 --> I[technical=incomplete<br/>policy=incomplete<br/>exit 2]
    C -- 否 --> D{required capability missing<br/>or exact manifest unvalidated?}
    D -- 是 --> I
    D -- 否 --> E{blocking category or fail_on met?}
    E -- 是 --> F[policy=block<br/>exit 1]
    E -- 否 --> G{findings exist?}
    G -- 是 --> H[policy=review<br/>exit 0]
    G -- 否 --> J[policy=pass<br/>exit 0]
```

wrapper 同时保存：

- `technical_verdict`：`no_findings`/`review`/`block`/`incomplete`；
- `policy_outcome`：`pass`/`review`/`block`/`incomplete`；
- `exit_code`：与实际进程返回一致；
- `reason_codes`：按固定顺序记录 coverage、manifest、required capability、category、threshold 等信号；
- effective policy 的所有值、digest 和 exact ruleset version；
- 原样嵌套的 `report/v1`。

`pass` 仅是配置策略输出，不能被 UI、Skill、CI 或文档渲染成“安全”。同理，`no_findings` 是 technical observation，不是保证。

### 22.3 Manifest 的暂时失败闭合

policy schema 已能声明 `manifest.enabled/path/require_exact`，但只有字段能解析不代表 inventory 已验证。在没有 exact manifest validator receipt 时：

- `manifest.enabled = false` -> `manifest_validation: not_required`；
- `manifest.enabled = true` 但无 validator result -> `missing` + `policy_outcome: incomplete` + exit `2`；
- `require_exact = false` 不能让部分 manifest 变成完整，仍为 `incomplete`。

v0.3 的 plan inventory 是闭合这一契约的合适位置。

### 22.4 Deep doctor

`capabilities.py` 把“包看起来已安装”和“当前环境真能用它处理最小有效输入”分开：

1. discovery 模式检查模块存在与版本；
2. deep 模式 import parser；
3. 在内存中构造 1x1 PNG 和一页空白 PDF；
4. 执行解码/读取并验证最小不变量；
5. 只暴露 `passed`/`failed`/`missing`，不把 parser exception 原文输出；
6. 同时输出平台文件系统保证与剩余 gap。

可选 parser 当前仍在主进程的 bounded adapter 中运行。Deep doctor 证明最小功能可用，不证明 parser 已经进程隔离、不会卡死或能解析所有真实文件。

### 22.5 Exact rules catalog

`rules --detail --json` 的 exact item 包含 ID、category、default severity、confidence、formats、representations、validator 和 automatic remediation，顶层包含 `ruleset_version`。该目录的用途是能力发现、policy 审阅和可复现性；不是通过外部目录改写实际 detector。

## 23. v0.2 报告预算、卫生与结构差异

### 23.1 名称与报告预算

名称来自不可信文件系统、ZIP 成员和 OOXML part。一个攻击者可以用超长 Unicode、大量控制字符或重叠匹配诱导遮罩器产生超线性工作和巨大 JSON。v0.2 将下列预算纳入 `Limits`：

```text
max_name_bytes
max_display_path_chars
max_report_field_chars
max_findings_per_artifact / max_findings_total
max_gaps_total / max_errors_total
max_report_bytes
```

预算超限后的行为必须可观测：固定 placeholder、对应 gap、partial 工件和整体 `incomplete`。普通 finding 不能用尽 summary、error 和“已截断”控制 gap 所需空间。如果最终 JSON 无法在预算内完整表示，宁可拒绝输出，也不生成半份看起来合法的报告。

### 23.2 统一报告卫生边界

```mermaid
flowchart LR
    P[typed payload] --> H[report_hygiene]
    H --> S{schema / evidence / path / size valid?}
    S -- 是 --> J[canonical JSON]
    J --> O[stdout]
    J --> F[exclusive report file]
    J -. 未来需明确授权 .-> X[外部派生视图]
    S -- 否 --> E[stable path-free error<br/>no report conclusion]
```

卫生器必须深度遍历 scan/check/sanitize/verify 中的所有嵌套 report，检查：

- 精确字段集、类型和枚举值；
- evidence 必须是允许的遮罩形态；
- artifact path 是相对、经清理的显示字符串；
- 不出现已知绝对 home、UNC 或原始扫描根；
- 不出现控制字符、超长字段、NaN/无穷值或超预算 JSON；
- errors 只使用稳定 code/message，不携带底层 exception 原文。

报告卫生是“这份已遮罩输出满足公共契约”的机械检查，不是“这份报告可以公开分享”的授权。

### 23.3 本地 report show/diff（接口待 `--help` 最终核验）

`report show` 应只做安全派生视图：按 rule/category/severity 分组，使用已遮罩 evidence，不重新打开 source。`report diff` 应只按 rule/path/location 结构说明仍存在、新增或消失，并单独呈现 schema/ruleset/policy 变化。

跨运行比较不能自动豁免 baseline，原因是：

- finding ID 不包含 evidence，同位置出现全新秘密时 ID 可能仍相同；
- evidence/content token 是 run-scoped HMAC，不同运行不能直接声称值或字节相同。

因此 diff 不改变本次退出码，不吞 gap/error，不产生自动 allowlist。

## 24. v0.3 `prepare` 数据模型与完整流程

本节描述当前本地 v0.3 实现。`prepare` 已接入 CLI、版本化 schema 和合成端到端/竞态测试，但仍是 alpha 接口；未知 schema 或未来不兼容变化必须失败关闭。

### 24.1 整体状态机

```mermaid
stateDiagram-v2
    [*] --> Planned: exact source inventory + one action each
    Planned --> Reviewed: inspect masked action view
    Reviewed --> Approved: approval binds exact plan digest
    Approved --> Rejected: source/plan/approval drift
    Approved --> Staged: preflight + execute allowlisted actions
    Staged --> Rejected: action/facet/staging failure
    Staged --> Committed: exclusive no-replace publish
    Committed --> Verified: pre-scan relation + bound final scan + post-scan relation
    Committed --> Incomplete: unexpected item/change/finding/gap
    Verified --> HumanDecision
    Incomplete --> HumanDecision
```

`Verified` 也不是“安全”；它只说明输出 inventory 与已批准动作关系已按当前能力验证，且最终复扫结果已被完整记录。

### 24.2 Local control plan

plan 为 source inventory 中的每一项保存：

```text
action_id
source_path
target_path
media_type
action
reason_code(s)
approval_required
expected_relation
known_losses[]
source_binding { algorithm, digest, size }
```

顶层包含 schema、`classification: local_only_do_not_share`、固定的 source/destination boundary 占位标签、非空 item count、actions 和 canonical `plan_digest`。plan 使用强 SHA-256 source binding 来跨进程发现漂移；正因如此，它属于敏感本地控制工件，不是 masked report。

每个 source item 必须恰好一个 action：

```text
copy_unchanged
strip_ooxml_metadata
strip_png_metadata
strip_jpeg_metadata
omit_from_boundary
rename_in_bundle
manual_or_external_required
block
```

漏项不默认 copy，重复 source action 或未知 source 也失败关闭。临界秘密/PII 不得仅因“可以 omit”就被自动删除；检测建议不是写授权。

### 24.3 Inspect 与 approval

Inspect 派生视图展示每项 action、理由、目标路径、预期关系和已知损失，但不展示强 source digest、绝对根或原始 evidence。Approval 是独立的本地控制工件，绑定：

- exact `plan_digest`；
- 完整、去重、已排序的 approved action IDs；
- `status: approved_for_apply`；
- canonical `approval_digest`；
- `classification: local_only_do_not_share`。

含 `manual_or_external_required` 或 `block` 的计划不可获得 apply approval。这两类项必须先经外部专业流程产生新输入，然后从 plan 开始重做。

Plan/approval digest 是 canonical consistency binding，不是数字签名、人工身份认证或不可抵赖记录。拥有同一账户写权限的进程可以同步改写所有控制工件并重算摘要；D3 控制目录必须由用户信任。

### 24.4 Apply 安全流程

```mermaid
flowchart TD
    A[严格解析 plan + approval] --> B{digests and action IDs exact?}
    B -- 否 --> X[拒绝；退出 3/4]
    B -- 是 --> C[重新枚举 SOURCE]
    C --> D{inventory / type / size / binding drift?}
    D -- 是 --> Y[拒绝；重新 plan]
    D -- 否 --> E{OUTPUT absent and disjoint?}
    E -- 否 --> X
    E -- 是 --> F[在系统临时位置创建并验证 owner-only staging]
    F --> G[仅执行已批 allowlisted actions]
    G --> H[为 copy/strip/omit/rename 生成内部验证记录]
    H --> I{每项精确符合计划?}
    I -- 否 --> Z[标记 incomplete；恢复/诊断]
    I -- 是 --> J[exclusive no-replace commit]
    J --> K[提交后精确关系检查]
    K --> L[同一 HMAC key 最终扫描并绑定实际读取]
    L --> M[扫描后再次精确检查]
    M --> N[输出有界 masked result]
```

Apply 不修改 SOURCE，不删原件，不覆盖 OUTPUT，不执行任意 plan 内容，不自动上传结果。Staging 位于系统临时位置而不是目标父目录，名称不反映 target tree；POSIX 验证当前有效用户和 `0700`，Windows 在创建时设置受保护、仅当前用户且可向子项继承的 DACL，并通过目录句柄安全信息复核。权限无法证明时，在保留 OUTPUT 前失败。

Commit 先独占保留 output 目录并写随机 incomplete marker，再逐目录/文件采用 create-new 语义填充，不使用会覆盖竞争项的 replacing rename。目标名保留后的故障设置 `output_may_exist`；若路径 identity 不再可信，宁可留下明确的不完整工件，也不递归删除可能已被替换的目录。

### 24.5 计划内验证语义

| 关系 | 精确条件 |
|---|---|
| copy | source/target 映射唯一，相对路径按计划，media type、size 和 token 相同 |
| omit | exact source 路径/子树在输出不存在，且不能被其他 materialized target 复活 |
| rename | 一对一映射，内容/media type 不变，原名不残留，无折叠/规范化冲突 |
| strip | 必须通过 v0.2 四快照 receipt 与格式级 preserved facets |
| directory | 目录子树 inventory 与全部子 action 一致，无多项、少项或额外空目录 |

任何新文件、缺失文件、额外空目录、重复身份、额外字节变化、Scanner 实际读取快照不符、输出新 finding、coverage gap、parser failure 或资源截断均导致 `incomplete`。“finding 变少”不能替代这些关系验证。

### 24.6 CLI 与 schema

```text
sharesafe prepare plan SOURCE --decisions DECISIONS --out-plan PLAN --json
sharesafe prepare inspect PLAN --json
sharesafe prepare approve PLAN --out-approval APPROVAL --approve-all --json
sharesafe prepare apply PLAN --approval APPROVAL --source SOURCE --out NEW_OUTPUT_DIRECTORY --json
sharesafe prepare verify PLAN --source SOURCE --output OUTPUT_DIRECTORY --json
```

当前 schema 包括：

- D3：`sharesafe.prepare-decisions/v1`、`sharesafe.prepare-plan/v1`、`sharesafe.prepare-approval/v1`；
- D2：`sharesafe.prepare-control-write/v1`、`sharesafe.prepare-inspection/v1`、`sharesafe.prepare-result/v1`。

`prepare-result/v1` 包含 plan action 总数/分类、可有界省略的动作记录、commit 状态、expected/observed 文件计数、问题总数/已报告/省略数、嵌套 final scan、reporting detail 和 `ready_for_review`。它从不序列化 plan digest、source SHA-256 或 output SHA-256。

### 24.7 结果预算与失败闭合

完整结果先按 `max_report_bytes` 测量。如果超过预算：

1. 加入 `prepare_result_size_limit`，使 verification 和退出码成为 incomplete/`2`；
2. 优先保留完整 final scan 和 verification issues，再在剩余预算内保留动作前缀；
3. 若嵌套 final scan 本身使 envelope 无法容纳，则替换为含明确 reporting gap 的最小合法 `sharesafe.report/v1`；
4. 始终记录 action/issue 的 total、reported、omitted 和 final scan detail；
5. 输出前再次通过统一报告卫生与完整 JSON 字节检查。

因此即使 output 已经 commit，调用方也不会只得到一个含混的内部错误或半截 JSON。预算降级的 result 仍是证据不足状态，不能因为详细数组为空就解释为“没有动作/没有问题”。

## 25. 数据分级、威胁边界与故障恢复

### 25.1 数据分级

| 类别 | 内容 | 信任要求 |
|---|---|---|
| D0 公开设计材料 | 不含本地运行数据的 schema、文档、默认 policy 模板 | 仍需发布前审阅，但无 source binding |
| D1 最小化分享摘要 | 仅总数、类别和非身份结论，无逐文件路径/token/时间 | 仅经用户明确授权方可离开本机 |
| D2 遮罩操作记录 | scan/check/sanitize/verify/final prepare receipt | 受限内部；相对路径、大小和类别仍可泄露结构 |
| D3 本地控制工件 | policy、control plan、approval、强 source digests、完整 inventory | owner-only/等价权限；不放进 OUTPUT；不上传 |
| D4 原始输入与内存中间值 | 原文件、原始元数据、裸 detector hit、解压/解码字节 | 仅在本地进程最小存活；不进公共报告/日志/对话 |

D3 与 D2 的分离是 v0.3 的必要条件：为了跨进程发现 source drift，control plan 必须保存稳定强 digest；这种信息不能进入普通 masked report，否则会变成内容关联/枚举 oracle。Digest 只提供一致性，不提供签名认证。

### 25.2 信任边界

```mermaid
flowchart TB
    U[用户明确选定的 SOURCE] -->|D4| CORE[ShareSafe deterministic core]
    UN[不可信：文件名、字节、容器、parser 输出] --> CORE
    CORE -->|typed + masked| H[report hygiene]
    H -->|D2| R[本地报告]
    CORE -->|D3| P[policy / plan / approval]
    P --> CORE
    CORE -->|new path only| O[新输出边界]
    R --> HD[人/组织决策]
    O --> HD
    HD -. 另行授权 .-> EXT[外部分享/发布]
```

核心可信的是它自己的类型化逻辑、当前进程临时 HMAC key 和内部 issuer；不可信的包括输入字节、文件/成员名、第三方 parser、外部 JSON、旧 action 记录、用户可编辑 plan 以及并发变化的文件系统。

下列威胁仍在范围外或只能部分缓解：

- 被完全控制的本机内核/管理员、底层存储或备份系统；
- OCR、图像语义、音视频、隐写和不可见渲染效果；
- 可选 parser 在主进程中的全部 CPU/RSS/墙钟隔离；
- 所有平台上等价的父目录句柄锚定与多文件原子提交；
- 法律、合规、组织授权、功能和版式验收。

### 25.3 故障、输出状态与恢复

| 故障点 | 公开状态 | 恢复动作 |
|---|---|---|
| policy 不可读/无效/读取时变化 | 退出 `3`/`4`，无 check decision | 修复本地策略后重跑；不回退到更宽松隐式策略 |
| deep parser probe failed | doctor `incomplete` 或 parser unusable | 修复/禁用可选 parser；若输入需该能力，保留 coverage gap |
| 扫描期间文件替换 | artifact partial + gap + exit `2` | 在稳定输入上重跑；不使用已读部分作放行 |
| report hygiene 失败 | 稳定错误，无可信报告 | 停止消费；用合成 canary 复现；不附真实输入 |
| receipt token/facet 不符 | `unverified` + `incomplete` | 保留原件，将输出当待调查副本，不追加 standalone verify 来“漂绿” |
| prepare plan/approval 篡改或 source drift | apply 前拒绝 | 重新 plan -> inspect -> approve，不修改 digest 绕过 |
| staging 私有权限不可证明 | `private_staging_unavailable`，无 committed output | 更换受支持本地文件系统；不降级到共享临时目录 |
| staging 前半失败 | 无 committed output | 只在 identity checkpoint 仍匹配时清理精确随机目录；不删宽泛目录 |
| commit 后 final rescan/关系失败 | output 已存在，verification incomplete 或明确 `output_may_exist` | 保留并隔离 output；若有 incomplete marker 绝不分享；不静默递归删除 |
| prepare result 超预算 | 完整 JSON、omitted 计数、`prepare_result_size_limit`、exit `2` | 在受控环境提高预算后重跑；不得把空明细数组解释为无问题 |
| 任何 gap/error/resource limit | `incomplete` + exit `2` | 补能力、缩小真实分享单元或人工处理；不仅调大限制来隐藏 |

### 25.4 运维与诊断最小集

在不接触真实敏感内容的前提下，诊断顺序应是：

```text
sharesafe --version
sharesafe --help
sharesafe doctor --deep --json
sharesafe self-test --json
sharesafe rules --detail --json
sharesafe policy validate --config SYNTHETIC_POLICY --json
sharesafe check SYNTHETIC_INPUT --config SYNTHETIC_POLICY --json
```

如果故障只在真实工件上出现，应用同格式的最小合成 fixture 复制结构特征，不上传原文件、未审阅报告、本机绝对路径、真实凭据或 D3 control plan。
