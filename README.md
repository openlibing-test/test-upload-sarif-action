# openlibing-upload-sarif

## 简介

通用 SARIF 上传插件：将任意静态扫描工具产出的 SARIF 文件（支持单文件或目录）上传到华为云 OBS 对象存储，生成标准化的构建产物 JSON，并通过 APIG 网关回调通知 OpenLibing 服务。

- **插件名**: `openlibing-upload-sarif`
- **认证模式**: OIDC 联邦认证（免静态 AK/SK），由插件内嵌 SDK 自包含换证，无需额外运行 `huaweicloud-oidc-auth` 插件

## 功能特性

- 通用 SARIF 上传：不绑定任何具体扫描工具，支持单文件或目录（自动扫描目录下所有 `.sarif` 文件）
- 自动识别 SARIF 文件中的工具名（`runs[0].tool.driver.name`）用于构建产物类型，后端按 `tool.driver.name` 路由
- 自动补齐 `region.snippet`（代码上下文）：SARIF 缺少代码片段信息时，按 `uri` + 行号读取源码补齐，提升后端告警可读性
- OIDC 免静态凭证：插件内嵌 `@openlibing/huaweicloud-oidc-client` SDK，自申请 OIDC ID Token 并调用华为云 STS 换证，OBS 上传与 APIG 回调全程使用临时凭证
- 自动下载安装 `obsutil` 命令行工具，上传对象设置公共读权限
- 通过 APIG 网关回调通知 OpenLibing 扫描服务（V11-HMAC-SHA256 签名 + `X-Security-Token`）
- 失败重试：OBS 上传与 APIG 回调均采用**指数退避重试（默认 3 次）**，降低网络抖动导致的数据丢失风险

## 前置要求

Workflow 只需声明 `permissions: id-token: write`。插件内嵌 `@openlibing/huaweicloud-oidc-client` SDK 会自动向流水线申请 OIDC ID Token 并调用华为云 STS 换取临时凭证，**无需再运行 `huaweicloud-oidc-auth` 插件**：

```yaml
permissions:
  id-token: write
```

## 输入参数

| 参数 | 说明 | 必填 | 默认值 |
|------|------|------|--------|
| sarif_file | SARIF 文件路径或所在目录（相对/绝对路径均可，目录自动扫描所有 `.sarif` 文件） | 是 | - |
| category | 检查结果分类（用户手动传入，不传则为空） | 否 | - |
| source_path | 源码根目录（可选，逗号分隔多个）。SARIF 缺少 `region.snippet` 时按 `uri`+行号读源码补齐；不传则默认在 `ATOMGIT_WORKSPACE` 下按文件名查找 | 否 | - |
| env_type | 环境类型：`prod`（正式环境）/ `beta`（测试环境） | 否 | `prod` |

> OBS 上传与 APIG 回调所需临时凭证由插件内嵌 SDK 自动换取（OIDC ID Token 自申请 + STS 换证），无需通过本插件输入，也无需在 workflow 中运行 `huaweicloud-oidc-auth` 插件。

## 输出参数

| 参数 | 说明 |
|------|------|
| result | 上传结果：`success` 或 `failed` |

## OBS 路径规则

最终 OBS 对象键的格式为（路径前缀内置为 `code-arts-check-results`，不可配置）：

```
code-arts-check-results/{repoBaseName}/{YYYYMMDD.HH}[/{workflowRunId}]/{sarifFileName}
```

- `repoBaseName`: 从环境变量 `ATOMGIT_REPOSITORY` 或 `GIT_REPOSITORY` 提取仓库名
- 时间戳: 按执行时刻生成，精确到小时
- `workflowRunId`: 若环境变量 `ATOMGIT_RUN_ID` 存在则加入路径中，用于区分不同流水线运行
- 支持单文件或多文件（目录模式），所有 SARIF 文件统一上传到同一前缀路径

OBS 桶: `openlibing-gitcode-action`
- 写入 Endpoint: `obs.cn-southwest-2.myhuaweicloud.com`
- 读取 Endpoint: `https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com`

## 回调通知

上传成功后，插件会通过 APIG 网关向 OpenLibing 服务发送 POST 回调（`/action-api/codescan/v1/result/receive`，网关 IAM 认证），携带仓库、流水线、提交与 SARIF 下载地址等信息。

回调 payload 字段:

| 字段 | 来源 |
|------|------|
| repoUrl | `ATOMGIT_REPOSITORY_URL` |
| pipelineId | `ATOMGIT_PIPELINE_ID` |
| pipelineName | `PIPELINE_NAME` |
| pipelineRunId | `ATOMGIT_RUN_ID` |
| branch | `ATOMGIT_HEAD_REF`（MR 事件）或 `ATOMGIT_REF_NAME` |
| commitId | `ATOMGIT_SHA` |
| obsUrl | SARIF 文件下载地址（恒为数组，匹配后端 `List<String>` DTO） |
| category | 用户传入的 `category`，不传则为空 |
| source | 固定值 `GITCODE_ACTION` |
| sourceRunUrl | 根据仓库 URL 和 `ATOMGIT_RUN_ID` 拼接的 GitCode 运行链接 |

OBS 上传与 APIG 回调均内置**指数退避重试（默认 3 次）**。回调失败不影响最终结果（只输出 WARN 日志），SARIF 上传成功即视为成功。

## 使用示例

### 基础用法（单文件）

```yaml
steps:
  - name: 检出代码
    uses: checkout
    with:
      token: ${{ secrets.GC_TOKEN }}

  - name: 运行扫描工具生成 SARIF
    run: |
      # 任意可产出 SARIF 的扫描工具，如 codeql / spotbugs / gitleaks 等
      codeql database analyze ... --format=sarif-latest --output=./scan-results.sarif

  - name: 上传 SARIF 到 OpenLibing
    uses: openlibing-upload-sarif
    with:
      sarif_file: ./scan-results.sarif
      category: 'security-scan'
      env_type: beta
```

### 多 SARIF 文件（目录模式）

```yaml
  - name: 上传多个 SARIF 文件
    uses: openlibing-upload-sarif
    with:
      sarif_file: ./codeql-results/
      source_path: ./src   # 可选：源码根目录，SARIF 缺 snippet 时自动补齐代码片段
```

当 `sarif_file` 为目录时，插件会自动扫描目录下所有 `.sarif` 文件并逐一上传。

### 自动补齐代码片段（region.snippet）

部分扫描工具（如 SpotBugs）的原生 SARIF 只输出行号、不含代码文本。插件在检测到 `region` 缺少 `snippet` 时，按 `artifactLocation.uri` + `startLine(/endLine)` 从源码根目录读取对应代码行自动补齐：

- `source_path` 未配置时，默认在 `ATOMGIT_WORKSPACE` 下按文件名递归查找源码
- 已含 `region.snippet.text` 的 result 跳过，不重复处理
- 源码不可读时静默跳过，不影响上传

## 构建产物 JSON 格式

插件会在临时目录下生成 `build-result.json`，并随 SARIF 一同上传到 OBS。`type` 字段优先取自 SARIF 的 `runs[0].tool.driver.name`（如 `CodeQL`、`SpotBugs`、`Gitleaks`），解析失败则使用通用类型。

**单文件模式**（只有一个 SARIF 文件时，`buildings` 为单个对象）:

```json
{
  "type": "build",
  "buildings": {
    "name": "scan-results.sarif",
    "type": "CodeQL代码检查结果（sarif）",
    "downloadUrl": "https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com/code-arts-check-results/your-repo/20250910.14/run-123/scan-results.sarif"
  }
}
```

**多文件模式**（多个 SARIF 文件时，`buildings` 为数组）:

```json
{
  "type": "build",
  "buildings": [
    {
      "name": "codeql-java.sarif",
      "type": "CodeQL代码检查结果（sarif）",
      "downloadUrl": "https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com/code-arts-check-results/your-repo/20250910.14/run-123/codeql-java.sarif"
    },
    {
      "name": "spotbugs.sarif",
      "type": "SpotBugs代码检查结果（sarif）",
      "downloadUrl": "https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com/code-arts-check-results/your-repo/20250910.14/run-123/spotbugs.sarif"
    }
  ]
}
```

## 执行流程

1. 校验输入参数（`sarif_file`、SDK 加载状态）
2. SDK 自包含 OIDC 换证（自申请 OIDC ID Token + 调用华为云 STS 换取临时凭证）
3. 检查 SARIF 文件存在（自动尝试在 workspace 与 Git 目录中查找，支持目录模式自动扫描；文件不存在则报错退出）
4. 检查并补齐代码片段（`region.snippet` 缺失时按 `uri`+行号读源码补齐）
5. 下载并解压 `obsutil` 工具（无 SARIF 文件时跳过）
6. 根据仓库名、时间戳与 `ATOMGIT_RUN_ID` 构建 OBS 路径
7. 生成 `build-result.json` 构建产物（工具名取自 SARIF）
8. 上传构建产物与 SARIF 文件到 OBS（OIDC 临时凭证 + 公共读权限，指数退避重试 3 次）
9. 通过 APIG 回调通知 OpenLibing 服务（V11 签名 + `X-Security-Token`，指数退避重试 3 次）

## 注意事项

- 运行前需先使用 `checkout` 检出代码；Workflow 必须声明 `permissions: id-token: write` 才能申请 OIDC ID Token
- 插件内嵌 `@openlibing/huaweicloud-oidc-client` SDK 自动完成换证，**无需运行 `huaweicloud-oidc-auth` 插件**
- 前置扫描工具需产出标准 SARIF 文件，并提供 `sarif_file` 路径（文件或目录）
- 回调通知失败仅产生 WARN，不会阻断流程，最终结果以 OBS 上传是否成功为准
- OBS 桶 `openlibing-gitcode-action`、路径前缀 `code-arts-check-results`、APIG 回调地址均已硬编码在插件中，如有变更需修改源码
- 插件运行依赖 Bash 环境（使用 `shell: '/bin/bash'` 调用 `execSync`）
