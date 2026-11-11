# openlibing-upload-sarif

## 简介

统一 SARIF 上传插件：将任意静态扫描工具产出的 SARIF 文件（支持单文件或目录）、华为云 CodeArts Check 代码检查报告（Markdown/原生 SARIF）或 CodeArts Check API 拉取的问题明细转换为 SARIF，上传到华为云 OBS 对象存储，并通过 APIG 网关回调通知 OpenLibing 服务。本插件已归并原 `codeArts-check-upload-sarif-action` 的能力。

- **插件名**: `openlibing-upload-sarif`
- **认证模式**: OIDC 联邦认证（免静态 AK/SK），由插件内嵌 SDK 自包含换证，无需额外运行 `huaweicloud-oidc-auth` 插件。GitCode 使用 `GitCodeActions` 身份提供商，GitHub Actions 使用 `GitHubActions` 身份提供商

> **双平台支持**：同一份 `dist/index.js` 同时适配 GitCode Actions 与 GitHub Actions，运行平台通过 `GITHUB_ACTIONS=true` 自动识别（GitHub 优先取 `GITHUB_*`，GitCode 保持 `ATOMGIT_*`）。
> GitHub 侧只需在 workflow 中声明 `permissions: id-token: write`，无需配置 AK/SK。

## GitHub Actions 接入

```yaml
name: scan-and-upload

on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write # OIDC 免密换证必需

jobs:
  upload-sarif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: 运行扫描工具生成 SARIF
        run: |
          # 任意可产出 SARIF 的扫描工具
          clang-tidy ... > sarif/clang-tidy.sarif

      - name: 上传 SARIF 到 OpenLibing
        uses: openlibing-test/upload-sarif-action@main
        with:
          sarif_file: sarif/clang-tidy.sarif
          source_path: .
          category: business
          env_type: beta
```

GitHub 平台下 `source` 上报 `GITHUB_ACTION`（后端已支持该枚举），`repoUrl` 由 `GITHUB_SERVER_URL` + `GITHUB_REPOSITORY` 拼装，`sourceRunUrl` 为对应 Actions 运行页链接。

### 双平台环境变量映射

| 用途            | GitCode Actions                              | GitHub Actions                                   | 说明                                  |
| --------------- | -------------------------------------------- | ------------------------------------------------ | ------------------------------------- |
| 平台识别        | -                                            | `GITHUB_ACTIONS=true`                            | 命中 GitHub 分支，否则按 GitCode 处理 |
| OIDC 身份提供商 | `GitCodeActions`（SDK 默认）                 | `GitHubActions`（插件内 `configure()` 覆盖）     | 需与华为云 IAM 侧注册名一致           |
| OBS 桶          | `OBS_BUCKET` / `openlibing-gitcode-action`   | `OBS_BUCKET_GITHUB` / `openlibing-github-action` | 两平台结果物理隔离                    |
| OBS 读端点      | `OBS_READ_ENDPOINT`（默认 GitCode 桶域名）   | 默认 GitHub 桶域名                               | 两者均可由 `OBS_READ_ENDPOINT` 覆盖   |
| 仓库地址        | `ATOMGIT_REPOSITORY_URL`                     | `GITHUB_SERVER_URL` + `GITHUB_REPOSITORY`        | 回调 `repoUrl`                        |
| 仓库名          | `ATOMGIT_REPOSITORY` / `GIT_REPOSITORY`      | `GITHUB_REPOSITORY`                              | 取 `/` 最后一段作为 OBS 路径仓库名    |
| 流水线 ID       | `ATOMGIT_PIPELINE_ID`                        | `GITHUB_JOB`                                     | 后端 `pipelineId` 为必填              |
| 流水线名称      | `PIPELINE_NAME`                              | `GITHUB_WORKFLOW`                                | 回调 `pipelineName`                   |
| 运行 ID         | `ATOMGIT_RUN_ID`                             | `GITHUB_RUN_ID`                                  | 回调 `pipelineRunId` 与 OBS 路径      |
| 分支            | `ATOMGIT_HEAD_REF`（MR）/ `ATOMGIT_REF_NAME` | `GITHUB_BASE_REF`（PR）/ `GITHUB_REF_NAME`       | 回调 `branch`                         |
| 提交 ID         | `ATOMGIT_SHA`                                | `GITHUB_SHA`                                     | 回调 `commitId`                       |
| 工作区          | `WORKSPACE`                                  | `GITHUB_WORKSPACE`                               | 未设置时回退 `process.cwd()`          |
| 输出文件        | `STEP_OUTPUT`                                | `GITHUB_OUTPUT`                                  | 插件优先读 `GITHUB_OUTPUT`            |
| 来源标记        | `GITCODE_ACTION`                             | `GITHUB_ACTION`                                  | 回调 `source`                         |

## 功能特性

- **三数据源**（可并存，均转换为 SARIF 后统一上传）：
  1. `report_file`：本地 CodeArts 代码检查报告（Markdown `.md/.markdown`）或 CodeArts 原生导出的 SARIF（`.sarif`），支持通配符/目录/逗号分隔多值
  2. `codecheck_task_url`（+ CodeArts Check API）：从 `codecheck_gitcode_v2` 步骤输出的任务 URL 解析 `project_id/task_id/region/jobId`，通过 CodeArts Check API 分页拉取问题明细并生成 SARIF（凭证优先 runner 注入的 `CODEARTS_IAM_AK/SK`，缺失时兜底 OIDC 临时凭证）
  3. `sarif_file`：本地任意工具的 SARIF 文件（单文件/多文件/目录），不绑定具体扫描工具
- 自动识别 SARIF 文件中的工具名（`runs[0].tool.driver.name`）用于构建产物类型，后端按 `tool.driver.name` 路由
- CodeArts 原生 SARIF 自动规范化：工具名 `"CodeArts Check"`（带空格）统一改写为 `"CodeArtsCheck"`，并为缺失 `partialFingerprints.primaryLocationLineHash` 的结果补齐指纹（保证问题可入库）
- 自动补齐代码片段：`region.snippet` 对齐为问题行本身源码（前端定位高亮），`contextRegion` 补上下各 2 行上下文窗口（前端展示），提升后端告警可读性
- OIDC 免静态凭证：插件内嵌 `@openlibing/huaweicloud-oidc-client` SDK，自申请 OIDC ID Token 并调用华为云 STS 换证，OBS 上传与 APIG 回调全程使用临时凭证
- 内嵌 `esdk-obs-nodejs` SDK 上传 OBS，上传对象默认私有（不设置 ACL，后端凭平台凭证下载）
- 通过 APIG 网关回调通知 OpenLibing 扫描服务（V11-HMAC-SHA256 签名 + `X-Security-Token`）
- 失败重试：OBS 上传与 APIG 回调均采用**指数退避重试（默认 3 次）**，降低网络抖动导致的数据丢失风险

## 前置要求

Workflow 只需声明 `permissions: id-token: write`。插件内嵌 `@openlibing/huaweicloud-oidc-client` SDK 会自动向流水线申请 OIDC ID Token 并调用华为云 STS 换取临时凭证，**无需再运行 `huaweicloud-oidc-auth` 插件**：

```yaml
permissions:
  id-token: write
```

> 使用 CodeArts Check API 数据源时，若 runner 已注入 `CODEARTS_IAM_AK/SK` 则优先使用（老方式）；否则自动兜底使用 OIDC 换取的临时凭证调用 API。

## 输入参数

| 参数               | 说明                                                                                                                                                                         | 必填 | 默认值 |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ------ |
| report_file        | CodeArts 代码检查结果路径：Markdown 报告（`.md/.markdown`）或 CodeArts 原生导出的 SARIF（`.sarif`），支持通配符/目录/逗号分隔多值；不传时可直接走 `codecheck_task_url` + API | 否   | -      |
| sarif_file         | 本地任意工具的 SARIF 文件/目录路径（逗号分隔多值，目录自动扫描其中所有 `.sarif` 文件，非递归）                                                                               | 否   | -      |
| codecheck_task_url | `codecheck_gitcode_v2` 步骤输出的 `codeCheck_task_url`，从中解析 `project_id/task_id/region/jobId`，未显式配置 `project_id/task_id` 时兜底使用                               | 否   | -      |
| project_id         | CodeArts 项目 ID（可通过 `codecheck_task_url` 自动解析）                                                                                                                     | 否   | -      |
| task_id            | CodeArts 检查任务 ID（可通过 `codecheck_task_url` 自动解析）                                                                                                                 | 否   | -      |
| task_name          | CodeArts 检查任务名（可选，仅用于 SARIF 文件名与日志显示；任务定位请使用 `task_id` 或 `codecheck_task_url`）                                                                 | 否   | -      |
| region             | CodeArts 区域（优先此参数，其次 `codecheck_task_url` 解析，再从环境变量 `CODEARTS_REGION` 等读取，最后默认 `cn-north-4`）                                                    | 否   | -      |
| category           | 检查结果分类（用户手动传入，不传则为空）                                                                                                                                     | 否   | -      |
| source_path        | 源码根目录（可选，逗号分隔多个）。SARIF 缺少 `region.snippet` 时按 `uri`+行号读源码补齐；不传则默认在工作区（`WORKSPACE` / `GITHUB_WORKSPACE`）下按文件名查找                | 否   | -      |
| env_type           | 环境类型：`prod`（正式环境）/ `beta`（测试环境）                                                                                                                             | 否   | `prod` |

> 至少配置三种数据源之一（`report_file` / `sarif_file` / `codecheck_task_url`+API 参数），可同时配置并存使用。
>
> OBS 上传与 APIG 回调所需临时凭证由插件内嵌 SDK 自动换取（OIDC ID Token 自申请 + STS 换证），无需通过本插件输入，也无需在 workflow 中运行 `huaweicloud-oidc-auth` 插件。

## 输出参数

| 参数   | 说明                            |
| ------ | ------------------------------- |
| result | 上传结果：`success` 或 `failed` |

## OBS 路径规则

OBS 对象键的格式为（路径前缀按工具名动态拼装，与 pre-commit-action 的 `pre-commit-results` 前缀共用同一路径结构）：

```
{toolPrefix}/{repoBaseName}/{YYYYMMDD.HH}/{workflowRunId|manual}/{sarifFileName}
```

- `toolPrefix`: 根据每个 SARIF 的 `runs[0].tool.driver.name` 动态生成（如 `spotbugs-results`、`codeartscheck-results`）；工具名无法解析时兜底为 `code-arts-check-results`
- `repoBaseName`: 优先取 `ATOMGIT_REPOSITORY`，GitHub 用 `GITHUB_REPOSITORY`，再兜底 `GIT_REPOSITORY`，取 `/` 最后一段作为仓库名
- 时间戳: 按执行时刻生成，精确到小时（`yyyyMMdd.HH`，与 pre-commit-action 一致）
- `workflowRunId`: GitCode 取 `ATOMGIT_RUN_ID`，GitHub 取 `GITHUB_RUN_ID`；缺失时用 `manual` 兜底，保证路径层级固定
- 每个 SARIF 文件按其自身工具名独立拼装前缀（多工具上传时各自归位到对应前缀）

OBS 桶按平台隔离：GitCode 为 `openlibing-gitcode-action`，GitHub 为 `openlibing-github-action`（分别可用 `OBS_BUCKET` / `OBS_BUCKET_GITHUB` 覆盖）。

- 写入 Endpoint: 由 OIDC SDK `configure()` 动态返回 region 拼装 `https://obs.{region}.myhuaweicloud.com`（与 pre-commit-action 一致，不写死区域）
- 读取 Endpoint: 默认与使用中的桶一致（`https://{bucket}.obs.cn-southwest-2.myhuaweicloud.com`），可用 `OBS_READ_ENDPOINT` 覆盖

## 回调通知

上传成功后，插件会通过 APIG 网关向 OpenLibing 服务发送 POST 回调（`/action-api/codescan/v1/result/receive`，网关 IAM 认证），携带仓库、流水线、提交与 SARIF 下载地址等信息。

回调 payload 字段:

| 字段          | GitCode Actions                                             | GitHub Actions                                                                       |
| ------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| repoUrl       | `ATOMGIT_REPOSITORY_URL`                                    | `GITHUB_SERVER_URL` + `GITHUB_REPOSITORY`                                            |
| pipelineId    | `ATOMGIT_PIPELINE_ID`                                       | `GITHUB_JOB`                                                                         |
| pipelineName  | `PIPELINE_NAME`                                             | `GITHUB_WORKFLOW`                                                                    |
| pipelineRunId | `ATOMGIT_RUN_ID`                                            | `GITHUB_RUN_ID`                                                                      |
| branch        | `ATOMGIT_HEAD_REF`（MR）/ `ATOMGIT_REF_NAME`                | `GITHUB_BASE_REF`（PR）/ `GITHUB_REF_NAME`                                           |
| commitId      | `ATOMGIT_SHA`                                               | `GITHUB_SHA`                                                                         |
| obsUrl        | SARIF 文件下载地址（恒为数组，匹配后端 `List<String>` DTO） | 同左                                                                                 |
| category      | 用户传入的 `category`，不传则为空                           | 同左                                                                                 |
| source        | 固定值 `GITCODE_ACTION`                                     | 固定值 `GITHUB_ACTION`                                                               |
| sourceRunUrl  | 根据仓库 URL 和 `ATOMGIT_RUN_ID` 拼接的 GitCode 运行链接    | 根据 `GITHUB_SERVER_URL`/`GITHUB_REPOSITORY`/`GITHUB_RUN_ID` 拼接的 Actions 运行链接 |

OBS 上传与 APIG 回调均内置**指数退避重试（默认 3 次）**。回调失败不影响最终结果（只输出 WARN 日志），SARIF 上传成功即视为成功。

## 使用示例

### 数据源一：任意工具 SARIF 文件上传（原 `sarif_file` 能力）

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
      category: "security-scan"
      env_type: beta
```

### 数据源二：CodeArts Check API（`codecheck_task_url` 自动解析参数）

`codecheck_gitcode_v2` 步骤的 `outputs.codeCheck_task_url` 可直接作为输入，插件自动解析 `project_id/task_id/region/jobId` 并从 CodeArts Check API 拉取问题明细：

```yaml
steps:
  - name: CodeArts 代码检查
    id: codecheck
    uses: codecheck_gitcode_v2
    with: ...
  - name: 上传 CodeArts 检查结果到 OpenLibing
    uses: openlibing-upload-sarif
    with:
      codecheck_task_url: ${{ steps.codecheck.outputs.codeCheck_task_url }}
      env_type: beta
```

也可显式传入 `project_id` / `task_id`（无需 `codecheck_task_url`），或二者并用（显式参数优先）：

```yaml
- name: 上传 CodeArts 检查结果
  uses: openlibing-upload-sarif
  with:
    project_id: <project-id>
    task_id: <task-id>
    task_name: my-check-task # 可选，仅用于 SARIF 文件名
    region: cn-north-4 # 可选，默认 cn-north-4
```

### 数据源三：CodeArts 检查报告文件（`report_file`）

适用于已有 CodeArts 输出的 Markdown 报告或原生 SARIF（如 `step_summary_*.md`）：

```yaml
- name: 上传 CodeArts 报告
  uses: openlibing-upload-sarif
  with:
    report_file: ./step_summary_*.md
    env_type: beta
```

`report_file` 也支持目录与逗号分隔多值；`.md` 走 Markdown 解析转 SARIF，`.sarif` 走原生规范化。

### 多 SARIF 文件（目录模式）

```yaml
- name: 上传多个 SARIF 文件
  uses: openlibing-upload-sarif
  with:
    sarif_file: ./codeql-results/
    source_path: ./src # 可选：源码根目录，SARIF 缺 snippet 时自动补齐代码片段
```

当 `sarif_file` 为目录时，插件会自动扫描目录下所有 `.sarif` 文件并逐一上传。

### 自动补齐代码片段（region.snippet / contextRegion）

部分扫描工具（如 SpotBugs）的原生 SARIF 只输出行号、不含代码文本；部分工具（如 CodeArts Check）虽自带 snippet 但内容可能与源码不一致。插件按 `artifactLocation.uri` + `startLine(/endLine)` 从源码根目录读取源码补齐：

- `region.snippet`：对齐为**问题行本身**（或多行问题范围）的实际源码，供前端做内容匹配定位高亮行；工具自带 snippet 与文件实际内容不一致时也会被覆盖
- `contextRegion.snippet`：问题行（或多行范围）**上下各 2 行**的上下文窗口，供前端展示上下文；工具自带的不同窗口也会被覆盖为统一窗口，前端展示固定 5 行
- `source_path` 未配置时，默认在工作区（`WORKSPACE` / `GITHUB_WORKSPACE`）下按文件名递归查找源码
- 源码不可读时静默跳过，不影响上传

## 执行流程

1. 校验输入参数（三种数据源至少配置其一、SDK 加载状态）
2. SDK 自包含 OIDC 换证（自申请 OIDC ID Token + 调用华为云 STS 换取临时凭证）
3. 收集并生成 SARIF：`report_file`（Markdown 解析 / 原生 SARIF 规范化）→ CodeArts Check API 兜底拉取（`codecheck_task_url` 或显式 `project_id`+`task_id`）→ `sarif_file`（本地 SARIF 收集，支持目录模式）
4. 检查并补齐代码片段（`region.snippet` 对齐问题行、`contextRegion` 补上下文窗口）
5. 根据仓库名、时间戳与运行 ID（`ATOMGIT_RUN_ID` / `GITHUB_RUN_ID`）构建 OBS 路径
6. 上传 SARIF 文件到 OBS（OIDC 临时凭证 + 对象默认私有，指数退避重试 3 次）
7. 通过 APIG 回调通知 OpenLibing 服务（V11 签名 + `X-Security-Token`，指数退避重试 3 次）

## 注意事项

- 运行前需先使用 `checkout` 检出代码；Workflow 必须声明 `permissions: id-token: write` 才能申请 OIDC ID Token
- 插件内嵌 `@openlibing/huaweicloud-oidc-client` SDK 自动完成换证，**无需运行 `huaweicloud-oidc-auth` 插件**
- 使用 CodeArts Check API 数据源时优先使用 runner 注入的 `CODEARTS_IAM_AK/SK`（defects-detail 接口暂不支持 OIDC 调用），缺失时兜底 OIDC 临时凭证
- 三种数据源（`report_file` / `codecheck_task_url`+API / `sarif_file`）可并存，统一转换为 SARIF 后上传
- 回调通知失败仅产生 WARN，不会阻断流程，最终结果以 OBS 上传是否成功为准
- OBS 桶按平台自动选择（GitCode `openlibing-gitcode-action` / GitHub `openlibing-github-action`）、路径前缀拼装规则（`{toolName}-results`，兜底 `code-arts-check-results`）、APIG 回调地址均已内置在插件中，如有变更需修改源码
- 插件运行依赖 Bash 环境（使用 `shell: '/bin/bash'` 调用 `execSync`）
