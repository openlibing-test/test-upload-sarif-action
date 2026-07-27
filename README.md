# openlibing-upload-sarif

## 简介

将 CodeQL 扫描结果(SARIF 文件)上传到华为云 OBS 对象存储,并生成标准化的构建产物 JSON,同时通过 APIG 网关回调通知 OpenLibing 服务。

- **插件名**: `openlibing-upload-sarif`

## 功能特性

- 自动检查并定位 SARIF 文件路径(支持 workspace 和 Git 目录自动发现)
- 自动下载安装 `obsutil` 命令行工具
- 上传 SARIF 文件到 OBS 桶 `openlibing-codeql`,设置公共读权限
- 根据 SARIF 文件生成构建产物 `build-result.json`
- 通过 APIG 网关回调通知 OpenLibing 扫描服务
- 支持 APIG HMAC-SHA256 签名鉴权(AppKey/AppSecret)

## 输入参数

| 参数 | 说明 | 必填 | 默认值 |
|------|------|------|--------|
| sarif_file | SARIF 文件路径(相对路径或绝对路径),支持单个文件或目录(自动扫描目录下所有 `.sarif` 文件) | 是 | - |
| obs_ak | OBS Access Key ID | 是 | - |
| obs_sk | OBS Secret Access Key | 是 | - |
| apig_app_key | APIG 网关 AppKey(HMAC-SHA256 签名,与 AppSecret 配合使用) | 否 | - |
| apig_app_secret | APIG 网关 AppSecret(HMAC-SHA256 签名,与 AppKey 配合使用) | 否 | - |
| category | 检查结果分类(用户手动传入,不传则为空) | 否 | - |

## 输出参数

| 参数 | 说明 |
|------|------|
| result | 上传结果:`success` 或 `failed` |

## OBS 路径规则

最终 OBS 对象键的格式为(路径前缀内置为 `codeql-results`,不可配置):

```
codeql-results/{repoBaseName}/{YYYYMMDD.HH}[/{workflowRunId}]/{sarifFileName}
```

- `repoBaseName`: 从环境变量 `ATOMGIT_REPOSITORY` 或 `GIT_REPOSITORY` 提取仓库名
- 时间戳: 按执行时刻生成,精确到小时
- `workflowRunId`: 若环境变量 `workflow_run_id` 存在则加入路径中,用于区分不同流水线运行
- 支持单文件或多文件(目录模式),所有 SARIF 文件统一上传到同一前缀路径

OBS 桶: `openlibing-codeql`
- 写入 Endpoint: `obs.cn-southwest-2.myhuaweicloud.com`
- 读取 Endpoint: `https://openlibing-codeql.obs.cn-southwest-2.myhuaweicloud.com`

## 回调通知

上传成功后,插件会通过 APIG 网关向 OpenLibing 服务发送 POST 回调,携带仓库、流水线、提交与 SARIF 下载地址等信息。

回调 payload 字段:

| 字段 | 来源 |
|------|------|
| repoUrl | `ATOMGIT_REPOSITORY_URL` |
| pipelineId | `ATOMGIT_PIPELINE_ID` |
| pipelineName | `PIPELINE_NAME` |
| pipelineRunId | `workflow_run_id` 环境变量 |
| branch | `ATOMGIT_HEAD_REF` |
| commitId | `ATOMGIT_SHA` |
| obsUrl | SARIF 文件下载地址(单文件为字符串,多文件为数组) |
| category | 用户传入的 `category`,默认为空 |
| source | 固定值 `GITCODE_ACTION` |
| sourceRunUrl | 根据仓库 URL 和 `workflow_run_id` 拼接的 GitCode 运行链接 |

APIG 网关鉴权(HMAC-SHA256 签名):

| 输入参数 | 说明 |
|----------|------|
| `apig_app_key` | AppKey,作为签名 Access Key |
| `apig_app_secret` | AppSecret,作为签名密钥 |

当 `apig_app_key` 和 `apig_app_secret` 都传入时,会使用 HMAC-SHA256 方式对请求进行签名;均未传入则不签名直接发送。

执行日志中会输出当前是否携带了各 APIG 凭据(不打印明文)。回调失败不会影响最终结果(只输出 WARN 日志),SARIF 上传成功即视为成功。

## 使用示例

### 基础用法

```yaml
steps:
  - name: 检出代码
    uses: checkout
    with:
      repository: https://gitcode.com/your-org/your-repo.git
      ref: master

  - name: 运行 CodeQL 扫描
    uses: codeql-action
    with:
      language: javascript
      source-root: ./
      output-path: ./codeql-results.sarif
      query-suite: security-and-quality

  - name: 上传 SARIF 到 OpenLibing
    uses: openlibing-upload-sarif
    with:
      sarif_file: ./codeql-results.sarif
      obs_ak: ${{ secrets.OPENLIBING_OBS_AK }}
      obs_sk: ${{ secrets.OPENLIBING_OBS_SK }}
      apig_app_key: ${{ secrets.OPENLIBING_APIG_APP_KEY }}
      apig_app_secret: ${{ secrets.OPENLIBING_APIG_APP_SECRET }}
      category: 'security-scan'
```

> `apig_app_key` / `apig_app_secret` 为可选 APIG 鉴权参数,若无需签名鉴权可省略。`category` 为可选分类标签。

### 多 SARIF 文件(目录模式)

```yaml
  - name: 上传多个 SARIF 文件
    uses: openlibing-upload-sarif
    with:
      sarif_file: ./codeql-results/
      obs_ak: ${{ secrets.OPENLIBING_OBS_AK }}
      obs_sk: ${{ secrets.OPENLIBING_OBS_SK }}
```

当 `sarif_file` 为目录时,插件会自动扫描目录下所有 `.sarif` 文件并逐一上传。

## 构建产物 JSON 格式

插件会在临时目录下生成 `build-result.json`,并随 SARIF 一同上传到 OBS。

**单文件模式**(只有一个 SARIF 文件时,`buildings` 为单个对象):

```json
{
  "type": "build",
  "buildings": {
    "name": "codeql-results.sarif",
    "type": "CodeQL代码检查结果（sarif）",
    "downloadUrl": "https://openlibing-codeql.obs.cn-southwest-2.myhuaweicloud.com/codeql-results/your-repo/20250625.14/run-123/codeql-results.sarif"
  }
}
```

**多文件模式**(多个 SARIF 文件时,`buildings` 为数组):

```json
{
  "type": "build",
  "buildings": [
    {
      "name": "codeql-results-java.sarif",
      "type": "CodeQL代码检查结果（sarif）",
      "downloadUrl": "https://openlibing-codeql.obs.cn-southwest-2.myhuaweicloud.com/codeql-results/your-repo/20250625.14/run-123/codeql-results-java.sarif"
    },
    {
      "name": "codeql-results-js.sarif",
      "type": "CodeQL代码检查结果（sarif）",
      "downloadUrl": "https://openlibing-codeql.obs.cn-southwest-2.myhuaweicloud.com/codeql-results/your-repo/20250625.14/run-123/codeql-results-js.sarif"
    }
  ]
}
```

## 执行流程

1. 校验输入参数(`sarif_file`、`obs_ak`、`obs_sk`)
2. 检查 SARIF 文件存在(自动尝试在 workspace 与 Git 目录中查找,支持目录模式自动扫描)
3. 下载并解压 `obsutil` 工具
4. 根据仓库名、时间戳与 `workflow_run_id` 构建 OBS 路径
5. 生成 `build-result.json` 构建产物
6. 上传构建产物目录与 SARIF 文件到 OBS
7. 通过 APIG 回调通知 OpenLibing 服务(包含 category、source、sourceRunUrl 等字段)

## 注意事项

- 运行前需先使用 `official_checkout` 检出代码,以便插件能从环境变量中获取仓库信息
- 需要前置执行 `codeql-action` 等可生成 SARIF 文件的步骤,并提供 `sarif_file` 路径
- SARIF 文件路径支持单文件或目录模式;目录模式会自动扫描目录下所有 `.sarif` 文件
- 回调通知失败仅产生 WARN,不会阻断流程,最终结果以 OBS 上传是否成功为准
- OBS 桶 `openlibing-codeql`、路径前缀 `codeql-results`、APIG 回调地址均已硬编码在插件中,如有变更需修改源码
- 插件运行依赖 Bash 环境(使用 `shell: '/bin/bash'` 调用 `execSync`)
- `workflow_run_id` 需由调用方在 step env 中注入,用于构建 OBS 路径和回调 payload

