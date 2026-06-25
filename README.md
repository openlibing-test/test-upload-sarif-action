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
- 支持 APIG 三种鉴权方式:AppKey/AppSecret、AppCode

## 输入参数

| 参数 | 说明 | 必填 | 默认值 |
|------|------|------|--------|
| sarif_file | SARIF 文件路径(相对路径或绝对路径) | 是 | - |
| obs_ak | OBS Access Key ID | 是 | - |
| obs_sk | OBS Secret Access Key | 是 | - |
| apig_app_key | APIG 网关 AppKey(鉴权头: `Appkey`) | 否 | - |
| apig_app_secret | APIG 网关 AppSecret(鉴权头: `AppSecret`) | 否 | - |
| apig_app_code | APIG 网关 AppCode(鉴权头: `X-Apig-AppCode`) | 否 | - |

## 输出参数

| 参数 | 说明 |
|------|------|
| result | 上传结果:`success` 或 `failed` |
| download_url | SARIF 文件在 OBS 上的下载地址 |
| build_result_url | 构建产物 JSON 在 OBS 上的下载地址 |

## OBS 路径规则

最终 OBS 对象键的格式为(路径前缀内置为 `codeql-results`,不可配置):

```
codeql-results/{repoBaseName}/{YYYYMMDD.HH}/{sarifFileName}
```

- `repoBaseName`: 从环境变量 `ATOMGIT_REPOSITORY` 或 `GIT_REPOSITORY` 提取仓库名
- 时间戳: 按执行时刻生成,精确到小时

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
| pipelineRunId | `ATOMGIT_PIPELINE_RUN_ID` / `PIPELINE_RUN_ID` |
| branch | `ATOMGIT_REF_NAME` |
| commitId | `ATOMGIT_SHA` |
| obsUrl | SARIF 文件下载地址 |

APIG 网关鉴权(按需组合):

| 输入参数 | 请求头 | 说明 |
|----------|--------|------|
| `apig_app_key` | `Appkey` | AppKey 鉴权 |
| `apig_app_secret` | `AppSecret` | 与 AppKey 配套使用 |
| `apig_app_code` | `X-Apig-AppCode` | AppCode 简单鉴权 |

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
      obs_ak: ${{ secrets.OBS_AK }}
      obs_sk: ${{ secrets.OBS_SK }}
      apig_app_key: ${{ secrets.APIG_APP_KEY }}
      apig_app_secret: ${{ secrets.APIG_APP_SECRET }}
      apig_app_code: ${{ secrets.APIG_APP_CODE }}
```

> APIG 鉴权为可选配置,若无需回调鉴权可省略 `apig_app_key` / `apig_app_secret` / `apig_app_code` 三个字段。

## 构建产物 JSON 格式

插件会在临时目录下生成 `build-result.json`,并随 SARIF 一同上传到 OBS,示例结构:

```json
{
  "type": "build",
  "buildings": [
    {
      "name": "codeql-results.sarif",
      "type": "CodeQL代码检查结果(sarif)",
      "downloadUrl": "https://openlibing-codeql.obs.cn-southwest-2.myhuaweicloud.com/codeql-results/your-repo/20250625.14/codeql-results.sarif"
    }
  ]
}
```

## 执行流程

1. 校验输入参数(`sarif_file`、`obs_ak`、`obs_sk`)
2. 检查 SARIF 文件存在(自动尝试在 workspace 与 Git 目录中查找)
3. 下载并解压 `obsutil` 工具
4. 根据仓库名与时间戳构建 OBS 路径
5. 生成 `build-result.json` 构建产物
6. 上传构建产物目录与 SARIF 文件到 OBS
7. 通过 APIG 回调通知 OpenLibing 服务

## 注意事项

- 运行前需先使用 `official_checkout` 检出代码,以便插件能从环境变量中获取仓库信息
- 需要前置执行 `codeql-action` 等可生成 SARIF 文件的步骤,并提供 `sarif_file` 路径
- 回调通知失败仅产生 WARN,不会阻断流程,最终结果以 OBS 上传是否成功为准
- OBS 桶 `openlibing-codeql`、路径前缀 `codeql-results`、APIG 回调地址均已硬编码在插件中,如有变更需修改源码
- 插件运行依赖 Bash 环境(使用 `shell: '/bin/bash'` 调用 `execSync`)

