'use strict';

const { installFetchPolyfill } = require('./src/util/fetchPolyfill');
// GitCode 插件 runtime 为 node16，无全局 fetch；注入最小 polyfill，否则
// OIDC SDK 会回退 require('undici') 导致 "Cannot find module 'undici'"。
installFetchPolyfill();

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// OIDC 签名 SDK：APIG V11-HMAC-SHA256 签名 + HTTPS 请求。
// 临时凭证（HUAWEICLOUD_OIDC_AK / HUAWEICLOUD_OIDC_SK / HUAWEICLOUD_SECURITY_TOKEN）
// 由官方 huaweicloud-oidc-auth 插件在 workflow 中注入环境变量，本插件不管理凭证。
let V11Signer = null;
let sendRequest = null;
try {
  ({ V11Signer, sendRequest } = require('@openlibing/huaweicloud-oidc-client'));
} catch (e) {
  console.log('[ERROR] @openlibing/huaweicloud-oidc-client 加载失败，请重新构建 dist 后重试');
}

// ---------- 常量 ----------

const APIG_SIGN_REGION = 'cn-southwest-2'; // APIG V11 签名区域
const OIDC_API_PREFIX = '/action-api'; // OIDC 回调路径前缀（网关 IAM 认证）
const CALLBACK_PATH = '/codescan/v1/result/receive';
// beta.apig.openlibing.com 已确认 DNS 指向华为云 APIG，但证书尚未绑定该域名
// （TLS 握手返回 *.apic.cn-southwest-2.huaweicloudapis.com 默认证书）。
// 当前临时使用已发布 /action-api 接口的 APIG 域名，保证链路可测；平台绑定证书后应切回该域名。
const OIDC_PROD_BASE = 'https://apig.openlibing.com';
const OIDC_BETA_BASE = 'https://174e1b821a8446f38998a67186ba766e.apic.cn-southwest-2.huaweicloudapis.com';

// OBS：通用 SARIF 结果统一存放（后端 SarifParseServiceImpl 匿名 HTTP GET 下载）
const OBS_KEY_ROOT = 'code-arts-check-results';
const OBS_BUCKET = 'openlibing-gitcode-action';
const OBS_WRITE_ENDPOINT = 'obs.cn-southwest-2.myhuaweicloud.com';
const OBS_READ_ENDPOINT = 'https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com';

const SARIF_EXT = '.sarif';

// ---------- 通用辅助 ----------

function getInput(name) {
  return (process.env[`INPUT_${name.toUpperCase()}`] || '').trim();
}

function setOutput(key, value) {
  const stepOutput = process.env.STEP_OUTPUT;
  if (!stepOutput) {
    console.log(`[WARN] STEP_OUTPUT env not set, skip output: ${key}=${value}`);
    return;
  }
  let filePath;
  try {
    filePath = fs.statSync(stepOutput).isDirectory() ? path.join(stepOutput, 'output') : stepOutput;
  } catch (e) {
    // 文件不存在但父目录有效时按文件路径追加（appendFileSync 自动创建）
    const parentDir = path.dirname(stepOutput);
    if (!(fs.existsSync(parentDir) && fs.statSync(parentDir).isDirectory())) {
      console.log(`[WARN] STEP_OUTPUT path is invalid, skip output: ${key}=${value}`);
      return;
    }
    filePath = stepOutput;
  }
  fs.appendFileSync(filePath, `${key}=${value}\n`, 'utf-8');
  console.log(`[OUTPUT] ${key}=${value}`);
}

function exec(cmd) {
  console.log(`> ${cmd}`);
  execSync(cmd, { stdio: 'inherit', shell: '/bin/bash' });
}

function execCapture(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf-8', shell: '/bin/bash' }).trim();
  } catch (e) {
    return '';
  }
}

/** 执行 obsutil 命令，日志对 AK/SK/SecurityToken（-i=/-k=/-t=）脱敏，避免临时凭证落日志 */
function execObsutil(cmd) {
  const masked = cmd.replace(/(-i="[^"]*"|-k="[^"]*"|-t="[^"]*")/g, (m) => m.split('=')[0] + '="***"');
  console.log(`> ${masked}`);
  execSync(cmd, { stdio: 'inherit', shell: '/bin/bash' });
}

/** 日志脱敏：IP 地址替换为占位符 */
function sanitizePath(pathStr) {
  return pathStr.replace(/(\d+\.\d+\.\d+\.\d+)/g, '[IP_ADDRESS]');
}

// ---------- OIDC 回调 ----------

/**
 * OIDC 回调：用官方 huaweicloud-oidc-auth 插件注入的临时凭证对 APIG 请求做
 * V11-HMAC-SHA256 签名 + X-Security-Token 后上报（网关 IAM 认证，免静态凭证）。
 * @param {string} url APIG 回调地址
 * @param {Object} payload 回调报文
 * @returns {Promise<Object>} 响应体（code=200/0 视为成功）
 */
async function sendCallbackOidc(url, payload) {
  if (!V11Signer || !sendRequest) {
    throw new Error('@openlibing/huaweicloud-oidc-client 未加载，无法进行 OIDC 回调');
  }
  const ak = process.env.HUAWEICLOUD_OIDC_AK || '';
  const sk = process.env.HUAWEICLOUD_OIDC_SK || '';
  const token = process.env.HUAWEICLOUD_SECURITY_TOKEN || '';

  const signer = new V11Signer({ region: APIG_SIGN_REGION });
  signer.Key = ak;
  signer.Secret = sk;
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['X-Security-Token'] = token;

  const body = JSON.stringify(payload);
  const signedHeaders = signer.sign('POST', url, headers, body);
  const res = await sendRequest('POST', url, signedHeaders, body);

  const data = res.data;
  if (res.status < 200 || res.status >= 300) {
    throw new Error((data && (data.msg || data.message || data.error_msg)) || `HTTP ${res.status}`);
  }
  if (data && (data.code === 200 || data.code === 0)) {
    return data;
  }
  throw new Error(`API 业务错误: code=${data && data.code}, msg=${data && (data.msg || data.message) || 'unknown'}`);
}

// ---------- 主流程辅助 ----------

/** 构造 Actions 运行页 URL：https://gitcode.com/{owner}/{repo}/actions/runs/{runId} */
function buildSourceRunUrl() {
  const repoUrl = (process.env.ATOMGIT_REPOSITORY_URL || '').trim();
  const runId = process.env.ATOMGIT_RUN_ID || '';
  if (!repoUrl || !runId) return '';
  let httpsBase = repoUrl;
  const sshMatch = httpsBase.match(/^git@([^:]+):(.+)$/);
  if (sshMatch) {
    httpsBase = `https://${sshMatch[1]}/${sshMatch[2]}`;
  } else if (/^ssh:\/\//i.test(httpsBase)) {
    httpsBase = httpsBase.replace(/^ssh:\/\/[^@/]+@?/i, 'https://');
  }
  return `${httpsBase.replace(/\.git$/, '')}/actions/runs/${runId}`;
}

/** 回调分支：MR 事件用目标分支（ATOMGIT_HEAD_REF），其他事件用当前 ref */
function resolveBranch() {
  const eventName = (process.env.ATOMGIT_EVENT_NAME || '').toLowerCase();
  return eventName === 'mr'
    ? (process.env.ATOMGIT_HEAD_REF || '')
    : (process.env.ATOMGIT_REF_NAME || '');
}

/** 下载并解压 obsutil（优先 wget，失败回退 curl），返回可执行文件路径 */
function installObsutil() {
  const tmpDir = os.tmpdir();
  exec(`wget -q https://obs-community.obs.cn-north-1.myhuaweicloud.com/obsutil/current/obsutil_linux_amd64.tar.gz -O ${tmpDir}/obsutil_linux_amd64.tar.gz 2>/dev/null || curl -sL https://obs-community.obs.cn-north-1.myhuaweicloud.com/obsutil/current/obsutil_linux_amd64.tar.gz -o ${tmpDir}/obsutil_linux_amd64.tar.gz`);
  exec(`cd ${tmpDir} && tar zxf obsutil_linux_amd64.tar.gz --strip-components=1 2>/dev/null || true`);
  exec(`chmod 755 ${tmpDir}/obsutil 2>/dev/null || true`);
  const obsutilPath = execCapture(`which obsutil 2>/dev/null || find ${tmpDir} -name "obsutil" -type f 2>/dev/null | head -1`);
  if (!obsutilPath) {
    throw new Error('obsutil 安装失败');
  }
  console.log(`[OK] obsutil 路径: ${obsutilPath}`);
  return obsutilPath;
}

/** 将 OIDC 临时凭证写入 obsutil 独立配置文件，返回上传命令的鉴权参数 */
function writeObsutilConfig(obsutilPath, oidcAk, oidcSk, oidcToken) {
  const configPath = path.join(os.tmpdir(), 'obsutil-oidc-config');
  try {
    exec(`touch ${configPath}`); // -config= 指向的文件必须已存在（obsutil 只更新不创建）
    execObsutil(`${obsutilPath} config -i="${oidcAk}" -k="${oidcSk}" -t="${oidcToken}" -e="${OBS_WRITE_ENDPOINT}" -config="${configPath}"`);
  } catch (err) {
    console.log(`[ERROR] 写入 obsutil 配置文件失败: ${err.message}`);
    setOutput('result', 'failed');
    process.exit(1);
  }
  return `-config="${configPath}"`;
}

/** 从 SARIF 文件提取工具名（runs[0].tool.driver.name），用于构建产物类型；解析失败返回空 */
function extractToolName(sarifFile) {
  try {
    const data = JSON.parse(fs.readFileSync(sarifFile, 'utf-8'));
    const name = data && data.runs && data.runs[0] && data.runs[0].tool &&
      data.runs[0].tool.driver && data.runs[0].tool.driver.name;
    return name ? String(name).trim() : '';
  } catch (e) {
    return '';
  }
}

// ---------- 主流程 ----------

async function run() {
  const sarifFile = getInput('sarif_file');
  const category = getInput('category');
  const envType = (getInput('env_type') || 'prod').toLowerCase();
  const isBetaEnv = envType === 'beta';
  const workflowRunId = process.env.ATOMGIT_RUN_ID || '';

  // OIDC 临时凭证：由官方 huaweicloud-oidc-auth 插件写入环境变量（APIG 回调 / OBS 上传必须）
  const oidcAk = process.env.HUAWEICLOUD_OIDC_AK || '';
  const oidcSk = process.env.HUAWEICLOUD_OIDC_SK || '';
  const oidcToken = process.env.HUAWEICLOUD_SECURITY_TOKEN || '';

  const callbackUrl = (isBetaEnv ? OIDC_BETA_BASE : OIDC_PROD_BASE) + OIDC_API_PREFIX + CALLBACK_PATH;

  console.log('===== openlibing-upload-sarif 启动 =====');
  console.log(`[INFO] 环境类型: ${isBetaEnv ? 'beta (测试环境)' : 'prod (正式环境)'}`);
  console.log('[INFO] 认证模式: OIDC 联邦认证（凭证由 huaweicloud-oidc-auth 插件提供）');
  console.log(`[INFO] 回调地址: ${callbackUrl}`);

  console.log('\n===== [1] 校验参数 =====');
  if (!sarifFile) {
    console.log('[ERROR] sarif_file 参数不能为空');
    setOutput('result', 'failed');
    process.exit(1);
  }
  const missingInputs = [];
  if (!oidcAk || !oidcSk) {
    missingInputs.push('OIDC 临时凭证（请先在 workflow 运行 huaweicloud-oidc-auth 插件）');
  }
  if (missingInputs.length > 0) {
    console.log(`[ERROR] 缺少必要的参数: ${missingInputs.join(', ')}`);
    setOutput('result', 'failed');
    process.exit(1);
  }
  if (!V11Signer || !sendRequest) {
    console.log('[ERROR] @openlibing/huaweicloud-oidc-client 加载失败，无法进行 OIDC 签名回调');
    setOutput('result', 'failed');
    process.exit(1);
  }
  console.log('[OK] 参数校验通过');

  console.log('\n===== [2] 检查 SARIF 文件 =====');
  const workspace = process.env.WORKSPACE || process.cwd();
  let resolvedSarifPath = sarifFile;
  if (!fs.existsSync(resolvedSarifPath)) {
    resolvedSarifPath = path.join(workspace, sarifFile);
  }
  if (!fs.existsSync(resolvedSarifPath)) {
    const gitDir = execCapture(`find ${workspace} -maxdepth 3 -name ".git" -type d 2>/dev/null | head -1`);
    if (gitDir) {
      resolvedSarifPath = path.join(path.dirname(gitDir), sarifFile);
    }
  }
  if (!fs.existsSync(resolvedSarifPath)) {
    console.log(`[ERROR] SARIF 路径不存在: ${sarifFile}`);
    setOutput('result', 'failed');
    process.exit(1);
  }

  let sarifFiles = [];
  const isDir = fs.statSync(resolvedSarifPath).isDirectory();
  if (isDir) {
    console.log(`[INFO] 输入为目录: ${resolvedSarifPath}，扫描所有 .sarif 文件`);
    const entries = fs.readdirSync(resolvedSarifPath);
    for (const entry of entries) {
      if (entry.toLowerCase().endsWith(SARIF_EXT)) {
        sarifFiles.push(path.join(resolvedSarifPath, entry));
      }
    }
    if (sarifFiles.length === 0) {
      console.log(`[ERROR] 目录中未找到 .sarif 文件: ${resolvedSarifPath}`);
      setOutput('result', 'failed');
      process.exit(1);
    }
    console.log(`[OK] 找到 ${sarifFiles.length} 个 SARIF 文件:`);
    sarifFiles.forEach(f => console.log(`  - ${path.basename(f)}`));
  } else {
    sarifFiles = [resolvedSarifPath];
    console.log(`[OK] SARIF 文件: ${resolvedSarifPath}`);
  }

  console.log('\n===== [3] 安装 obsutil =====');
  let obsutilPath;
  try {
    obsutilPath = installObsutil();
  } catch (err) {
    console.log(`[ERROR] ${err.message}`);
    setOutput('result', 'failed');
    process.exit(1);
  }

  console.log('\n===== [4] 构建 OBS 路径 =====');
  const repoBaseName = (process.env.ATOMGIT_REPOSITORY || process.env.GIT_REPOSITORY || '').split('/').pop() || 'unknown-repo';
  const now = new Date();
  const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}.${String(now.getHours()).padStart(2, '0')}`;
  const obsKeyPrefix = `${OBS_KEY_ROOT}/${repoBaseName}/${dateStr}${workflowRunId ? '/' + workflowRunId : ''}`;
  const downloadUrlPrefix = `${OBS_READ_ENDPOINT}/${obsKeyPrefix}`;
  console.log(`[INFO] OBS 路径: obs://${OBS_BUCKET}/${obsKeyPrefix}/`);
  console.log(`[INFO] 下载前缀: ${downloadUrlPrefix}`);

  console.log('\n===== [5] 生成构建产物 JSON =====');
  const buildResultDir = path.join(os.tmpdir(), 'sarif-analyze-output');
  if (!fs.existsSync(buildResultDir)) {
    fs.mkdirSync(buildResultDir, { recursive: true });
  }

  const sarifDownloadUrls = sarifFiles.map(f => `${downloadUrlPrefix}/${path.basename(f)}`);
  const sarifBuildings = sarifFiles.map((f, i) => {
    const toolName = extractToolName(f);
    return {
      name: path.basename(f),
      // 通用 SARIF：优先取工具名（runs[0].tool.driver.name），后端按 tool.driver.name 路由
      type: toolName ? `${toolName}代码检查结果（sarif）` : 'SARIF代码检查结果（sarif）',
      downloadUrl: sarifDownloadUrls[i]
    };
  });

  const isSingleFile = sarifFiles.length === 1;
  const buildResult = {
    type: 'build',
    buildings: isSingleFile ? sarifBuildings[0] : sarifBuildings
  };
  const buildResultPath = path.join(buildResultDir, 'build-result.json');
  fs.writeFileSync(buildResultPath, JSON.stringify(buildResult, null, 2), 'utf-8');

  console.log('\n===== [6] 上传到 OBS =====');
  const obsAuthArgs = writeObsutilConfig(obsutilPath, oidcAk, oidcSk, oidcToken);

  console.log('[INFO] 上传构建产物文件: build-result.json');
  try {
    // -acl=public-read：后端 SarifParseServiceImpl 通过匿名 HTTP GET 下载，对象必须公共读
    execObsutil(`${obsutilPath} cp "${buildResultPath}" "obs://${OBS_BUCKET}/${obsKeyPrefix}/build-result.json" -f -acl=public-read -e="${OBS_WRITE_ENDPOINT}" ${obsAuthArgs}`);
  } catch (e1) {
    console.log(`[WARN] 构建产物文件上传失败: ${e1.message}`);
  }

  for (let i = 0; i < sarifFiles.length; i++) {
    const sarifPath = sarifFiles[i];
    const sarifName = path.basename(sarifPath);
    console.log(`[INFO] 上传 SARIF 文件 (${i + 1}/${sarifFiles.length}): ${sarifName}`);
    try {
      // -acl=public-read：后端 SarifParseServiceImpl 通过匿名 HTTP GET 下载，对象必须公共读
      execObsutil(`${obsutilPath} cp "${sarifPath}" "obs://${OBS_BUCKET}/${obsKeyPrefix}/" -f -acl=public-read -e="${OBS_WRITE_ENDPOINT}" ${obsAuthArgs}`);
    } catch (e2) {
      console.log(`[ERROR] ${sarifName} 上传失败: ${e2.message}`);
      console.log('[INFO] 检查 obsutil 错误详情:');
      try {
        exec(`cat /home/octopus/.obsutil_output/*.log 2>/dev/null | tail -50`);
      } catch (_) {}
      setOutput('result', 'failed');
      process.exit(1);
    }
  }

  const obsUrlValue = isSingleFile ? sarifDownloadUrls[0] : sarifDownloadUrls;

  console.log('\n================================================================');
  console.log('[INFO] 上传成功');
  console.log('================================================================');

  console.log('\n===== [7] 回调通知 =====');
  const callbackPayload = {
    repoUrl: process.env.ATOMGIT_REPOSITORY_URL || '',
    pipelineId: process.env.ATOMGIT_PIPELINE_ID || '',
    pipelineName: process.env.PIPELINE_NAME || '',
    pipelineRunId: workflowRunId || '',
    branch: resolveBranch(),
    commitId: process.env.ATOMGIT_SHA || '',
    // 后端 DTO 为 List<String>，恒传数组兼容新旧后端（旧版无 StringOrListDeserializer）
    obsUrl: Array.isArray(obsUrlValue) ? obsUrlValue : [obsUrlValue],
    category: category || '',
    source: 'GITCODE_ACTION',
    sourceRunUrl: buildSourceRunUrl() || ''
  };

  try {
    const callbackResult = await sendCallbackOidc(callbackUrl, callbackPayload);
    console.log(`[OK] 回调通知发送成功，回调时间: ${new Date().toISOString()}`);
    console.log(`[INFO] 回调响应: ${JSON.stringify(callbackResult)}`);
    const resultViewUrl = isBetaEnv ? 'https://beta.openlibing.com/apps/codeCheck' : 'https://www.openlibing.com/apps/codeCheck';
    console.log(`查看上传结果解析: ${resultViewUrl}`);
  } catch (cbErr) {
    console.log(`[WARN] 回调通知发送失败: ${cbErr.message}`);
    console.log('[INFO] SARIF 上传已成功，回调失败不影响最终结果');
  }

  setOutput('result', 'success');
}

module.exports = { run };

if (require.main === module) {
  run().catch(err => {
    const sanitizedMessage = sanitizePath(err.message);
    console.error(`Action 执行失败: ${sanitizedMessage}`);
    setOutput('result', 'failed');
    process.exit(1);
  });
}
