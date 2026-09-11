'use strict';

const { installFetchPolyfill } = require('./src/util/fetchPolyfill');
// GitCode 插件 runtime 为 node16，无全局 fetch；注入最小 polyfill，否则
// OIDC SDK 会回退 require('undici') 导致 "Cannot find module 'undici'"。
installFetchPolyfill();

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// OIDC SDK：APIG V11-HMAC-SHA256 签名 + HTTPS 请求 + 自包含 OIDC 换证。
// getCredentials() 通过 Actions 兼容流水线环境变量（ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN）
// 自申请 OIDC ID Token，再调用华为云 STS AssumeAgencyWithOIDC 换取临时 AK/SK/SecurityToken，
// 无需在 workflow 中额外运行 huaweicloud-oidc-auth 插件（仅需声明 permissions: id-token: write）。
let V11Signer = null;
let sendRequest = null;
let getCredentials = null;
try {
  ({ V11Signer, sendRequest, getCredentials } = require('@openlibing/huaweicloud-oidc-client'));
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

/**
 * 同步指数退避重试：默认 3 次，失败后 sleep(2^(n-1) 秒) 再试。
 * 用于 OBS 上传等同步命令，降低网络抖动导致的数据丢失风险（设计文档 5.3）。
 */
function withRetrySync(fn, { retries = 3, label = '' } = {}) {
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return fn();
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;
      const delaySec = Math.pow(2, attempt - 1);
      console.log(`[WARN] ${label} 第 ${attempt} 次失败（${err.message}），${delaySec}s 后重试（${attempt + 1}/${retries}）`);
      execSync(`sleep ${delaySec}`, { shell: '/bin/bash' });
    }
  }
  throw lastErr;
}

/**
 * 异步指数退避重试：默认 3 次，失败后 sleep(2^(n-1) * 1000ms) 再试。
 * 用于 APIG 回调等异步请求（设计文档 5.3）。
 */
async function withRetryAsync(fn, { retries = 3, label = '' } = {}) {
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;
      const delayMs = Math.pow(2, attempt - 1) * 1000;
      console.log(`[WARN] ${label} 第 ${attempt} 次失败（${err.message}），${delayMs}ms 后重试（${attempt + 1}/${retries}）`);
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  throw lastErr;
}

/** 日志脱敏：IP 地址替换为占位符 */
function sanitizePath(pathStr) {
  return pathStr.replace(/(\d+\.\d+\.\d+\.\d+)/g, '[IP_ADDRESS]');
}

// ---------- OIDC 回调 ----------

/**
 * OIDC 回调：用 SDK 换取的临时凭证对 APIG 请求做
 * V11-HMAC-SHA256 签名 + X-Security-Token 后上报（网关 IAM 认证，免静态凭证）。
 * @param {string} url APIG 回调地址
 * @param {Object} payload 回调报文
 * @param {{accessKeyId: string, secretAccessKey: string, securityToken: string|null}} cred SDK 换取的临时凭证
 * @returns {Promise<Object>} 响应体（code=200/0 视为成功）
 */
async function sendCallbackOidc(url, payload, cred) {
  if (!V11Signer || !sendRequest) {
    throw new Error('@openlibing/huaweicloud-oidc-client 未加载，无法进行 OIDC 回调');
  }
  const signer = new V11Signer({ region: APIG_SIGN_REGION });
  signer.Key = cred.accessKeyId;
  signer.Secret = cred.secretAccessKey;
  const headers = { 'Content-Type': 'application/json' };
  if (cred.securityToken) headers['X-Security-Token'] = cred.securityToken;

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
function writeObsutilConfig(obsutilPath, cred) {
  const configPath = path.join(os.tmpdir(), 'obsutil-oidc-config');
  try {
    exec(`touch ${configPath}`); // -config= 指向的文件必须已存在（obsutil 只更新不创建）
    execObsutil(`${obsutilPath} config -i="${cred.accessKeyId}" -k="${cred.secretAccessKey}" -t="${cred.securityToken}" -e="${OBS_WRITE_ENDPOINT}" -config="${configPath}"`);
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

// ---------- region.snippet 补齐 ----------

/** shell 单参数转义（用于 find 命令的引号包裹参数，防注入） */
function escapeShellArg(s) {
  return String(s).replace(/(["'`$\\])/g, '\\$1');
}

/**
 * 将 SARIF uri 解析为源码根目录下的真实文件路径；找不到返回 null。
 * 依次尝试：绝对路径（file:// 或 / 开头）→ sourceRoots 直接拼接 → 按文件名递归兜底查找。
 */
function resolveSourceFile(uri, sourceRoots) {
  let p = (uri || '').trim();
  if (!p) return null;
  if (p.startsWith('file://')) {
    try {
      const filePath = decodeURIComponent(p.replace(/^file:\/\//i, ''));
      return fs.existsSync(filePath) ? filePath : null;
    } catch (e) {
      return null;
    }
  }
  if (/^[a-zA-Z]:[\\/]/.test(p) || p.startsWith('/')) {
    return fs.existsSync(p) && fs.statSync(p).isFile() ? p : null;
  }
  p = p.replace(/^\.\//, '').replace(/^\/+/, '');
  for (const root of sourceRoots) {
    const cand = path.join(root, p);
    if (fs.existsSync(cand) && fs.statSync(cand).isFile()) return cand;
  }
  const base = path.basename(p);
  if (base) {
    for (const root of sourceRoots) {
      const found = execCapture(`find "${escapeShellArg(root)}" -name "${escapeShellArg(base)}" -type f 2>/dev/null | head -1`);
      if (found) return found;
    }
  }
  return null;
}

/**
 * 为 SARIF results 补充 region.snippet（实际代码行内容），提升后端告警可读性。
 * 仅当 region 缺少 snippet 时补齐：按 artifactLocation.uri + startLine(/endLine) 读源码；
 * 有 endLine 取多行，否则单行；源码不可读时静默跳过。
 * @returns {number} 成功补齐的 result 数量
 */
function enrichRegionSnippet(sarifObj, sourceRoots) {
  const results = sarifObj && sarifObj.runs && sarifObj.runs[0] && sarifObj.runs[0].results;
  if (!Array.isArray(results) || !sourceRoots || sourceRoots.length === 0) return 0;
  let enriched = 0;
  for (const r of results) {
    const loc = r && r.locations && r.locations[0] && r.locations[0].physicalLocation;
    if (!loc || !loc.artifactLocation || !loc.artifactLocation.uri) continue;
    const region = loc.region;
    if (!region || !region.startLine || region.startLine < 1) continue;
    if (region.snippet && region.snippet.text) continue; // 已有代码上下文，跳过
    const src = resolveSourceFile(loc.artifactLocation.uri, sourceRoots);
    if (!src) continue;
    let lines;
    try {
      lines = fs.readFileSync(src, 'utf-8').split(/\r?\n/);
    } catch (e) {
      continue;
    }
    const start = region.startLine;
    const end = region.endLine || start;
    const snippetLines = lines.slice(start - 1, end);
    if (!snippetLines.length) continue;
    region.snippet = { text: snippetLines.join('\n') };
    enriched++;
  }
  return enriched;
}

/** 遍历 SARIF 文件，缺少 region.snippet 时补齐并写回原文件 */
function enrichSarifFiles(sarifFiles, sourceRoots) {
  for (const f of sarifFiles) {
    let sarifObj;
    try {
      sarifObj = JSON.parse(fs.readFileSync(f, 'utf-8'));
    } catch (e) {
      console.log(`[WARN] 无法解析 SARIF: ${path.basename(f)}，跳过代码片段补齐`);
      continue;
    }
    const n = enrichRegionSnippet(sarifObj, sourceRoots);
    if (n > 0) {
      fs.writeFileSync(f, JSON.stringify(sarifObj, null, 2), 'utf-8');
      console.log(`[OK] ${path.basename(f)}: 已补充 ${n} 个 result 的 region.snippet`);
    } else {
      console.log(`[INFO] ${path.basename(f)}: 无需补充（已含 snippet 或源码不可读）`);
    }
  }
}

/**
 * 将全量代码检查统一元数据（layer/mode）写入 SARIF runs[].properties，随结果一并落库
 * （设计文档 5.1：layer / mode 等元数据注入 runs[].properties 或上传参数）。
 */
function injectSarifMetadata(sarifFiles, metadata) {
  for (const f of sarifFiles) {
    try {
      const sarifObj = JSON.parse(fs.readFileSync(f, 'utf-8'));
      const run = sarifObj && sarifObj.runs && sarifObj.runs[0];
      if (!run) continue;
      run.properties = run.properties || {};
      Object.assign(run.properties, metadata);
      fs.writeFileSync(f, JSON.stringify(sarifObj, null, 2), 'utf-8');
      console.log(`[OK] ${path.basename(f)}: 已注入元数据 ${JSON.stringify(metadata)}`);
    } catch (e) {
      console.log(`[WARN] 无法注入元数据: ${path.basename(f)}（${e.message}）`);
    }
  }
}

// ---------- 主流程 ----------

async function run() {
  const sarifFile = getInput('sarif_file');
  const category = getInput('category');
  const envType = (getInput('env_type') || 'prod').toLowerCase();
  const isBetaEnv = envType === 'beta';
  const workflowRunId = process.env.ATOMGIT_RUN_ID || '';
  // 全量代码检查统一元数据（设计文档 5.1/5.4）
  const layer = getInput('layer');
  const mode = (getInput('mode') || 'full').toLowerCase();
  const toolFailed = (getInput('tool_failed') || 'false').toLowerCase() === 'true';

  const callbackUrl = (isBetaEnv ? OIDC_BETA_BASE : OIDC_PROD_BASE) + OIDC_API_PREFIX + CALLBACK_PATH;

  console.log('===== openlibing-upload-sarif 启动 =====');
  console.log(`[INFO] 环境类型: ${isBetaEnv ? 'beta (测试环境)' : 'prod (正式环境)'}`);
  console.log('[INFO] 认证模式: OIDC 联邦认证（SDK 自包含换证，无需 huaweicloud-oidc-auth 插件）');
  console.log(`[INFO] 扫描层级 layer: ${layer || '（未指定）'}`);
  console.log(`[INFO] 扫描模式 mode: ${mode}`);
  console.log(`[INFO] 工具失败标记 tool_failed: ${toolFailed}`);
  console.log(`[INFO] 回调地址: ${callbackUrl}`);

  console.log('\n===== [1] 校验参数 =====');
  if (!sarifFile) {
    console.log('[ERROR] sarif_file 参数不能为空');
    setOutput('result', 'failed');
    process.exit(1);
  }
  if (!V11Signer || !sendRequest || !getCredentials) {
    console.log('[ERROR] @openlibing/huaweicloud-oidc-client 加载失败，无法进行 OIDC 认证');
    setOutput('result', 'failed');
    process.exit(1);
  }
  console.log('[OK] 参数校验通过');

  console.log('\n===== [2] OIDC 免密换证（SDK 自包含） =====');
  let cred;
  try {
    cred = await getCredentials();
    if (!cred || !cred.accessKeyId || !cred.secretAccessKey) {
      throw new Error('换证结果缺少 AK/SK');
    }
  } catch (err) {
    console.log(`[ERROR] OIDC 换证失败: ${err.message}`);
    console.log('[INFO] 请确认 workflow 已声明 permissions: id-token: write');
    setOutput('result', 'failed');
    process.exit(1);
  }
  console.log('[OK] 临时凭证获取成功（OIDC ID Token 自申请 + STS 换证）');

  console.log('\n===== [3] 检查 SARIF 文件 =====');
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
    if (toolFailed) {
      console.log(`[WARN] tool_failed=true 且 SARIF 路径不存在（${sarifFile}），按失败元数据模式执行：跳过 OBS 上传，仅上报失败标记`);
    } else {
      console.log(`[ERROR] SARIF 路径不存在: ${sarifFile}`);
      setOutput('result', 'failed');
      process.exit(1);
    }
  }

  let sarifFiles = [];
  if (fs.existsSync(resolvedSarifPath)) {
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
  } else {
    console.log('[WARN] 无 SARIF 文件可上传（tool_failed 模式）');
  }

  console.log('\n===== [4] 检查并补齐代码片段（region.snippet） =====');
  const sourcePathInput = getInput('source_path');
  const sourceRoots = [];
  if (sourcePathInput) {
    for (const p of sourcePathInput.split(',')) {
      const trimmed = p.trim();
      if (!trimmed) continue;
      sourceRoots.push(fs.existsSync(trimmed) ? trimmed : path.join(workspace, trimmed));
    }
  }
  // 始终兜底：ATOMGIT_WORKSPACE 下按文件名查找
  sourceRoots.push(workspace);
  console.log(`[INFO] 源码根目录: ${sourceRoots.join(', ')}`);
  enrichSarifFiles(sarifFiles, sourceRoots);

  // 注入全量代码检查统一元数据（layer/mode）到 runs[].properties（设计文档 5.1）
  if (sarifFiles.length > 0) {
    const sarifMeta = {};
    if (layer) sarifMeta.layer = layer;
    if (mode) sarifMeta.mode = mode;
    if (Object.keys(sarifMeta).length > 0) {
      injectSarifMetadata(sarifFiles, sarifMeta);
    }
  }

  let obsUrlValue = [];
  if (sarifFiles.length > 0) {
    console.log('\n===== [5] 安装 obsutil =====');
    let obsutilPath;
    try {
      obsutilPath = installObsutil();
    } catch (err) {
      console.log(`[ERROR] ${err.message}`);
      setOutput('result', 'failed');
      process.exit(1);
    }

    console.log('\n===== [6] 构建 OBS 路径 =====');
    const repoBaseName = (process.env.ATOMGIT_REPOSITORY || process.env.GIT_REPOSITORY || '').split('/').pop() || 'unknown-repo';
    const now = new Date();
    const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}.${String(now.getHours()).padStart(2, '0')}`;
    const obsKeyPrefix = `${OBS_KEY_ROOT}/${repoBaseName}/${dateStr}${workflowRunId ? '/' + workflowRunId : ''}`;
    const downloadUrlPrefix = `${OBS_READ_ENDPOINT}/${obsKeyPrefix}`;
    console.log(`[INFO] OBS 路径: obs://${OBS_BUCKET}/${obsKeyPrefix}/`);
    console.log(`[INFO] 下载前缀: ${downloadUrlPrefix}`);

    console.log('\n===== [7] 生成构建产物 JSON =====');
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

    console.log('\n===== [8] 上传到 OBS（失败指数退避重试，默认 3 次） =====');
    const obsAuthArgs = writeObsutilConfig(obsutilPath, cred);

    console.log('[INFO] 上传构建产物文件: build-result.json');
    try {
      // -acl=public-read：后端 SarifParseServiceImpl 通过匿名 HTTP GET 下载，对象必须公共读
      withRetrySync(() => execObsutil(`${obsutilPath} cp "${buildResultPath}" "obs://${OBS_BUCKET}/${obsKeyPrefix}/build-result.json" -f -acl=public-read -e="${OBS_WRITE_ENDPOINT}" ${obsAuthArgs}`), { label: 'build-result.json 上传' });
    } catch (e1) {
      console.log(`[WARN] 构建产物文件上传失败: ${e1.message}`);
    }

    for (let i = 0; i < sarifFiles.length; i++) {
      const sarifPath = sarifFiles[i];
      const sarifName = path.basename(sarifPath);
      console.log(`[INFO] 上传 SARIF 文件 (${i + 1}/${sarifFiles.length}): ${sarifName}`);
      try {
        // -acl=public-read：后端 SarifParseServiceImpl 通过匿名 HTTP GET 下载，对象必须公共读
        withRetrySync(() => execObsutil(`${obsutilPath} cp "${sarifPath}" "obs://${OBS_BUCKET}/${obsKeyPrefix}/" -f -acl=public-read -e="${OBS_WRITE_ENDPOINT}" ${obsAuthArgs}`), { label: `${sarifName} 上传` });
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

    obsUrlValue = isSingleFile ? sarifDownloadUrls[0] : sarifDownloadUrls;

    console.log('\n================================================================');
    console.log('[INFO] 上传成功');
    console.log('================================================================');
  } else {
    console.log('\n===== [5] 跳过 OBS 上传（tool_failed 模式，无 SARIF 文件可上传） =====');
  }

  console.log('\n===== [9] 回调通知（失败指数退避重试，默认 3 次） =====');
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
    // 全量代码检查统一元数据（设计文档 5.1/5.4）：层级 L1/L2、模式 full/incremental、工具失败标记
    layer: layer || '',
    mode: mode || 'full',
    toolFailed: toolFailed || false,
    source: 'GITCODE_ACTION',
    sourceRunUrl: buildSourceRunUrl() || ''
  };

  try {
    const callbackResult = await withRetryAsync(() => sendCallbackOidc(callbackUrl, callbackPayload, cred), { label: 'APIG 回调' });
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

module.exports = { run, enrichRegionSnippet, enrichSarifFiles, resolveSourceFile, injectSarifMetadata, withRetrySync, withRetryAsync };

if (require.main === module) {
  run().catch(err => {
    const sanitizedMessage = sanitizePath(err.message);
    console.error(`Action 执行失败: ${sanitizedMessage}`);
    setOutput('result', 'failed');
    process.exit(1);
  });
}
