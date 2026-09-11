/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 136:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const { installFetchPolyfill } = __nccwpck_require__(849);
// GitCode 插件 runtime 为 node16，无全局 fetch；注入最小 polyfill，否则
// OIDC SDK 会回退 require('undici') 导致 "Cannot find module 'undici'"。
installFetchPolyfill();

const { execSync } = __nccwpck_require__(317);
const fs = __nccwpck_require__(896);
const path = __nccwpck_require__(928);
const os = __nccwpck_require__(857);

// OIDC SDK：APIG V11-HMAC-SHA256 签名 + HTTPS 请求 + 自包含 OIDC 换证。
// getCredentials() 通过 Actions 兼容流水线环境变量（ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN）
// 自申请 OIDC ID Token，再调用华为云 STS AssumeAgencyWithOIDC 换取临时 AK/SK/SecurityToken，
// 无需在 workflow 中额外运行 huaweicloud-oidc-auth 插件（仅需声明 permissions: id-token: write）。
let V11Signer = null;
let sendRequest = null;
let getCredentials = null;
try {
  ({ V11Signer, sendRequest, getCredentials } = __nccwpck_require__(239));
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

if (require.main === require.cache[eval('__filename')]) {
  run().catch(err => {
    const sanitizedMessage = sanitizePath(err.message);
    console.error(`Action 执行失败: ${sanitizedMessage}`);
    setOutput('result', 'failed');
    process.exit(1);
  });
}


/***/ }),

/***/ 578:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * APIG 调用封装模块：callApig 一行调用 APIG 接口。
 * 自动完成：临时凭证获取（带缓存 / force 强制刷新）-> V11-HMAC-SHA256 签名 ->
 * X-Security-Token 注入 -> 发送请求。需精细控制时可自行组合 V11Signer + sendRequest。
 */

const { cfg } = __nccwpck_require__(269);
const { getCredentials } = __nccwpck_require__(477);
const { V11Signer } = __nccwpck_require__(311);
const { sendRequest } = __nccwpck_require__(531);

/**
 * 调用 APIG 接口：自动换证（带缓存）、V11 签名（自动携带 X-Security-Token）并发送请求。
 * 需精细控制时可自行组合 V11Signer + sendRequest。
 *
 * headers / body / opts 均为可选参数，可同时设置，也可只设置其中几个；
 * 跳过中间参数时传 null（如仅设置 opts：callApig('GET', url, null, null, { force: true })）。
 * @param {string} method HTTP 方法（GET/POST 等）
 * @param {string} url    完整 APIG URL（https://{host}{path}[?query]）
 * @param {Object} [headers] 附加请求头（与默认 Content-Type 头合并）
 * @param {string} [body]    请求体（字符串）
 * @param {Object} [opts]    额外选项：{ force } 强制刷新临时凭证、{ region } 覆盖签名区域
 * @returns {Promise<{status: number, headers: Object, data: Object|string|null}>} 同 sendRequest 返回
 */
async function callApig(method, url, headers, body, opts = {}) {
  const cred = await getCredentials({ force: !!opts.force });
  const signer = new V11Signer({ region: opts.region || cfg.region });
  signer.Key = cred.accessKeyId;
  signer.Secret = cred.secretAccessKey;
  // 大小写不敏感地检查用户是否已设置 Content-Type，避免默认 application/json 与用户传入的
  // content-type（大小写不同）共存导致规范请求重复头、签名校验失败（APIG.0301）
  const hasContentType = headers && Object.keys(headers).some((k) => k.toLowerCase() === 'content-type');
  const mergedHeaders = {
    ...(hasContentType ? {} : { 'Content-Type': 'application/json' }),
    ...(headers || {})
  };
  if (cred.securityToken) {
    mergedHeaders['X-Security-Token'] = cred.securityToken;
  }
  const reqBody = body || '';
  const signedHeaders = signer.sign(method, url, mergedHeaders, reqBody);
  return sendRequest(method, url, signedHeaders, reqBody);
}

module.exports = { callApig };


/***/ }),

/***/ 269:
/***/ ((module) => {

"use strict";


/**
 * 配置模块：内置 openlibing 默认配置 + configure() 覆盖。
 * 模块级单例 cfg 供 logger / http / oidc / credentials 共享。
 */

// 内置固定配置（openlibing 账号）
const CONFIG = {
  // openlibing 华为云账号 ID
  accountId: '4d29a984c4fe4e6eb5d404a853d0084e',
  // OIDC 受众（申请 OIDC ID Token 的 audience，需与身份提供商注册的客户端 ID 一致）
  audience: 'huawei-cloud-service',
  // IAM 信任委托名称
  agencyName: 'gitcode-actions',
  // OIDC 身份提供商名称（华为云侧按令牌签发平台分别注册：GitHub 平台为 GitHubActions，
  // GitCode Actions 平台为 GitCodeActions）。取 configure() 配置值，
  // 可通过显式 configure({ oidcProviderName }) 覆盖
  oidcProviderName: 'GitCodeActions',
  // 区域（openlibing 账号固定区域，可显式覆盖）
  region: 'cn-southwest-2',
  // STS 换证路径
  stsAssumePath: '/v5/agencies/assume-with-oidc',
  // 临时凭证默认有效期（秒）
  durationSeconds: 3600,
  // 提前刷新缓冲（秒），避免凭证在边界过期
  refreshBufferSeconds: 300,
  // 调试模式：开启后打印关键步骤日志（含每次 HTTP 请求/响应详情，敏感字段自动脱敏）
  debug: false
};

// 当前生效配置（可用 configure() 覆盖）
const cfg = { ...CONFIG };

/**
 * 覆盖内置配置（如更换账号 / 区域 / 受众 / 委托等）。
 * @param {Object} overrides 可覆盖字段：accountId/audience/agencyName/oidcProviderName/
 *                           region/stsAssumePath/durationSeconds/refreshBufferSeconds/debug
 * @returns {Object} 覆盖后的完整配置（含全部内置默认值）
 */
function configure(overrides = {}) {
  const allowed = [
    'accountId', 'audience', 'agencyName', 'oidcProviderName',
    'region', 'stsAssumePath', 'durationSeconds', 'refreshBufferSeconds', 'debug'
  ];
  for (const k of allowed) {
    if (overrides[k] !== undefined) {
      cfg[k] = overrides[k];
    }
  }
  return { ...cfg };
}

module.exports = { CONFIG, cfg, configure };


/***/ }),

/***/ 477:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * 临时凭证模块：getCredentials() 获取华为云临时凭证。
 * 调用链 CI 流水线（GitHub Actions / GitCode Actions 等 Actions 兼容平台）OIDC ID Token
 * -> 华为云 STS AssumeAgencyWithOIDC，带缓存自动刷新、force 强制刷新、并发去重。
 */

const { cfg } = __nccwpck_require__(269);
const { info, debug, error, mask, maskBody } = __nccwpck_require__(463);
const { sendRequest } = __nccwpck_require__(531);
const { getOidcToken } = __nccwpck_require__(790);

let _credentials = null; // { accessKeyId, secretAccessKey, securityToken, expiresAt, expiresAtISO }
let _credentialPromise = null; // 进行中的换证 Promise（并发去重）

/** 判断缓存凭证是否仍有效（未过期且留有缓冲时间）。 */
function _isValid(cred) {
  if (!cred || !cred.expiresAt) {
    return false;
  }
  return Date.now() < cred.expiresAt - cfg.refreshBufferSeconds * 1000;
}

/**
 * 获取 openlibing 账号下的华为云临时凭证。
 * 优先级：有效缓存 > OIDC+STS 换证。
 * @param {Object} [opts]
 * @param {boolean} [opts.force] 为 true 时强制重新换证（忽略缓存）
 * @returns {Promise<{accessKeyId: string, secretAccessKey: string,
 *                     securityToken: string|null, expiresAt: string|null, expiresIn: number|null}>}
 */
async function getCredentials(opts = {}) {
  if (!opts.force && _isValid(_credentials)) {
    const expiresIn = Math.max(0, Math.round((_credentials.expiresAt - Date.now()) / 1000));
    debug(`-- 临时凭证缓存有效，直接复用（剩余约 ${expiresIn} 秒）--`);
    return {
      accessKeyId: _credentials.accessKeyId,
      secretAccessKey: _credentials.secretAccessKey,
      securityToken: _credentials.securityToken,
      expiresAt: _credentials.expiresAtISO,
      expiresIn
    };
  }
  if (_credentials) {
    debug('-- 临时凭证缓存缺失或已过期，重新换取 --');
  }
  const cred = await _exchangeCredentials();
  return {
    accessKeyId: cred.accessKeyId,
    secretAccessKey: cred.secretAccessKey,
    securityToken: cred.securityToken,
    expiresAt: cred.expiresAtISO,
    expiresIn: Math.max(0, Math.round((cred.expiresAt - Date.now()) / 1000))
  };
}

/** 解析 OIDC Token payload 中的关键声明（失败返回 null）。 */
function _parseTokenClaims(idToken) {
  try {
    const payload = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url').toString());
    return { iss: payload.iss, aud: payload.aud, azp: payload.azp, sub: payload.sub };
  } catch (e) {
    return null;
  }
}

/** 打印 OIDC Token 声明（logFn 传 debug 为调试定位，传 error 为失败定位）。 */
function _printTokenClaims(claims, logFn) {
  if (!claims) {
    logFn('（无法解析 OIDC Token payload）');
    return;
  }
  logFn('-- OIDC Token 声明（用于与华为云信任策略比对）--');
  logFn(`iss : ${JSON.stringify(claims.iss)}`);
  logFn(`aud : ${JSON.stringify(claims.aud)}`);
  logFn(`azp : ${JSON.stringify(claims.azp)}`);
  logFn(`sub : ${JSON.stringify(claims.sub)}`);
}

/**
 * 通过流水线签发的 OIDC JWT 调用 STS AssumeAgencyWithOIDC 换取临时 AK/SK/SecurityToken。
 * OIDC 提供商取 configure() 配置值（需与华为云 IAM 侧注册名一致）；
 * iss/aud/azp/sub 声明调试模式下打印、STS 失败时以 error 级补打，用于与信任策略比对排查。
 * @returns {Promise<{accessKeyId: string, secretAccessKey: string,
 *                     securityToken: string, expiresAt: number, expiresAtISO: string}>}
 */
async function _assumeAgencyWithOIDC() {
  const agencyUrn = `iam::${cfg.accountId}:agency:${cfg.agencyName}`;
  const stsEndpoint = `https://sts.${cfg.region}.myhuaweicloud.com${cfg.stsAssumePath}`;

  debug('=== 步骤1：申请 OIDC ID Token ===');
  debug(`audience=${cfg.audience}`);
  const idToken = await getOidcToken();
  if (!idToken) {
    throw new Error('获取 OIDC ID Token 为空（请确认流水线已声明 permissions: id-token: write）');
  }
  debug(`OIDC Token 获取成功，长度 ${idToken.length}`);

  const claims = _parseTokenClaims(idToken);
  _printTokenClaims(claims, debug);

  const providerName = cfg.oidcProviderName;
  const providerUrn = `iam::${cfg.accountId}:oidcProvider:${providerName}`;

  const body = {
    provider_urn: providerUrn,
    agency_urn: agencyUrn,
    agency_session_name: cfg.agencyName,
    id_token: idToken,
    duration_seconds: cfg.durationSeconds
  };

  info(`-- OIDC 免密换证开始：区域 ${cfg.region}，提供商 ${providerName}，委托 ${cfg.agencyName} --`);
  debug('=== 步骤2：调用 STS AssumeAgencyWithOIDC ===');
  debug(`provider_urn        : ${body.provider_urn}`);
  debug(`agency_urn          : ${body.agency_urn}`);
  debug(`agency_session_name : ${body.agency_session_name}`);
  debug(`duration_seconds    : ${body.duration_seconds}`);

  const res = await sendRequest('POST', stsEndpoint, { 'Content-Type': 'application/json' }, JSON.stringify(body));

  if (res.status !== 200) {
    const code = res.data && (res.data.error_code || res.data.code);
    const msg = res.data && (res.data.error_msg || res.data.message);
    error(`STS 失败详情 : ${maskBody(res.data)}`);
    // 失败定位：非调试模式下也补打 Token 声明与换证配置，供与信任策略逐项比对
    _printTokenClaims(claims, error);
    error(`provider_urn : ${providerUrn}`);
    error('=== 排查提示 ===');
    error('STS5.1001/403：多为信任策略条件不匹配，请将上方 OIDC Token 的 iss/aud/azp/sub 与华为云信任策略逐项比对。');
    error('  - iss 必须与所选 OIDC 提供商注册的颁发者 URL 严格一致（GitHub 平台为 https://token.actions.githubusercontent.com，GitCode Actions 平台以其流水线签发地址为准）');
    error('  - aud/azp 必须与策略中 oidc:aud 一致（且身份提供商客户端 ID 已注册）');
    error('  - sub 必须能被策略中 oidc:sub 的通配符匹配');
    throw new Error(`STS auth failed (${res.status})${code ? ' [' + code + ']' : ''}: ${msg || '未知错误'}`);
  }

  const cred = res.data.credentials;
  if (!cred || !cred.access_key_id || !cred.secret_access_key || !cred.security_token) {
    error(`STS 响应体 : ${maskBody(res.data)}`);
    throw new Error('STS auth failed: 响应中缺少临时凭证字段');
  }

  const expiresAt = new Date(cred.expiration).getTime();
  info(`-- 临时凭证获取成功：AK ${mask(cred.access_key_id)}，有效期约 ${Math.max(0, Math.round((expiresAt - Date.now()) / 1000))} 秒 --`);
  debug('=== 步骤3：成功获取临时安全凭证 ===');
  debug(`SecurityToken    : ${mask(cred.security_token, 10, 10)}`);
  debug(`凭证过期时间     : ${cred.expiration}`);

  const result = {
    accessKeyId: cred.access_key_id,
    secretAccessKey: cred.secret_access_key,
    securityToken: cred.security_token,
    expiresAt,
    expiresAtISO: cred.expiration
  };
  _credentials = result;
  _credentialPromise = null;
  return result;
}

/**
 * 换取临时凭证（带并发去重：同一时刻只发起一次 STS 换证，其余等待同一结果）。
 * @returns {Promise<Object>} 同 _assumeAgencyWithOIDC 返回
 */
async function _exchangeCredentials() {
  if (_credentialPromise) {
    debug('-- 检测到进行中的换证请求，复用同一结果（并发去重）--');
    return _credentialPromise;
  }
  _credentialPromise = _assumeAgencyWithOIDC();
  try {
    return await _credentialPromise;
  } catch (err) {
    _credentialPromise = null;
    error(`-- OIDC 免密换证失败：${err.message} --`);
    throw err;
  }
}

module.exports = { getCredentials };


/***/ }),

/***/ 531:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * HTTP 请求工具模块：sendRequest 发送请求并解析 JSON 响应。
 * 基于 Node 内置 fetch（Node 18+），零第三方依赖。
 * 调试模式打印完整请求/响应日志（敏感字段自动脱敏），非调试模式不打印请求详情。
 */

const { debug, maskHeaders, maskBody, clip } = __nccwpck_require__(463);

// Node 18+ 有内置全局 fetch；在只支持 node16 运行时的 CI 平台（如 GitCode Action）下
// 回退到 undici（作为 Action 产物时由 @actions/core 的传递依赖随 ncc 一并内联）。
// 运行时动态判断而非模块加载时固化，保证测试拦截器替换全局 fetch 后仍生效。

/**
 * 发送 HTTPS 请求并解析 JSON 响应（通用基础能力，供调用 APIG 等接口使用）。
 * 调试模式（configure({ debug: true })）下打印完整请求/响应日志，敏感字段自动脱敏。
 * @param {string} method  HTTP 方法（GET/POST/...）
 * @param {string} url     完整 URL（https://{host}{path}[?query]）
 * @param {Object} [headers] 请求头
 * @param {string|Buffer} [body] 请求体（字符串或二进制 Buffer，均可选）
 * @returns {Promise<{status: number, headers: Object, data: Object|string}>}
 *          JSON 解析失败时 data = { raw }
 */
async function sendRequest(method, url, headers, body) {
  debug(`--> ${String(method).toUpperCase()} ${url}`);
  debug(`--> 请求头: ${JSON.stringify(maskHeaders(headers))}`);
  if (body !== undefined && body !== null && body !== '') {
    debug(`--> 请求体: ${_describeBody(body)}`);
  }

  let res;
  try {
    const fetchImpl = typeof fetch === 'function' ? fetch : (...args) => (__nccwpck_require__(337).fetch)(...args);
    res = await fetchImpl(url, {
      method,
      headers,
      body: body || undefined
    });
  } catch (err) {
    throw new Error(`网络请求失败 ${method} ${url}: ${err.message}`);
  }

  const raw = await res.text();
  debug(`<-- HTTP 状态码: ${res.status}`);
  debug(`<-- 响应头: ${JSON.stringify(_headersToObject(res.headers))}`);
  debug(`<-- 响应体: ${raw ? clip(maskBody(raw)) : '(空)'}`);

  let data = {};
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch (e) {
      data = { raw };
    }
  }
  return { status: res.status, headers: _headersToObject(res.headers), data };
}

/**
 * 调试日志的请求体描述：二进制按类型与长度描述（不读内容），字符串/普通对象脱敏后截断，
 * 避免大体积或非文本内容拖慢处理、刷屏或序列化异常。
 */
function _describeBody(body) {
  if (typeof body === 'string') return clip(maskBody(body));
  if (Buffer.isBuffer(body) || body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    return `(二进制，${body.byteLength ?? body.length} 字节)`;
  }
  try {
    return clip(maskBody(JSON.stringify(body)));
  } catch (e) {
    return '(对象，无法序列化)';
  }
}

/** 将 fetch 的 Headers 对象转换为普通对象。 */
function _headersToObject(headers) {
  const out = {};
  headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

module.exports = { sendRequest };


/***/ }),

/***/ 239:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * @openlibing/huaweicloud-oidc-client：openlibing 平台与华为云的交互 SDK（npm 包入口）
 *
 * 本包封装 openlibing 平台对接华为云的通用基础能力：
 *   1. OIDC 认证：getCredentials() 获取华为云临时凭证（AK/SK/SecurityToken），调用链为
 *      CI 流水线 OIDC ID Token（GitHub Actions / GitCode Actions 等 Actions 兼容平台，
 *      audience = huawei-cloud-service）-> 华为云 STS AssumeAgencyWithOIDC 换证，带缓存
 *      自动刷新、force 强制刷新、并发去重；OIDC 提供商取 configure() 配置值。
 *   2. APIG 调用：callApig() 一行调用 APIG 接口（自动换证 + V11 签名 + X-Security-Token）；
 *      V11Signer 对 APIG 请求做 V11-HMAC-SHA256 签名（严格复刻华为云官方 APIG Python SDK
 *      的 V11 算法，仅适用于 APIG 网关，作用域服务名固定为 apic），供精细控制场景使用。
 *   3. HTTPS 请求工具：sendRequest() 发送请求并解析 JSON 响应，供调用 APIG 等接口使用。
 *
 * 设计边界：OBS 上传等业务逻辑由使用方基于本 SDK 提供的临时凭证自行实现（OBS 使用自身签名协议）。
 *
 * 日志分级：info 关键步骤成功日志（OIDC Token 申请、换证步骤等）与 error 关键步骤失败日志（失败原因、排查
 * 提示等，输出到 stderr）任何模式下均打印；debug 调试定位日志（每次 HTTP 请求的请求行、请求头、
 * 请求体与响应状态码、响应头、响应体、OIDC Token 声明等，敏感字段自动脱敏）通过
 * configure({ debug: true }) 开启，默认关闭。
 *
 * 仅依赖 Node 内置模块（https / crypto / url），不依赖 @actions/core；OIDC Token 通过
 * Actions 兼容流水线（GitHub / GitCode Actions）注入的环境变量自包含申请，任意 Node 环境均可独立使用。
 *
 * 模块结构（src/）：
 *   config.js       内置配置 + configure() 覆盖（模块级单例 cfg）
 *   logger.js       分级日志（info 关键步骤 / debug 调试定位 / error 失败详情）+ 敏感字段脱敏工具
 *   http.js         sendRequest HTTPS 请求工具（调试模式打印请求/响应详情）
 *   oidc.js         OIDC ID Token 申请（GitHub / GitCode Actions 等 Actions 兼容流水线自申请 / 环境变量注入）
 *   credentials.js  getCredentials：OIDC -> STS 换证（缓存 / force / 并发去重）
 *   signer-v11.js   V11Signer：APIG V11-HMAC-SHA256 签名器
 *   apig.js         callApig：一行调用 APIG（自动换证 + V11 签名 + X-Security-Token）
 *
 * 用法：
 *   const openlibing = require('@openlibing/huaweicloud-oidc-client');
 *
 *   // 开启调试定位日志（额外打印请求/响应详情等，敏感字段脱敏；关键步骤日志默认已打印）
 *   openlibing.configure({ debug: true });
 *
 *   // 覆盖内置 openlibing 配置（换账号/区域等）
 *   openlibing.configure({ accountId: 'xxx', region: 'cn-north-4' });
 *
 *   // 1) 一行调用 APIG（自动换证 + V11 签名 + X-Security-Token）
 *   const res = await openlibing.callApig('GET', 'https://{apig-host}/v1/export');
 *   // => { status, headers, data }
 *
 *   // 2) OIDC 认证：获取临时凭证（供 OBS 上传等场景自行使用）
 *   const cred = await openlibing.getCredentials();
 *   // => { accessKeyId, secretAccessKey, securityToken, expiresAt, expiresIn }
 *
 *   // 强制刷新
 *   const fresh = await openlibing.getCredentials({ force: true });
 *
 *   // 3) 精细控制：自行组合 V11 签名与 HTTPS 请求
 *   const signer = new openlibing.V11Signer({ region: 'cn-southwest-2' });
 *   signer.Key = cred.accessKeyId;
 *   signer.Secret = cred.secretAccessKey;
 *   const headers = signer.sign('GET', 'https://{apig-host}/v1/export', {}, '');
 *   const res2 = await openlibing.sendRequest('GET', 'https://{apig-host}/v1/export', headers, '');
 */

module.exports = {
  callApig: (__nccwpck_require__(578).callApig),
  getCredentials: (__nccwpck_require__(477).getCredentials),
  configure: (__nccwpck_require__(269).configure),
  V11Signer: (__nccwpck_require__(311).V11Signer),
  sendRequest: (__nccwpck_require__(531).sendRequest)
};


/***/ }),

/***/ 463:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * 日志与脱敏模块：分级日志（info 关键步骤 / debug 调试定位 / error 失败详情）+ 敏感字段脱敏工具。
 * 各级别日志均带 [INFO] / [DEBUG] / [ERROR] 前缀与 ISO 8601 UTC 时间戳，便于肉眼区分、排序与按级别检索。
 */

const { cfg } = __nccwpck_require__(269);

/** 当前时间戳（ISO 8601 UTC，如 2026-08-28T12:03:54.123Z）。 */
function ts() {
  return new Date().toISOString();
}

/** 关键步骤日志（info 级）：任何模式下均打印（普通 Node 环境使用 console.log，不依赖 @actions/core）。 */
function info(msg) {
  console.log(`[INFO] ${ts()} ${msg}`);
}

/** 调试日志（debug 级）：仅在调试模式（configure({ debug: true })）下打印，用于请求/响应详情等定位信息。 */
function debug(msg) {
  if (cfg.debug) {
    console.log(`[DEBUG] ${ts()} ${msg}`);
  }
}

/** 错误日志（error 级）：任何模式下均打印，输出到 stderr（失败详情、排查提示等），便于与正常日志区分。 */
function error(msg) {
  console.error(`[ERROR] ${ts()} ${msg}`);
}

/** 脱敏：仅保留首尾若干字符，中间用 * 代替。 */
function mask(value, head = 6, tail = 4) {
  if (!value) return '(空)';
  const s = String(value);
  if (s.length <= head + tail) return s.slice(0, 2) + '***' + s.slice(-2);
  return s.slice(0, head) + '***' + s.slice(-tail) + `（长度 ${s.length}）`;
}

/** 调试日志中需要脱敏的字段名（请求头字段与 JSON 字段名，小写比较）。 */
const SENSITIVE_KEYS = [
  'authorization', 'x-security-token', 'x-auth-token', 'password', 'secret',
  'id_token', 'access_key_id', 'secret_access_key', 'security_token',
  'accesskeyid', 'secretaccesskey', 'securitytoken', 'client_secret'
];

/** JWT 特征（三段 base64url，以 eyJ 开头），用于在任意文本中识别并脱敏令牌。 */
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

/** 文本脱敏：将其中的 JWT 令牌整体脱敏。 */
function maskText(text) {
  return String(text).replace(JWT_RE, (m) => mask(m, 20, 10));
}

/** 深度脱敏 JSON 结构：敏感字段名直接脱敏，其余字段递归处理（字符串再做 JWT 识别）。 */
function maskDeep(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return maskText(value);
  if (Array.isArray(value)) return value.map(maskDeep);
  if (typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) {
      out[k] = SENSITIVE_KEYS.includes(k.toLowerCase()) ? mask(value[k]) : maskDeep(value[k]);
    }
    return out;
  }
  return value;
}

/** 请求头脱敏：敏感头字段值脱敏，其余原样。 */
function maskHeaders(headers) {
  const out = {};
  for (const k of Object.keys(headers || {})) {
    out[k] = SENSITIVE_KEYS.includes(k.toLowerCase()) ? mask(headers[k]) : headers[k];
  }
  return out;
}

/** 请求体/响应体脱敏：JSON 结构做深度脱敏，非 JSON 文本做 JWT 识别脱敏。 */
function maskBody(body) {
  const s = typeof body === 'string' ? body : JSON.stringify(body);
  try {
    return JSON.stringify(maskDeep(JSON.parse(s)));
  } catch (e) {
    return maskText(s);
  }
}

/** 调试日志体积保护：超长文本截断，避免大体积请求/响应体拖慢处理或刷屏。 */
function clip(text, max = 4096) {
  const s = String(text);
  if (s.length <= max) return s;
  return `${s.slice(0, max)}…（截断，总长 ${s.length} 字符）`;
}

module.exports = { info, debug, error, mask, maskText, maskDeep, maskHeaders, maskBody, clip, SENSITIVE_KEYS };


/***/ }),

/***/ 790:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * OIDC 模块：申请 CI 流水线签发的 OIDC ID Token（自包含，不依赖 @actions/core）。
 * 支持 GitHub Actions、GitCode Actions 等 Actions 兼容流水线：两者签发 OIDC ID Token 的方式
 * 一致，均通过运行时注入的 ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN
 * 环境变量申请（GitCode Actions 流水线与 GitHub Actions 运行器协议兼容）。
 */

const { cfg } = __nccwpck_require__(269);
const { info, error } = __nccwpck_require__(463);
const { sendRequest } = __nccwpck_require__(531);

/** 申请 OIDC ID Token（自包含，不依赖 @actions/core，GitHub / GitCode Actions 流水线均适用）。 */
async function getOidcToken() {
  const fromEnv = process.env.HUAWEICLOUD_OIDC_TOKEN;
  if (fromEnv) {
    info('-- OIDC ID Token 获取成功：来自环境变量 HUAWEICLOUD_OIDC_TOKEN 注入 --');
    return fromEnv;
  }
  const fromActions = await getOidcTokenFromActions();
  if (fromActions) {
    info('-- OIDC ID Token 申请成功（Actions 兼容流水线 OIDC 接口）--');
    return fromActions;
  }
  error('-- OIDC ID Token 申请失败：缺少 ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN 环境变量 --');
  throw new Error(
    '无法申请 OIDC ID Token：缺少 ACTIONS_ID_TOKEN_REQUEST_URL/ACTIONS_ID_TOKEN_REQUEST_TOKEN。' +
    '请确认流水线（GitHub Actions / GitCode Actions 等兼容平台）已声明 permissions: id-token: write，' +
    '或设置环境变量 HUAWEICLOUD_OIDC_TOKEN 直接注入令牌。'
  );
}

/**
 * 通过 Actions 兼容流水线（GitHub Actions / GitCode Actions）注入的环境变量自行申请 OIDC ID Token。
 * 与 @actions/core 的 getIDToken 实现一致：向 ACTIONS_ID_TOKEN_REQUEST_URL 发起
 * GET 请求并携带 audience 查询参数，Authorization 头使用 ACTIONS_ID_TOKEN_REQUEST_TOKEN。
 * @returns {Promise<string|null>}
 */
async function getOidcTokenFromActions() {
  const reqUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const reqToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!reqUrl || !reqToken) {
    return null;
  }
  const url = new URL(reqUrl);
  url.searchParams.append('audience', cfg.audience);
  const res = await sendRequest('GET', url.toString(), {
    Authorization: `Bearer ${reqToken}`,
    'Content-Type': 'application/json',
    'User-Agent': 'OpenlibingClient/1.0'
  }, '');
  if (res.status !== 200 || !res.data || !res.data.value) {
    error(`OIDC Token 申请失败（HTTP ${res.status}）: ${JSON.stringify(res.data)}`);
    return null;
  }
  return res.data.value;
}

module.exports = { getOidcToken };


/***/ }),

/***/ 311:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * APIG V11-HMAC-SHA256 签名模块（严格复刻华为云官方 APIG Python SDK 的 V11 算法）。
 * 仅适用于 APIG 网关接口，签名作用域服务名固定为 apic。
 */

const crypto = __nccwpck_require__(982);

const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const APIC_SERVICE = 'apic';

// 与官方 noEscape 一致的字符表：不可编码字符（字母数字和 - _ . ~）为 1
const noEscape = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0
];

const hexTable = [];
for (let i = 0; i < 256; ++i) {
  hexTable[i] = '%' + ((i < 16 ? '0' : '') + i.toString(16)).toUpperCase();
}

/** 官方 urlencode 实现（quote(str, safe='~')）。 */
function urlEncode(str) {
  if (typeof str !== 'string') {
    str = str == null ? '' : String(str);
  }
  let out = '';
  let lastPos = 0;
  for (let i = 0; i < str.length; ++i) {
    const c = str.charCodeAt(i);
    if (c < 0x80) {
      if (noEscape[c] === 1) continue;
      if (lastPos < i) out += str.slice(lastPos, i);
      lastPos = i + 1;
      out += hexTable[c];
      continue;
    }
    if (lastPos < i) out += str.slice(lastPos, i);
    if (c < 0x800) {
      lastPos = i + 1;
      out += hexTable[0xC0 | (c >> 6)] + hexTable[0x80 | (c & 0x3F)];
      continue;
    }
    if (c < 0xD800 || c >= 0xE000) {
      lastPos = i + 1;
      out += hexTable[0xE0 | (c >> 12)] +
        hexTable[0x80 | ((c >> 6) & 0x3F)] +
        hexTable[0x80 | (c & 0x3F)];
      continue;
    }
    ++i;
    if (i >= str.length) throw new Error('ERR_INVALID_URI');
    const c2 = str.charCodeAt(i) & 0x3FF;
    lastPos = i + 1;
    const cFull = 0x10000 + (((c & 0x3FF) << 10) | c2);
    out += hexTable[0xF0 | (cFull >> 18)] +
      hexTable[0x80 | ((cFull >> 12) & 0x3F)] +
      hexTable[0x80 | ((cFull >> 6) & 0x3F)] +
      hexTable[0x80 | (cFull & 0x3F)];
  }
  if (lastPos === 0) return str;
  if (lastPos < str.length) return out + str.slice(lastPos);
  return out;
}

/** CanonicalURI：路径按 '/' 分段逐段编码后拼接，末尾补 '/'。 */
function canonicalURI(pathname) {
  const input = pathname || '';
  const uriList = input.split('/');
  const uri = uriList.map((seg) => urlEncode(seg));
  let urlpath = uri.join('/');
  if (urlpath[urlpath.length - 1] !== '/') {
    urlpath = urlpath + '/';
  }
  return urlpath;
}

/** CanonicalQueryString：查询参数按键排序，值排序后拼接。 */
function canonicalQueryString(searchParams) {
  const keys = [];
  for (const key of searchParams.keys()) keys.push(key);
  keys.sort();
  const arr = [];
  for (const key of keys) {
    const ke = urlEncode(key);
    const values = searchParams.getAll(key);
    values.sort();
    for (const v of values) {
      arr.push(ke + '=' + urlEncode(v));
    }
  }
  return arr.join('&');
}

/**
 * CanonicalHeaders：按 signed headers 顺序，name:value\n（value 去首尾空格）。
 * 注意：allHeaders 的 key 可能保留原始大小写，因此先构建小写 key 的查找表，
 * 否则会取到 undefined，导致规范请求错误、签名不匹配（表现为 APIG.0602 等）。
 *
 * 防御性检查：若同一头名以不同大小写重复出现（如 Content-Type 与 content-type），
 * 规范化时会后值覆盖前值，签名与请求实际头不一致导致 APIG.0301 验签失败。
 * 此处检测到重复时通过 console.warn 输出提示，便于调用方排查。
 */
function canonicalHeaders(allHeaders, signedHeaders) {
  const normalized = {};
  const seen = {};
  const duplicates = [];
  for (const k of Object.keys(allHeaders)) {
    const lowerK = k.toLowerCase();
    if (seen[lowerK] && !duplicates.includes(lowerK)) {
      duplicates.push(lowerK);
    }
    seen[lowerK] = true;
    normalized[lowerK] = allHeaders[k];
  }
  if (duplicates.length > 0) {
    console.warn(`[V11Signer] 检测到重复请求头（将使用最后出现的值）: ${duplicates.join(', ')}`);
  }
  const arr = [];
  for (const k of signedHeaders) {
    arr.push(k + ':' + String(normalized[k]).trim());
  }
  return arr.join('\n') + '\n';
}

/** sha256 hex。 */
function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/** hmac-sha256 hex。 */
function hmacSha256Hex(key, str) {
  return crypto.createHmac('sha256', key).update(str, 'utf8').digest('hex');
}

/**
 * HKDF-SHA256 派生密钥，返回 hex 字符串。
 * 严格对齐官方 signer_v11.py 的 _hkdf：salt = AK，ikm = SK，info = credential_scope。
 */
function hkdfGetDerKeySha256(accessKey, secretKey, credentialScope) {
  const salt = Buffer.from(accessKey, 'utf8');
  const ikm = Buffer.from(secretKey, 'utf8');
  const info = Buffer.from(credentialScope, 'utf8');
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  let okm = Buffer.alloc(0);
  let t = Buffer.alloc(0);
  const length = 32;
  const rounds = Math.ceil((length + 32) / 32);
  for (let i = 1; i <= rounds; ++i) {
    const newInfo = Buffer.concat([t, info, Buffer.from([i])]);
    t = crypto.createHmac('sha256', prk).update(newInfo).digest();
    okm = Buffer.concat([okm, t], okm.length + t.length);
  }
  return okm.slice(0, length).toString('hex').toLowerCase();
}

/** 当前 GMT 时间，格式 YYYYMMDDTHHMMSSZ。 */
function getTime() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getUTCFullYear() +
    pad(d.getUTCMonth() + 1) +
    pad(d.getUTCDate()) +
    'T' +
    pad(d.getUTCHours()) +
    pad(d.getUTCMinutes()) +
    pad(d.getUTCSeconds()) +
    'Z'
  );
}

/**
 * V11Signer：使用 AK/SK 对 APIG 请求做 V11-HMAC-SHA256 签名。
 * 仅适用于 APIG 网关接口（签名作用域服务名固定为 apic）。
 */
class V11Signer {
  constructor(options = {}) {
    this.Key = '';
    this.Secret = '';
    this.region = options.region || '';
  }

  /**
   * 对请求签名，返回签名后的完整请求头（含 Authorization / x-sdk-date / host）。
   * @param {string} method   HTTP 方法（如 GET/POST）
   * @param {string} url      完整 URL（https://{apig-host}{path}[?query]）
   * @param {Object} [headers] 请求头
   * @param {string} [body]    请求体（字符串）
   * @returns {Object} 签名后的请求头
   */
  sign(method, url, headers = {}, body = '') {
    const parsedUrl = new URL(url);

    const allHeaders = {};
    for (const k of Object.keys(headers)) allHeaders[k] = headers[k];
    if (!Object.keys(allHeaders).some((k) => k.toLowerCase() === 'x-sdk-date')) {
      allHeaders['x-sdk-date'] = getTime();
    }
    if (!Object.keys(allHeaders).some((k) => k.toLowerCase() === 'host')) {
      allHeaders['host'] = parsedUrl.host;
    }

    const signedHeaders = Object.keys(allHeaders)
      .map((k) => k.toLowerCase())
      .sort();

    const canonicalURIStr = canonicalURI(parsedUrl.pathname);
    const canonicalQueryStringStr = canonicalQueryString(parsedUrl.searchParams);
    const canonicalHeadersStr = canonicalHeaders(allHeaders, signedHeaders);
    const payloadHash = body ? sha256Hex(body) : EMPTY_BODY_SHA256;

    const canonicalRequest = [
      method.toUpperCase(),
      canonicalURIStr,
      canonicalQueryStringStr,
      canonicalHeadersStr,
      signedHeaders.join(';'),
      payloadHash
    ].join('\n');

    const canonicalRequestHash = sha256Hex(canonicalRequest);

    const time = allHeaders['x-sdk-date'];
    const formattedDate = time.substring(0, 8);
    const credentialScope = formattedDate + '/' + this.region + '/' + APIC_SERVICE;

    const stringToSign =
      'V11-HMAC-SHA256\n' +
      time + '\n' +
      credentialScope + '\n' +
      canonicalRequestHash;

    const realUseSecret = hkdfGetDerKeySha256(this.Key, this.Secret, credentialScope);
    const signature = hmacSha256Hex(realUseSecret, stringToSign);

    allHeaders['Authorization'] =
      'V11-HMAC-SHA256 Credential=' + this.Key + '/' + credentialScope +
      ', SignedHeaders=' + signedHeaders.join(';') +
      ', Signature=' + signature;

    return allHeaders;
  }
}

module.exports = { V11Signer };


/***/ }),

/***/ 849:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * 最小 fetch polyfill（基于 Node 内置 http/https，零第三方依赖）。
 *
 * 背景：GitCode 插件 runtime 为 node16（action.yml runs.using: node16），无全局 fetch。
 * @openlibing/huaweicloud-oidc-client 的 http.js 在全局 fetch 缺失时回退 require('undici')，
 * 而 undici 未随 ncc 打包产物内联，会导致 "Cannot find module 'undici'"。
 * 此处仅在全局 fetch 缺失时注入，覆盖 SDK sendRequest 的 POST APIG 上报（JSON body）。
 * 不影响 node18+（已有全局 fetch）的环境。
 */

const http = __nccwpck_require__(611);
const https = __nccwpck_require__(692);

/** fetch 响应兼容对象：status / headers.forEach / text() */
class PolyfillHeaders {
  constructor(raw) {
    this._raw = {};
    for (const k of Object.keys(raw || {})) {
      this._raw[k.toLowerCase()] = raw[k];
    }
  }
  forEach(cb) {
    for (const k of Object.keys(this._raw)) {
      cb(this._raw[k], k);
    }
  }
}

function installFetchPolyfill() {
  if (typeof globalThis.fetch === 'function') {
    return; // node 18+ 已有全局 fetch，无需注入
  }

  globalThis.fetch = function fetchPolyfill(url, options) {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const transport = urlObj.protocol === 'https:' ? https : http;
      const method = (options && options.method) || 'GET';
      const headers = Object.assign({}, options && options.headers);
      const body = options && options.body;
      if (body) {
        headers['Content-Length'] = Buffer.byteLength(body);
      }

      const req = transport.request({
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method,
        headers,
        timeout: 30000
      }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          resolve({
            status: res.statusCode,
            headers: new PolyfillHeaders(res.headers),
            text: () => Promise.resolve(raw)
          });
        });
      });

      req.on('error', (e) => reject(new Error(`${method} ${url}: ${e.message}`)));
      req.on('timeout', () => req.destroy(new Error(`fetch polyfill timeout after 30000ms: ${method} ${url}`)));
      if (body) {
        req.write(body);
      }
      req.end();
    });
  };
}

module.exports = { installFetchPolyfill };


/***/ }),

/***/ 337:
/***/ ((module) => {

module.exports = eval("require")("undici");


/***/ }),

/***/ 317:
/***/ ((module) => {

"use strict";
module.exports = require("child_process");

/***/ }),

/***/ 982:
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 611:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 692:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 857:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ }),

/***/ 928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __nccwpck_require__(136);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;