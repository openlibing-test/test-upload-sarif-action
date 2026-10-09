/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 3:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const { installFetchPolyfill } = __nccwpck_require__(776);
// GitCode 插件 runtime 为 node16，无全局 fetch；注入最小 polyfill，否则
// OIDC SDK 会回退 require('undici') 导致 "Cannot find module 'undici'"。
installFetchPolyfill();

const { execSync } = __nccwpck_require__(317);
const fs = __nccwpck_require__(896);
const path = __nccwpck_require__(928);
const os = __nccwpck_require__(857);
const ObsClient = __nccwpck_require__(869);

const CodeCheckReportParser = __nccwpck_require__(190);
const SarifGenerator = __nccwpck_require__(628);
const SarifNormalizer = __nccwpck_require__(634);
const SarifUriNormalizer = __nccwpck_require__(316);
const CodeArtsCheckApi = __nccwpck_require__(478);

// OIDC 签名 SDK：APIG V11-HMAC-SHA256 签名 + HTTPS 请求 + 自包含 OIDC 换证。
// getCredentials() 通过 Actions 兼容流水线环境变量（ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN）
// 自申请 OIDC ID Token，再调用华为云 STS AssumeAgencyWithOIDC 换取临时 AK/SK/SecurityToken，
// 无需在 workflow 中额外运行 huaweicloud-oidc-auth 插件（仅需声明 permissions: id-token: write）。
let V11Signer = null;
let sendRequest = null;
let getCredentials = null;
let configure = null;
try {
  ({ V11Signer, sendRequest, getCredentials, configure } = __nccwpck_require__(693));
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
// 上传端点 server 由 OIDC SDK configure 动态返回 region，不在此写死
const OBS_KEY_ROOT = 'code-arts-check-results'; // buildToolPrefix 兜底前缀（工具名缺失时）
const OBS_BUCKET = 'openlibing-gitcode-action';
const OBS_READ_ENDPOINT = 'https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com';

const REPORT_EXT = ['.md', '.markdown'];
const SARIF_EXT = ['.sarif'];
// CodeArts region 解析优先级：input > codeCheck_task_url > 环境变量 > 默认 cn-north-4
const REGION_ENV_CANDIDATES = ['CODEARTS_REGION', 'CODEARTS_IAM_REGION', 'CLOUD_REGION', 'CLOUD_REGION_ID', 'REGION_ID'];

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

function execCapture(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf-8', shell: '/bin/bash' }).trim();
  } catch (e) {
    return '';
  }
}

/**
 * 同步指数退避重试：默认 3 次，失败后 sleep(2^(n-1) 秒) 再试。
 * 用于 OBS 上传等同步命令，降低网络抖动导致的数据丢失风险。
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
 * 用于 APIG 回调、OBS SDK 上传等异步请求。
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

function resolveRegion() {
  const fromInput = getInput('region');
  if (fromInput) {
    console.log(`[INFO] 使用 region（input）: ${fromInput}`);
    return fromInput;
  }
  for (const name of REGION_ENV_CANDIDATES) {
    const val = process.env[name];
    if (val && val.trim()) {
      console.log(`[INFO] 使用 region（环境变量 ${name}）: ${val.trim()}`);
      return val.trim();
    }
  }
  console.log('[INFO] 使用 region（默认）: cn-north-4');
  return 'cn-north-4';
}

// ---------- 报告定位与转换 ----------

function isReportFile(name) {
  const lower = name.toLowerCase();
  return REPORT_EXT.some((ext) => lower.endsWith(ext));
}

function isSarifFile(name) {
  const lower = name.toLowerCase();
  return SARIF_EXT.some((ext) => lower.endsWith(ext));
}

function hasWildcard(p) {
  return /[*?]/.test(p);
}

/** 通配符匹配：* 匹配任意字符（含空），? 匹配单个字符 */
function globMatch(pattern, name) {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${regexStr}$`).test(name);
}

/** 在目录中按文件名通配符匹配报告文件 */
function globReportFiles(patternPath) {
  const dir = path.dirname(patternPath);
  const namePattern = path.basename(patternPath);
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return [];
  let entries = [];
  try {
    entries = fs.readdirSync(dir);
  } catch (e) {
    return [];
  }
  return entries
    .filter((entry) => (isReportFile(entry) || isSarifFile(entry)) && globMatch(namePattern, entry))
    .map((entry) => path.join(dir, entry));
}

/** 扫描目录下所有报告/SARIF 文件 */
function scanReportDir(dirPath) {
  let entries = [];
  try {
    entries = fs.readdirSync(dirPath);
  } catch (e) {
    return [];
  }
  return entries
    .filter((entry) => isReportFile(entry) || isSarifFile(entry))
    .map((entry) => path.join(dirPath, entry));
}

/** 尝试解析单个候选路径（通配符/目录/文件），未命中返回 null */
function tryResolveCandidate(candidate) {
  if (hasWildcard(candidate)) {
    const matched = globReportFiles(candidate);
    return matched.length > 0 ? { kind: 'glob', files: matched } : null;
  }
  if (!fs.existsSync(candidate)) return null;
  const stat = fs.statSync(candidate);
  if (stat.isDirectory()) {
    const files = scanReportDir(candidate);
    return files.length > 0 ? { kind: 'dir', files, dir: candidate } : null;
  }
  return { kind: 'file', files: [candidate] };
}

/**
 * 定位报告文件：支持单文件 / 目录 / 通配符（如 /tmp/step_summary_*.md）
 * 依次尝试：原路径 -> WORKSPACE 拼接 -> Git 目录拼接。
 * @returns {{kind: 'glob'|'dir'|'file', files: string[], dir?: string}|null}
 */
function resolveReportFiles(reportFile, workspace) {
  const candidates = [reportFile];
  if (workspace) {
    candidates.push(path.join(workspace, reportFile));
  }
  for (const candidate of candidates) {
    const found = tryResolveCandidate(candidate);
    if (found) return found;
  }
  const gitDir = execCapture(`find "${escapeShellArg(workspace)}" -maxdepth 3 -name ".git" -type d 2>/dev/null | head -1`);
  if (gitDir) {
    const found = tryResolveCandidate(path.join(path.dirname(gitDir), reportFile));
    if (found) return found;
  }
  return null;
}

/**
 * 转换单个文件为 SARIF 文件。
 *
 * 按输入类型分发：
 * - 原生 SARIF（.sarif，如 CodeArts Check 导出）→ SarifNormalizer 规范化（工具名统一为
 *   CodeArtsCheck（无空格）、补齐 partialFingerprints），保证 openlibing-codecheck 可消费；
 * - Markdown 报告（.md/.markdown）→ CodeCheckReportParser 解析后由 SarifGenerator 生成。
 */
function convertReportFile(reportFile, outDir) {
  let sarif;
  let issueCount;
  const warnings = [];
  if (isSarifFile(reportFile)) {
    const normalized = SarifNormalizer.normalizeFile(reportFile);
    sarif = normalized.sarif;
    issueCount = normalized.issueCount;
    warnings.push(...normalized.warnings);
  } else {
    const parsed = CodeCheckReportParser.parseFile(reportFile);
    sarif = SarifGenerator.generate(parsed);
    issueCount = parsed.issues.length;
    warnings.push(...parsed.warnings);
  }
  // 输出文件名包含来源父目录名（如 module-a-report.sarif），
  // 避免不同目录的同名报告（module-a/report.md 与 module-b/report.md）互相覆盖。
  const parentDir = path.basename(path.dirname(reportFile));
  const stem = path.basename(reportFile).replace(/\.(md|markdown|sarif)$/i, '');
  const outName = (parentDir && parentDir !== '.' ? `${parentDir}-${stem}` : stem) + '.sarif';
  const outPath = path.join(outDir, outName);
  fs.writeFileSync(outPath, JSON.stringify(sarif, null, 2), 'utf-8');
  return { outPath, issueCount, warnings };
}

/** 批量转换报告文件，返回生成的 SARIF 文件路径列表 */
function convertReports(reportFiles, outDir) {
  const sarifFiles = [];
  const seenNames = new Set();
  for (const reportFile of reportFiles) {
    const { outPath, issueCount, warnings } = convertReportFile(reportFile, outDir);
    // 同一父目录下的同名报告（如 report.md 与 report.sarif）转换结果仍可能重名，
    // 检测到输出重名时明确报错退出，避免静默覆盖导致报告内容丢失。
    const outName = path.basename(outPath);
    if (seenNames.has(outName)) {
      console.log(`[ERROR] 转换输出文件重名: ${outName}（来源 ${reportFile}），请检查 report_file 是否包含同名报告`);
      setOutput('result', 'failed');
      process.exit(1);
    }
    seenNames.add(outName);
    warnings.forEach((w) => console.log(`[WARN] ${path.basename(reportFile)}: ${w}`));
    console.log(`[OK] 转换完成: ${path.basename(reportFile)} -> ${path.basename(outPath)} (${issueCount} 条问题)`);
    sarifFiles.push(outPath);
  }
  return sarifFiles;
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

/** 读取并解析 CodeArts 任务参数（codecheck_task_url 未显式配置时兜底） */
function readTaskParams() {
  let projectId = getInput('project_id');
  let taskName = getInput('task_name');
  let taskId = getInput('task_id');
  let region = getInput('region');
  const taskUrl = getInput('codecheck_task_url');

  if (taskUrl) {
    const parsed = CodeArtsCheckApi.parseTaskUrl(taskUrl);
    if (parsed) {
      projectId = projectId || parsed.projectId;
      taskId = taskId || parsed.taskId;
      region = region || parsed.region;
      console.log(`[INFO] 从 codeCheck_task_url 解析 project_id/task_id/region/jobId: ${parsed.projectId} / ${parsed.taskId} / ${parsed.region} / ${parsed.jobId}`);
    } else {
      console.log(`[WARN] 无法从 codeCheck_task_url 解析参数: ${taskUrl}`);
    }
  }
  region = region || resolveRegion();
  return { projectId, taskName, taskId, region };
}

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

/** 从 SARIF 文件提取工具名（runs[0].tool.driver.name），用于构建产物类型与 OBS 路径前缀；解析失败返回空 */
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

/**
 * 将工具名转换为 OBS 路径前缀：{toolName}-results（如 CodeArtsCheck -> codeartscheck-results）。
 * 工具名缺失/无法解析时兜底为通用前缀 code-arts-check-results。
 */
function buildToolPrefix(toolName) {
  const name = (toolName || '').trim();
  if (!name) return OBS_KEY_ROOT;
  const safe = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return safe ? `${safe}-results` : OBS_KEY_ROOT;
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
 * 为 SARIF results 补充代码上下文，供前端正确展示与高亮：
 * - region.snippet：对齐为问题行本身（或多行问题范围）的源码文本。前端用它做内容匹配定位
 *   高亮行；工具自带 snippet 若与文件实际内容不一致也会被覆盖，保证匹配稳定命中。
 * - contextRegion.snippet：问题行（或多行范围）上下各 2 行的上下文窗口，供前端展示上下文。
 *   工具自带的不同窗口（如 3 行）也会被覆盖为统一窗口，保证前端展示固定 5 行；源码不可读时静默跳过。
 * @returns {number} 成功补充的 result 数量
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
    const src = resolveSourceFile(loc.artifactLocation.uri, sourceRoots);
    if (!src) continue;
    let lines;
    try {
      lines = fs.readFileSync(src, 'utf-8').split(/\r?\n/);
    } catch (e) {
      continue;
    }
    const startLine = region.startLine;
    const endLine = region.endLine || startLine;
    const problemLines = lines.slice(startLine - 1, Math.min(lines.length, endLine));
    if (!problemLines.length) continue;
    let changed = false;

    // 1) region.snippet 对齐为问题行本身（前端定位高亮依赖，必须与文件内容一致）
    const problemText = problemLines.join('\n');
    if (!region.snippet || region.snippet.text !== problemText) {
      region.snippet = { text: problemText };
      changed = true;
    }

    // 2) contextRegion：固定为问题范围上下各 2 行的窗口（越界自动裁剪），前端展示统一 5 行；
    //    工具自带的不同窗口（如 3 行）也一律覆盖对齐
    const ctxStart = Math.max(1, startLine - 2);
    const ctxEnd = Math.min(lines.length, endLine + 2);
    const ctxLines = lines.slice(ctxStart - 1, ctxEnd);
    if (ctxLines.length) {
      const ctxText = ctxLines.join('\n');
      const hasCtxSnippet =
        loc.contextRegion && loc.contextRegion.snippet && loc.contextRegion.snippet.text;
      if (!hasCtxSnippet || loc.contextRegion.snippet.text !== ctxText) {
        loc.contextRegion = {
          startLine: ctxStart,
          endLine: ctxEnd,
          snippet: { text: ctxText }
        };
        changed = true;
      }
    }

    if (changed) enriched++;
  }
  return enriched;
}

/** 遍历 SARIF 文件，缺少 region.snippet / contextRegion 时补齐并写回原文件 */
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
      console.log(`[OK] ${path.basename(f)}: 已补充 ${n} 个 result 的代码上下文（snippet 对齐问题行 + contextRegion 窗口）`);
      continue;
    }
    // n=0 时区分原因：无 result / 已含完整上下文（幂等）/ 源码不可读
    const run = sarifObj.runs && sarifObj.runs[0];
    const results = (run && run.results) || [];
    if (results.length === 0) {
      console.log(`[INFO] ${path.basename(f)}: 无 result，跳过代码上下文补齐`);
      continue;
    }
    const allHaveContext = results.every(r => {
      const loc = r && r.locations && r.locations[0] && r.locations[0].physicalLocation;
      return (
        loc &&
        loc.region &&
        loc.region.snippet &&
        loc.region.snippet.text &&
        loc.contextRegion &&
        loc.contextRegion.snippet &&
        loc.contextRegion.snippet.text
      );
    });
    if (allHaveContext) {
      console.log(`[INFO] ${path.basename(f)}: 全部 result 已含 snippet 与 contextRegion，无需补充`);
    } else {
      console.log(`[INFO] ${path.basename(f)}: 源码不可读，无法补齐代码上下文（检查 source_path 与 SARIF uri 是否指向工作区内文件）`);
    }
  }
}

/** 收集本地 sarif_file 输入指向的 SARIF 文件（单文件/多文件/目录，逗号分隔） */
function collectSarifFiles(sarifFile, workspace) {
  const sarifFiles = [];
  const missingPaths = [];
  const sarifPaths = sarifFile.split(',').map(s => s.trim()).filter(Boolean);
  for (const rawPath of sarifPaths) {
    let p = rawPath;
    if (!fs.existsSync(p)) {
      p = path.join(workspace, rawPath);
    }
    if (!fs.existsSync(p)) {
      const gitDir = execCapture(`find "${escapeShellArg(workspace)}" -maxdepth 3 -name ".git" -type d 2>/dev/null | head -1`);
      if (gitDir) {
        p = path.join(path.dirname(gitDir), rawPath);
      }
    }
    if (!fs.existsSync(p)) {
      missingPaths.push(rawPath);
      continue;
    }
    if (fs.statSync(p).isDirectory()) {
      console.log(`[INFO] 输入为目录: ${p}，扫描其中所有 .sarif 文件`);
      const entries = fs.readdirSync(p);
      const found = [];
      for (const entry of entries) {
        if (entry.toLowerCase().endsWith('.sarif')) {
          found.push(path.join(p, entry));
        }
      }
      if (found.length === 0) {
        console.log(`[WARN] 目录中未找到 .sarif 文件: ${p}`);
      }
      sarifFiles.push(...found);
    } else {
      sarifFiles.push(p);
      console.log(`[OK] SARIF 文件: ${p}`);
    }
  }
  return { sarifFiles, missingPaths };
}

/** 解析仓库根目录：优先取 workspace 下 git 仓库根（兼容 repo_workspace 嵌套），兜底 workspace 本身 */
function resolveRepoRoot(workspace) {
  const gitDir = execCapture(`find "${escapeShellArg(workspace)}" -maxdepth 3 -name ".git" -type d 2>/dev/null | head -1`);
  if (gitDir) {
    console.log(`[INFO] 仓库根目录（git 根）: ${path.dirname(gitDir)}`);
    return path.dirname(gitDir);
  }
  console.log(`[INFO] 仓库根目录（兜底 workspace）: ${workspace}`);
  return workspace;
}

/** 对 SARIF 文件批量做 uri 归一化（机器绝对路径 -> 相对仓库根），原地写回变更文件 */
function normalizeSarifUriFiles(sarifFiles, repoRoot) {
  let changedFiles = 0;
  let changedResults = 0;
  for (const f of sarifFiles) {
    let sarifObj;
    try {
      sarifObj = JSON.parse(fs.readFileSync(f, 'utf-8'));
    } catch (e) {
      console.log(`[WARN] uri 归一化跳过（无法解析 SARIF）: ${path.basename(f)}`);
      continue;
    }
    const n = SarifUriNormalizer.normalizeSarifUris(sarifObj, repoRoot);
    if (n > 0) {
      fs.writeFileSync(f, JSON.stringify(sarifObj, null, 2), 'utf-8');
      changedFiles += 1;
      changedResults += n;
    }
  }
  if (changedFiles > 0 || changedResults > 0) {
    console.log(`[INFO] uri 归一化完成: ${changedFiles} 个文件 / ${changedResults} 条 result`);
  } else {
    console.log('[INFO] uri 归一化: 全部 result 已是相对仓库根路径，无需变更');
  }
}

// ---------- 主流程 ----------

async function run() {
  const reportFile = getInput('report_file');
  const sarifFile = getInput('sarif_file');
  const category = getInput('category');
  const envType = (getInput('env_type') || 'prod').toLowerCase();
  const isBetaEnv = envType === 'beta';
  const workflowRunId = process.env.ATOMGIT_RUN_ID || '';

  // CodeArts Check API 凭证：优先 runner 注入的 IAM AK/SK（老方式），兜底 SDK 换取的 OIDC 临时凭证。
  // defects-detail 接口暂不支持 OIDC（STS + X-Security-Token）调用，老 AK/SK 是首选。
  const legacyAk = process.env.CODEARTS_IAM_AK || '';
  const legacySk = process.env.CODEARTS_IAM_SK || '';

  const { projectId, taskName, taskId, region } = readTaskParams();

  const callbackUrl = (isBetaEnv ? OIDC_BETA_BASE : OIDC_PROD_BASE) + OIDC_API_PREFIX + CALLBACK_PATH;

  console.log('===== openlibing-upload-sarif 启动 =====');
  console.log(`[INFO] 环境类型: ${isBetaEnv ? 'beta (测试环境)' : 'prod (正式环境)'}`);
  console.log('[INFO] 认证模式: OIDC 联邦认证（SDK 自包含换证，无需 huaweicloud-oidc-auth 插件）');
  console.log(`[INFO] 回调地址: ${callbackUrl}`);
  console.log(`[INFO] CodeArts Check API 凭证: ${legacyAk && legacySk ? 'runner 注入 IAM AK/SK（老方式）' : 'OIDC 临时凭证（兜底）'}`);

  console.log('\n===== [1] 校验参数 =====');
  const apiReady = Boolean(legacyAk && legacySk && projectId && taskId);
  if (!reportFile && !sarifFile && !apiReady) {
    // 无数据源不按失败退出：版本级触发（push/workflow_dispatch）且上游扫描无告警时，
    // 不会产出 SARIF 报告（如 pre-commit-action 串接场景），此时无内容可上传属正常情况。
    console.log('[WARN] 未配置任何数据源（report_file / sarif_file / CodeArts API 参数），无扫描报告可上传，按成功退出');
    console.log('[INFO] 常见原因：上游扫描无告警未生成 SARIF 报告（如 pre-commit 检查全部通过）');
    setOutput('result', 'success');
    return;
  }
  if (!V11Signer || !sendRequest || !getCredentials || !configure) {
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

  const codeartsAk = legacyAk || cred.accessKeyId;
  const codeartsSk = legacySk || cred.secretAccessKey;
  const codeartsToken = legacyAk && legacySk ? '' : cred.securityToken;

  const tmpDir = os.tmpdir();
  const convertOutDir = path.join(tmpDir, 'sarif-convert-output');
  fs.mkdirSync(convertOutDir, { recursive: true });

  console.log('\n===== [3] 收集并生成 SARIF =====');
  const workspace = process.env.WORKSPACE || process.cwd();
  const sarifFiles = [];
  let apiConsumed = false;

  // 数据源 1：report_file（CodeArts Markdown 报告或原生 SARIF，如 codeArts 插件能力）
  if (reportFile) {
    const resolved = resolveReportFiles(reportFile, workspace);
    const nonEmptyFiles = resolved ? resolved.files.filter((f) => fs.statSync(f).size > 0) : [];
    if (nonEmptyFiles.length > 0) {
      const converted = convertReports(nonEmptyFiles, convertOutDir);
      sarifFiles.push(...converted);
      console.log(`[INFO] 数据源: 报告文件（${nonEmptyFiles.length} 个非空文件）`);
    } else {
      console.log('[WARN] report_file 未找到非空报告文件');
    }
  }

  // 数据源 2：CodeArts Check API（report_file 未产出且 API 参数就绪时兜底）
  if (sarifFiles.length === 0 && apiReady) {
    console.log('[INFO] 数据源: CodeArts Check API（不读取本地报告文件）');
    apiConsumed = true;
    try {
      const api = new CodeArtsCheckApi({ ak: codeartsAk, sk: codeartsSk, token: codeartsToken, region });
      const parsed = await api.fetchIssues({ projectId, taskId, taskName });
      parsed.warnings.forEach((w) => console.log(`[WARN] ${w}`));
      const sarif = SarifGenerator.generate(parsed);
      const outName = `${parsed.task.taskName || 'codearts-check'}.sarif`;
      const outPath = path.join(convertOutDir, outName);
      fs.writeFileSync(outPath, JSON.stringify(sarif, null, 2), 'utf-8');
      sarifFiles.push(outPath);
      console.log(`[OK] 转换完成(CodeArts API): ${outName} (${parsed.issues.length} 条问题)`);
    } catch (err) {
      console.log(`[ERROR] CodeArts Check API 拉取失败: ${err.message}`);
      setOutput('result', 'failed');
      process.exit(1);
    }
  } else if (sarifFiles.length === 0 && !apiReady && !sarifFile) {
    console.log('[ERROR] 未找到有效 SARIF（检查 report_file / sarif_file 路径，或配置 CodeArts API 参数）');
    setOutput('result', 'failed');
    process.exit(1);
  }

  // 数据源 3：sarif_file（本地 SARIF 文件，与报告/API 数据源可并存）
  if (sarifFile) {
    const { sarifFiles: localFiles, missingPaths } = collectSarifFiles(sarifFile, workspace);
    if (missingPaths.length > 0) {
      console.log(`[ERROR] SARIF 路径不存在: ${missingPaths.join(', ')}`);
      setOutput('result', 'failed');
      process.exit(1);
    }
    // 与 report_file 传入的 .sarif 保持一致：规范化（工具名统一 + 补齐指纹），
    // 否则缺指纹的扫描结果会被后端跳过、不入库。
    for (const f of localFiles) {
      try {
        const { sarif, issueCount, warnings } = SarifNormalizer.normalizeFile(f);
        fs.writeFileSync(f, JSON.stringify(sarif, null, 2), 'utf-8');
        warnings.forEach((w) => console.log(`[WARN] ${path.basename(f)}: ${w}`));
        console.log(`[INFO] SARIF 规范化: ${path.basename(f)} (${issueCount} 条问题)`);
      } catch (e) {
        console.log(`[WARN] SARIF 规范化跳过（无法解析或缺少 runs/tool.driver）: ${path.basename(f)}: ${e.message}`);
      }
    }
    sarifFiles.push(...localFiles);
  }

  if (sarifFiles.length === 0) {
    console.log('[ERROR] 未找到任何 SARIF 文件（检查 report_file / sarif_file 路径，或配置 CodeArts API 参数）');
    setOutput('result', 'failed');
    process.exit(1);
  }

  console.log(`[OK] 共收集 ${sarifFiles.length} 个 SARIF 文件:`);
  sarifFiles.forEach(f => console.log(`  - ${path.basename(f)}`));

  console.log('\n===== [3.5] SARIF uri 归一化（机器绝对路径 -> 相对仓库根） =====');
  // 部分工具（如 spotbugs）输出 runner 机器绝对路径，部分输出相对路径；统一剥离仓库根前缀，
  // 保证后端告警路径可读、无 snippet 时指纹跨机器稳定。
  const repoRoot = resolveRepoRoot(workspace);
  normalizeSarifUriFiles(sarifFiles, repoRoot);

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

  console.log('\n===== [5] 构建 OBS 路径 =====');
  const repoBaseName = (process.env.ATOMGIT_REPOSITORY || process.env.GIT_REPOSITORY || '').split('/').pop() || 'unknown-repo';
  const now = new Date();
  const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}.${String(now.getHours()).padStart(2, '0')}`;
  // 统一路径结构：{工具名前缀}-results/{仓库名}/{yyyyMMdd}.{HH}/{runId|manual}/{文件名}
  const timePath = `${repoBaseName}/${dateStr}/${workflowRunId || 'manual'}`;
  // 路径前缀按工具名动态拼装（如 spotbugs-results / codeartscheck-results），工具名缺失时兜底 code-arts-check-results
  const sarifUploads = sarifFiles.map((f) => {
    const toolName = extractToolName(f);
    const keyPrefix = `${buildToolPrefix(toolName)}/${timePath}`;
    const name = path.basename(f);
    return {
      file: f,
      name,
      toolName,
      keyPrefix,
      downloadUrl: `${OBS_READ_ENDPOINT}/${keyPrefix}/${name}`
    };
  });
  sarifUploads.forEach(u => console.log(`[INFO] OBS 路径: obs://${OBS_BUCKET}/${u.keyPrefix}/${u.name}`));

  console.log('\n===== [6] 上传到 OBS（esdk-obs-nodejs + 失败指数退避重试，默认 3 次） =====');
  // 回调需要的 SARIF 下载 URL 列表（后端 SarifParseServiceImpl 直接按该列表解析，无需 build-result.json）
  const sarifDownloadUrls = sarifUploads.map(u => u.downloadUrl);
  const isSingleFile = sarifFiles.length === 1;

  // server 由 OIDC SDK configure 动态返回 region，避免把区域写死
  const { region: obsRegion } = configure({});
  const server = `https://obs.${obsRegion}.myhuaweicloud.com`;
  // esdk-obs-nodejs 的 initFactory 为 fire-and-forget（内部 await refresh 后才设置签名上下文），
  // 构造后立即 putObject 会读到 null signatureContext（Cannot read properties of null (reading 'signature')），
  // 此处让出一个微任务等待初始化完成。
  const client = new ObsClient({
    access_key_id: cred.accessKeyId,
    secret_access_key: cred.secretAccessKey,
    security_token: cred.securityToken,
    server
  });
  await Promise.resolve();

  // putObject 结果校验：HTTP 状态 2xx 视为成功，否则抛错（供 withRetryAsync 重试）
  const assertUploadOk = (result, label) => {
    const msg = (result && result.CommonMsg) || {};
    if (!(msg.Status >= 200 && msg.Status < 300)) {
      throw new Error(`${label} 上传失败 (${msg.Status})${msg.Code ? ' [' + msg.Code + ']' : ''}: ${msg.Message || '未知错误'}`);
    }
  };

  for (let i = 0; i < sarifUploads.length; i++) {
    const u = sarifUploads[i];
    console.log(`[INFO] 上传 SARIF 文件 (${i + 1}/${sarifUploads.length}): ${u.name}`);
    try {
      // ACL: 'public-read'：后端 SarifParseServiceImpl 通过匿名 HTTP GET 下载，对象必须公共读
      await withRetryAsync(() => client.putObject({
        Bucket: OBS_BUCKET,
        Key: `${u.keyPrefix}/${u.name}`,
        SourceFile: u.file,
        ACL: 'public-read'
      }).then(r => assertUploadOk(r, u.name)), { label: `${u.name} 上传` });
    } catch (e2) {
      console.log(`[ERROR] ${u.name} 上传失败: ${e2.message}`);
      setOutput('result', 'failed');
      process.exit(1);
    }
  }
  await client.close();

  console.log('\n================================================================');
  console.log('[INFO] 上传成功');
  console.log('================================================================');

  console.log('\n===== [7] 回调通知（失败指数退避重试，默认 3 次） =====');
  const obsUrls = isSingleFile ? sarifDownloadUrls[0] : sarifDownloadUrls;
  const callbackPayload = {
    repoUrl: process.env.ATOMGIT_REPOSITORY_URL || '',
    pipelineId: process.env.ATOMGIT_PIPELINE_ID || '',
    pipelineName: process.env.PIPELINE_NAME || '',
    pipelineRunId: workflowRunId || '',
    branch: resolveBranch(),
    commitId: process.env.ATOMGIT_SHA || '',
    // 后端 DTO 为 List<String>，恒传数组兼容新旧后端（旧版无 StringOrListDeserializer）
    obsUrl: Array.isArray(obsUrls) ? obsUrls : [obsUrls],
    category: category || '',
    source: 'GITCODE_ACTION',
    sourceRunUrl: buildSourceRunUrl() || ''
  };

  try {
    const callbackResult = await withRetryAsync(() => sendCallbackOidc(callbackUrl, callbackPayload, cred), { label: 'APIG 回调' });
    console.log(`[OK] 回调通知发送成功，回调时间: ${new Date().toISOString()}`);
    console.log(`[INFO] 回调响应: ${JSON.stringify(callbackResult)}`);
    const resultViewUrl = isBetaEnv ? 'https://beta.openlibing.com/apps/codeCheck' : 'https://www.openlibing.com/apps/codeCheck';
    console.log(`查看上传结果解析: ${resultViewUrl}`);
  } catch (err) {
    console.log(`[WARN] 回调通知发送失败: ${err.message}`);
    console.log('[INFO] SARIF 上传已成功，回调失败不影响最终结果');
  }

  setOutput('result', 'success');
}

module.exports = {
  run,
  convertReportFile,
  convertReports,
  resolveReportFiles,
  collectSarifFiles,
  resolveRepoRoot,
  normalizeSarifUriFiles,
  CodeCheckReportParser,
  SarifGenerator,
  SarifNormalizer,
  SarifUriNormalizer,
  CodeArtsCheckApi,
  enrichRegionSnippet,
  enrichSarifFiles,
  resolveSourceFile,
  withRetrySync,
  withRetryAsync,
  buildToolPrefix
};

if (require.main === require.cache[eval('__filename')]) {
  run().catch((err) => {
    console.error(`Action 执行失败: ${sanitizePath(err.message)}`);
    setOutput('result', 'failed');
    process.exit(1);
  });
}


/***/ }),

/***/ 478:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const crypto = __nccwpck_require__(982);
const https = __nccwpck_require__(692);

const ALGORITHM = 'SDK-HMAC-SHA256';

// 华为云问题级别（defectLevel）-> 华为云报告中文级别
const SEVERITY_MAP = {
  '0': '致命',
  '1': '严重',
  '2': '一般',
  '3': '提示'
};

// ============================================================
// 华为云 AK/SK 签名（SDK-HMAC-SHA256，APIG 网关规范）
// 与 openlibing-upload-sarif 的 signApigRequest 保持一致：
// StringToSign 仅 3 行（无 CredentialScope），直接用 SK 做 HMAC-SHA256
// ============================================================

function sha256Hex(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/** RFC3986 编码（空格 -> %20，且对 !'()* 也编码） */
function rfc3986Encode(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

/** 规范化 URI：按 / 分段 RFC3986 编码，末尾补 /（华为云 APIG 签名规范） */
function canonicalURI(uri) {
  const segments = String(uri || '/').split('/');
  const encoded = segments.map((s) => rfc3986Encode(s)).join('/');
  if (encoded.length === 0 || encoded[encoded.length - 1] !== '/') {
    return encoded + '/';
  }
  return encoded;
}

/**
 * 构造 CanonicalRequest
 * signedHeaders 必须包含 host 与 x-sdk-date
 */
function buildCanonicalRequest(method, uri, query, headers, signedHeaders, payload) {
  const canonicalQuery = Object.keys(query)
    .sort()
    .map((k) => `${rfc3986Encode(k)}=${rfc3986Encode(String(query[k]))}`)
    .join('&');

  const canonicalHeaders = signedHeaders
    .map((h) => `${h}:${String(headers[h] || '').trim().replace(/\s+/g, ' ')}\n`)
    .join('');

  const payloadHash = sha256Hex(payload);

  return [
    method,
    canonicalURI(uri),
    canonicalQuery,
    canonicalHeaders,
    signedHeaders.join(';'),
    payloadHash
  ].join('\n');
}

/**
 * 对请求做 AK/SK 签名，返回需要附加的请求头
 * @param {object} opts
 * @param {string} opts.method GET/POST
 * @param {string} opts.uri 请求路径（如 /v2/{project_id}/tasks）
 * @param {object} opts.query 查询参数
 * @param {object} opts.headers 原始请求头（需含 host）
 * @param {string} opts.payload 请求体字符串（GET 为 ''）
 * @param {string} opts.ak
 * @param {string} opts.sk
 * @returns {{'x-sdk-date': string, Authorization: string}}
 */
function signRequest({ method, uri, query = {}, headers = {}, payload = '', ak, sk }) {
  const xSdkDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ

  const allHeaders = { ...headers, 'x-sdk-date': xSdkDate };
  const signedHeaders = ['host', 'x-sdk-date'];

  const canonicalRequest = buildCanonicalRequest(method, uri, query, allHeaders, signedHeaders, payload);
  // 华为云 SDK-HMAC-SHA256：StringToSign 仅 3 行，直接用 SK 做 HMAC-SHA256
  const stringToSign = [ALGORITHM, xSdkDate, sha256Hex(canonicalRequest)].join('\n');
  const signature = crypto.createHmac('sha256', sk).update(stringToSign, 'utf8').digest('hex');

  return {
    'x-sdk-date': xSdkDate,
    Authorization: `${ALGORITHM} Access=${ak}, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`
  };
}

function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error('CodeArts Check API 请求超时（30s）'));
    });
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// ============================================================
// CodeArts Check API 客户端
// ============================================================

class CodeArtsCheckApi {
  /**
   * @param {object} opts
   * @param {string} opts.ak IAM AK（OIDC 临时凭证 HUAWEICLOUD_OIDC_AK）
   * @param {string} opts.sk IAM SK（OIDC 临时凭证 HUAWEICLOUD_OIDC_SK）
   * @param {string} [opts.token] 临时凭证 SecurityToken（OIDC 模式必传，作为 X-Security-Token 请求头）
   * @param {string} [opts.region] 区域，默认 cn-north-4
  */
  constructor({ ak, sk, token = '', region = 'cn-north-4' }) {
    if (!ak || !sk) {
      throw new Error('缺少 CodeArts Check 鉴权凭证（ak/sk）');
    }
    this.ak = ak;
    this.sk = sk;
    this.token = token;
    this.region = region;
    this.host = `codecheck-ext.${region}.myhuaweicloud.com`;
  }

  /**
   * 发起签名请求并解析 JSON 响应
   */
  async request(method, uri, query = {}, body = null) {
    const payload = body === null ? '' : JSON.stringify(body);
    const headers = {
      host: this.host,
      'Content-Type': 'application/json'
    };
    // 临时凭证（OIDC 模式）：SecurityToken 仅作为请求头，不参与签名计算
    if (this.token) {
      headers['X-Security-Token'] = this.token;
    }
    const signed = signRequest({
      method,
      uri,
      query,
      headers,
      payload,
      ak: this.ak,
      sk: this.sk
    });

    const options = {
      hostname: this.host,
      port: 443,
      path: uri + this.buildQueryString(query),
      method,
      headers: { ...headers, ...signed }
    };

    console.log(`[INFO] CodeArts Check API 请求: ${method} https://${this.host}${options.path} | 认证: ${this.token ? 'OIDC 临时凭证 + X-Security-Token' : 'AK/SK 签名'}`);

    const resp = await httpsRequest(options, payload);
    let data;
    try {
      data = JSON.parse(resp.body || '{}');
    } catch (e) {
      throw new Error(`CodeArts Check API 响应不是合法 JSON (HTTP ${resp.status}): ${resp.body.slice(0, 200)}`);
    }
    if (resp.status < 200 || resp.status >= 300) {
      throw new Error(`CodeArts Check API HTTP ${resp.status}: ${resp.body.slice(0, 300)}`);
    }
    return data;
  }

  buildQueryString(query) {
    const keys = Object.keys(query);
    if (keys.length === 0) {
      return '';
    }
    return '?' + keys
      .sort()
      .map((k) => `${rfc3986Encode(k)}=${rfc3986Encode(String(query[k]))}`)
      .join('&');
  }

  /**
   * 获取代码问题列表（分页）
   * GET /v2/tasks/{task_id}/defects-detail
   * （v1 的 /v1/defect/issue-list-by-filter 未在公共网关发布，调用返回 APIGW.0101）
   */
  async listIssues(taskId, { page = 1, pageSize = 100 } = {}) {
    const limit = pageSize || 100;
    const offset = ((page || 1) - 1) * limit;
    const data = await this.request('GET', `/v2/tasks/${taskId}/defects-detail`, { offset, limit });
    return {
      total: data.total || 0,
      info: data.defects || []
    };
  }

  /**
   * 拉取任务全部问题并转换为与报告解析器一致的中间模型
   * @param {object} opts
   * @param {string} opts.projectId
   * @param {string} opts.taskId
   * @param {string} [opts.taskName] 仅用于 SARIF 文件名与日志显示
   * @returns {Promise<{task: object, issues: Array, warnings: Array}>}
   */
  async fetchIssues({ projectId, taskId, taskName }) {
    if (!projectId) {
      throw new Error('缺少 project_id');
    }
    if (!taskId) {
      throw new Error('缺少 task_id（可显式配置，或通过 codecheck_task_url 自动解析）');
    }

    const issues = [];
    const warnings = [];
    let page = 1;
    const pageSize = 200;
    let total = 0;
    // 最多拉取 50 页（10000 条），防止异常循环
    while (page <= 50) {
      const resp = await this.listIssues(taskId, { page, pageSize });
      total = resp.total || 0;
      for (const item of resp.info || []) {
        const issue = CodeArtsCheckApi.buildIssueFromApiItem(item);
        if (issue) {
          issues.push(issue);
        } else {
          warnings.push(`跳过无法解析的问题: ${JSON.stringify(item).slice(0, 200)}`);
        }
      }
      if (issues.length >= total || (resp.info || []).length === 0) {
        break;
      }
      page += 1;
    }

    return {
      task: { taskId, taskName: taskName || '' },
      issues,
      warnings
    };
  }

  /**
   * 将 API 返回的单条问题转换为中间模型
   * 兼容两种响应：ShowTaskDefectsV2（defect_level/rule_id/rule_name/defect_content/file_path/line_number）
   * 与 IssueListByFilter（defectLevel/ruleId/criterionName/fragment.lineNum）
   * @param {object} item 单条问题对象
   * @returns {object|null} 中间模型 {ruleId, ruleName, message, severity, file, line, snippet}
   */
  static buildIssueFromApiItem(item) {
    if (!item) {
      return null;
    }
    const frag = Array.isArray(item.fragment) && item.fragment[0] ? item.fragment[0] : {};
    const severity = SEVERITY_MAP[String(item.defect_level ?? item.defectLevel)] || '一般';
    const ruleId = item.rule_id || item.ruleId || item.ruleRuleId || item.defectType || 'UNKNOWN';
    const line = parseInt(item.line_number ?? frag.line_num ?? frag.lineNum, 10);
    return {
      ruleId,
      ruleName: item.rule_name || item.criterionName || item.defectType || item.ruleId || ruleId,
      message: item.defect_content || frag.description || item.defectType || item.criterionName || '',
      severity,
      file: item.file_path || frag.filePath || item.filePath || item.fileName || '',
      line: Number.isFinite(line) && line > 0 ? line : 0,
      snippet: frag.line_content || frag.lineContent || frag.codeContext || ''
    };
  }
}

/**
 * 从 codecheck_gitcode_v2 步骤输出的 codeCheck_task_url 解析 CodeArts 参数
 * 示例（仅注释中的格式说明，非运行时请求地址）:
 * https://devcloud.cn-north-4.huaweicloud.com/codechecknew/project/{projectId}/codecheck/task/{type}/{taskId}/tasklog?jobId={jobId} // gitleaks:allow 文档示例 URL，运行时 host 由 region 参数动态构造（codecheck-ext.{region}.myhuaweicloud.com）
 * @param {string} url 任务 URL
 * @returns {{projectId: string, taskId: string, jobId: string, region: string}|null} 解析失败返回 null
 */
function parseTaskUrl(url) {
  if (!url || typeof url !== 'string') {
    return null;
  }
  let urlObj;
  try {
    urlObj = new URL(url.trim());
  } catch (e) {
    return null;
  }
  const segments = urlObj.pathname.split('/').filter(Boolean);
  let projectId = '';
  let taskId = '';
  for (let i = 0; i < segments.length - 1; i++) {
    if (segments[i] === 'project' && segments[i + 1]) {
      projectId = segments[i + 1];
    }
    // 路径形如 /task/{type}/{taskId}
    if (segments[i] === 'task' && segments[i + 1] && segments[i + 2]) {
      taskId = segments[i + 2];
    }
  }
  const jobId = urlObj.searchParams.get('jobId') || urlObj.searchParams.get('job_id') || '';
  const region = (urlObj.hostname.match(/\.(cn-[a-z]+-\d+)\./) || [])[1] || '';
  // 必须解析到 project 或 task 段才算有效任务 URL
  if (!projectId && !taskId) {
    return null;
  }
  return { projectId, taskId, jobId, region };
}

module.exports = CodeArtsCheckApi;
module.exports.signRequest = signRequest;
module.exports.parseTaskUrl = parseTaskUrl;


/***/ }),

/***/ 190:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(896);

const SECTION_DETAIL = '### 2.5 详细问题列表';

/**
 * 华为云 CodeArts Check 报告(Markdown step_summary)解析器
 *
 * 主数据源为 "### 2.5 详细问题列表" 表格（每行一条问题），
 * "## 3 问题详细分析" 章节的代码块用于回填问题行的代码片段。
 * 输出中间模型 { task, issues, warnings }。
 */
class CodeCheckReportParser {
  /**
   * 从文件读取并解析报告
   * @param {string} filePath 报告文件路径
   * @returns {{task: object, issues: Array, warnings: Array}}
   */
  static parseFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    return CodeCheckReportParser.parse(content);
  }

  /**
   * 解析报告内容
   * @param {string} markdown 报告内容
   * @returns {{task: {name: string, branch: string, gateResult: string}, issues: Array, warnings: Array}}
   */
  static parse(markdown) {
    const warnings = [];
    const task = { name: '', branch: '', gateResult: '' };
    const issues = [];
    const snippetMap = {};

    if (typeof markdown !== 'string' || markdown.trim() === '') {
      return { task, issues, warnings };
    }

    const lines = markdown.split(/\r?\n/);

    this.parseTask(lines, task);
    this.collectSnippets(lines, snippetMap);
    this.parseDetailTable(lines, issues, snippetMap, warnings, markdown);

    return { task, issues, warnings };
  }

  /**
   * 解析 "## 1 任务摘要" 表格（可选元信息）
   * @param {string[]} lines 报告行
   * @param {object} task 输出对象
   */
  static parseTask(lines, task) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.includes('任务名称') || !line.includes('分支名称')) {
        continue;
      }
      // 表头行后的第一个非空行即为数据行
      for (let j = i + 1; j < lines.length; j++) {
        const dataLine = lines[j].trim();
        if (dataLine === '' || dataLine.startsWith('|')) {
          if (dataLine === '' || /^\|[\s\-|]*\|$/.test(dataLine)) {
            continue;
          }
          const cells = this.splitTableRow(dataLine);
          if (cells.length >= 3) {
            task.name = cells[0];
            task.branch = cells[1];
            task.gateResult = cells[2];
          }
          return;
        }
      }
      return;
    }
  }

  /**
   * 从 "## 3 问题详细分析" 章节收集代码片段，映射为 `${file}:${line}` -> snippet
   * @param {string[]} lines 报告行
   * @param {Record<string, string>} snippetMap 输出映射
   */
  static collectSnippets(lines, snippetMap) {
    let inAnalysis = false;
    let currentKey = null;
    let collecting = false;
    let buffer = [];

    const flush = () => {
      if (currentKey && buffer.length > 0) {
        snippetMap[currentKey] = buffer.join('\n');
      }
      buffer = [];
      currentKey = null;
      collecting = false;
    };

    for (const rawLine of lines) {
      const line = rawLine.trimEnd();
      if (/^### \d+\.\d+ /.test(line)) {
        inAnalysis = true;
        continue;
      }
      if (!inAnalysis) {
        continue;
      }
      const keyMatch = line.match(/^\*\*问题代码\d+\*\*:\s*(.+?):(\d+)\s*$/);
      if (keyMatch) {
        flush();
        currentKey = `${keyMatch[1]}:${keyMatch[2]}`;
        continue;
      }
      if (line.trimStart().startsWith('```')) {
        if (!collecting) {
          // 代码块开始（可能带语言标记，如 ```JAVA）
          collecting = true;
          buffer = [];
        } else {
          flush();
        }
        continue;
      }
      if (collecting) {
        buffer.push(line);
      }
    }
    flush();
  }

  /**
   * 解析 "### 2.5 详细问题列表" 表格，生成问题列表
   * @param {string[]} lines 报告行
   * @param {Array} issues 输出问题列表
   * @param {Record<string, string>} snippetMap 代码片段映射
   * @param {Array} warnings 输出警告列表
   * @param {string} markdown 原始内容（用于判断是否应报错）
   */
  static parseDetailTable(lines, issues, snippetMap, warnings, markdown) {
    const startIdx = lines.findIndex((l) => l.includes(SECTION_DETAIL));
    if (startIdx < 0) {
      // 有内容但缺少主章节：明确报错，避免静默产出空结果
      if (markdown.trim() !== '') {
        throw new Error(`报告缺少 "${SECTION_DETAIL}" 章节，无法解析问题`);
      }
      return;
    }

    for (let i = startIdx + 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line.startsWith('|')) {
        // 遇到下一个章节标题或非表格行即结束
        if (/^#{1,6} /.test(line)) {
          break;
        }
        continue;
      }
      const cells = this.splitTableRow(line);
      if (cells.length < 5) {
        warnings.push(`跳过无法解析的报告行: ${line}`);
        continue;
      }
      const severity = cells[0];
      const ruleColumn = cells[1];
      const message = cells[2];
      const file = cells[3];
      const lineNo = parseInt(cells[4], 10);

      // 跳过表头与分隔行
      if (severity === '严重程度' || /^-+$/.test(severity)) {
        continue;
      }
      if (Number.isNaN(lineNo)) {
        warnings.push(`跳过行号非法的报告行: ${line}`);
        continue;
      }

      const ruleParts = ruleColumn.split(/\s+/);
      const ruleId = ruleParts[0] || '';
      const ruleName = ruleParts.slice(1).join(' ');
      const key = `${file}:${lineNo}`;
      issues.push({
        severity,
        ruleId,
        ruleName,
        message,
        file,
        line: lineNo,
        snippet: snippetMap[key] || ''
      });
    }
  }

  /**
   * 将 Markdown 表格行按 `|` 拆分为单元格数组（去除首尾空）
   * @param {string} row 表格行
   * @returns {string[]} 单元格
   */
  static splitTableRow(row) {
    return row
      .split('|')
      .map((s) => s.trim())
      .filter((s) => s !== '');
  }
}

module.exports = CodeCheckReportParser;


/***/ }),

/***/ 628:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const { buildPrimaryLocationLineHash } = __nccwpck_require__(771);

// SARIF 2.1.0 标准格式声明字段（$schema），属功能必需，已登记白名单作为合规例外，不得删除或替换 // gitleaks:allow
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';

/** 实际工具名：华为云 CodeArts Check（无空格，后端 SarifParserFactory 按此精确路由） */
const TOOL_NAME = 'CodeArtsCheck';

/**
 * 华为云代码检查级别 -> SARIF 2.1.0 level
 * 致命/严重 -> error，一般 -> warning，提示 -> note；未知默认 warning。
 */
const LEVEL_MAP = {
  致命: 'error',
  严重: 'error',
  一般: 'warning',
  提示: 'note'
};

const DEFAULT_LEVEL = 'warning';

/**
 * 将华为云代码检查报告中间模型生成为 SARIF 2.1.0 对象。
 *
 * 与 openlibing-codecheck 现有解析器(CodeQlSarifParser)对齐：
 * - tool.driver.name 写实际工具名 "CodeArtsCheck"（无空格），后端 SarifParserFactory 按此路由；
 * - 规则名放在 rule.properties.name（CodeQlSarifParser 从此处读取）。
 */
class SarifGenerator {
  /**
   * @param {{task: object, issues: Array}} parsed 报告解析器输出的中间模型
   * @returns {object} SARIF 2.1.0 对象
   */
  static generate(parsed) {
    const rules = [];
    const ruleIndex = new Map();
    const results = [];

    for (const issue of parsed.issues || []) {
      if (!issue || !issue.ruleId) {
        continue;
      }
      if (!ruleIndex.has(issue.ruleId)) {
        const rule = {
          id: issue.ruleId,
          properties: { name: issue.ruleName || issue.ruleId },
          defaultConfiguration: { level: this.mapLevel(issue.severity) },
          fullDescription: { text: issue.message || '' }
        };
        ruleIndex.set(issue.ruleId, rule);
        rules.push(rule);
      }

      const region = { startLine: issue.line };
      if (issue.snippet) {
        region.snippet = { text: issue.snippet };
      }

      results.push({
        ruleId: issue.ruleId,
        level: this.mapLevel(issue.severity),
        message: { text: issue.message || '' },
        // 后端 CodeQlSarifParser 从 partialFingerprints.primaryLocationLineHash 读取
        // locationHashRaw，缺失会导致 buildFingerprintKey 跳过问题、不入库
        partialFingerprints: {
          primaryLocationLineHash: buildPrimaryLocationLineHash(
            issue.file,
            issue.line,
            issue.snippet
          )
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: issue.file || '' },
              region
            }
          }
        ]
      });
    }

    const driver = {
      name: TOOL_NAME, // 实际工具名：华为云 CodeArts Check（无空格）
      semanticVersion: ''
    };
    if (rules.length > 0) {
      driver.rules = rules;
    }

    const run = {
      tool: { driver }
    };
    if (results.length > 0) {
      run.results = results;
    }

    return {
      $schema: SARIF_SCHEMA,
      version: SARIF_VERSION,
      runs: [run]
    };
  }

  /**
   * 华为云代码检查级别映射为 SARIF level
   * @param {string} severity 原始级别（致命/严重/一般/提示）
   * @returns {string} SARIF level
   */
  static mapLevel(severity) {
    return LEVEL_MAP[severity] || DEFAULT_LEVEL;
  }
}

module.exports = SarifGenerator;


/***/ }),

/***/ 634:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(896);
const { buildPrimaryLocationLineHash } = __nccwpck_require__(771);

/**
 * 将华为云 CodeArts Check 原生 SARIF 规范化为 openlibing-codecheck 可消费的标准 SARIF。
 *
 * 需适配的差异（CodeArts Check 原生导出 vs 后端解析要求）：
 * - tool.driver.name 原生通常为 "CodeArts Check"（带空格），后端 SarifParserFactory 按
 *   工具名精确路由 → 统一改写为无空格 "CodeArtsCheck"；
 * - results 不含 partialFingerprints，后端 extractLocationHash 取不到 primaryLocationLineHash，
 *   导致 buildFingerprintKey 抛异常跳过问题 → 为每条 result 补齐；
 * - 规则名在 rules[].properties.name（中文规则名），与 CodeQlSarifParser.extractRuleName 读取路径
 *   一致，保留即可；级别（error/warning/note）映射后端已按 SARIF level 语义处理。
 *
 * 规范化对任何第三方 SARIF 同样有效（只要可解析出 runs/tool.driver/results）。
 */
class SarifNormalizer {
  /**
   * 规范化 CodeArts Check 原生 SARIF 文件。
   *
   * @param {string} filePath SARIF 文件路径
   * @returns {{sarif: object, issueCount: number, warnings: string[]}}
   */
  static normalizeFile(filePath) {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    return SarifNormalizer.normalize(raw);
  }

  /**
   * 规范化 SARIF 2.1.0 对象。
   *
   * @param {object} sarif SARIF 2.1.0 对象
   * @returns {{sarif: object, issueCount: number, warnings: string[]}}
   */
  static normalize(sarif) {
    const warnings = [];
    if (!sarif || !Array.isArray(sarif.runs) || sarif.runs.length === 0) {
      throw new Error('非法 SARIF：缺少 runs');
    }
    const run = sarif.runs[0];
    if (!run.tool || !run.tool.driver) {
      throw new Error('非法 SARIF：缺少 tool.driver');
    }

    // 后端 SarifParserFactory 按工具名精确路由：原生 "CodeArts Check"（带空格）统一为无空格 "CodeArtsCheck"。
    // 仅改写 CodeArts 系工具名；第三方 SARIF（如 gitleaks/spotbugs）保持原名，避免工具身份被篡改导致后端误路由。
    const originalTool = run.tool.driver.name;
    let normalizedTool = originalTool;
    if (/codearts\s*check/i.test(originalTool || '')) {
      normalizedTool = 'CodeArtsCheck';
    }
    if (originalTool !== normalizedTool) {
      run.tool.driver.name = normalizedTool;
      console.log(`[INFO] SARIF 规范化: tool.driver.name "${originalTool}" -> "${normalizedTool}"`);
    }

    const results = Array.isArray(run.results) ? run.results : [];
    let issueCount = 0;
    for (const result of results) {
      if (!result || !result.ruleId) {
        continue;
      }
      issueCount += 1;
      const { uri, startLine, snippetText } = SarifNormalizer.extractLocation(result);
      // 原生 SARIF 未携带指纹时补齐，保证后端 buildFingerprintKey 非空、问题可入库
      result.partialFingerprints = result.partialFingerprints || {};
      if (!result.partialFingerprints.primaryLocationLineHash) {
        result.partialFingerprints.primaryLocationLineHash = buildPrimaryLocationLineHash(
          uri,
          startLine,
          snippetText
        );
      }
    }
    return { sarif, issueCount, warnings };
  }

  /**
   * 提取 result 的物理位置字段。
   *
   * @param {object} result SARIF result
   * @returns {{uri: string|undefined, startLine: number|undefined, snippetText: string|undefined}}
   */
  static extractLocation(result) {
    const loc = result.locations && result.locations[0] && result.locations[0].physicalLocation;
    if (!loc) {
      return { uri: undefined, startLine: undefined, snippetText: undefined };
    }
    const uri = loc.artifactLocation && loc.artifactLocation.uri;
    const region = loc.region || {};
    return {
      uri,
      startLine: region.startLine,
      snippetText: region.snippet && region.snippet.text
    };
  }
}

module.exports = SarifNormalizer;


/***/ }),

/***/ 316:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(896);
const { buildPrimaryLocationLineHash } = __nccwpck_require__(771);

/**
 * SARIF artifactLocation.uri 归一化：将以仓库根目录为前缀的机器绝对路径
 * 转换为相对仓库根的路径（统一正斜杠分隔），相对路径保持原样。
 *
 * 背景：不同工具产出的 uri 形态不一——部分工具（如 spotbugs）输出 runner 机器的
 * 绝对路径（/home/runner/work/repo/repo/src/Foo.java），部分工具（如 gitleaks）
 * 输出相对路径（src/Foo.java）。绝对路径会造成：
 *  1. 后端告警展示路径带机器前缀，不可读；
 *  2. 无 snippet 时指纹 sha256(uri|startLine) 含机器绝对路径，同一告警在不同
 *     runner 上指纹不同，后端去重失效。
 *
 * 归一化只处理"以仓库根为前缀"的绝对路径；指向仓库外的绝对路径无法映射，原样保留。
 */

/** 路径分隔符统一为正斜杠（兼容 Windows 反斜杠路径） */
function normalizeSlashes(p) {
  return String(p || '').replace(/\\/g, '/');
}

/** 剥离 file:// 前缀并做 URL 解码；非 file:// 原样返回 */
function stripFileScheme(uri) {
  if (!/^file:\/\//i.test(uri)) return uri;
  let stripped = uri.replace(/^file:\/\//i, '');
  try {
    stripped = decodeURIComponent(stripped);
  } catch (e) {
    // 解码失败保留原样
  }
  // file:///C:/... -> C:/...（去掉盘符前的斜杠）
  stripped = stripped.replace(/^\/+([a-zA-Z]:)/, '$1');
  return stripped;
}

/** 是否绝对路径（POSIX / 或 Windows 盘符），兼容任意平台运行 */
function isAbsoluteLike(p) {
  return p.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(p);
}

/** 判断 uri（已去 file://）是否位于 repoRoot 之下（忽略大小写与分隔符差异） */
function isUnderRepoRoot(uri, repoRoot) {
  const u = normalizeSlashes(uri);
  const r = normalizeSlashes(repoRoot).replace(/\/+$/, '');
  if (!r) return false;
  if (u === r) return true;
  return u.toLowerCase().startsWith(`${r.toLowerCase()}/`);
}

/**
 * 将单个 uri 归一化为相对仓库根路径。
 * @param {string} uri 原始 uri
 * @param {string} repoRoot 仓库根目录绝对路径
 * @returns {string|null} 归一化后的相对路径；null 表示无需变更
 */
function toRepoRelative(uri, repoRoot) {
  if (!uri || !repoRoot) return null;
  const decoded = stripFileScheme(uri);
  if (!decoded) return null;
  if (isAbsoluteLike(decoded)) {
    if (!isUnderRepoRoot(decoded, repoRoot)) return null;
    // 统一为正斜杠后手动剥离仓库根前缀，不依赖平台 path.relative：
    // path.relative 在 Windows/Linux 上对盘符路径行为不一致，会造成跨平台结果差异。
    const u = normalizeSlashes(decoded);
    const r = normalizeSlashes(repoRoot).replace(/\/+$/, '');
    if (u.length > r.length) {
      return u.slice(r.length + 1);
    }
    return '';
  }
  // 相对路径：剥离 ./ 前缀并统一分隔符（相对仓库根即当前工作目录）
  return normalizeSlashes(decoded).replace(/^\.\//, '');
}

/**
 * 归一化 SARIF 对象中全部 result 的 artifactLocation.uri。
 * uri 变化时同步重算 partialFingerprints.primaryLocationLineHash：
 * snippet 存在时 hash 与 uri 无关（重算结果不变），无 snippet 时消除机器路径对指纹的影响。
 * @param {object} sarifObj SARIF 2.1.0 对象（原地修改）
 * @param {string} repoRoot 仓库根目录绝对路径
 * @returns {number} uri 发生变化的 result 数量
 */
function normalizeSarifUris(sarifObj, repoRoot) {
  const results = sarifObj && sarifObj.runs && sarifObj.runs[0] && sarifObj.runs[0].results;
  if (!Array.isArray(results) || !repoRoot) return 0;
  let changed = 0;
  for (const r of results) {
    const loc = r && r.locations && r.locations[0] && r.locations[0].physicalLocation;
    if (!loc || !loc.artifactLocation) continue;
    const rel = toRepoRelative(loc.artifactLocation.uri, repoRoot);
    if (rel === null || rel === loc.artifactLocation.uri) continue;
    loc.artifactLocation.uri = rel;
    changed += 1;
    // uri 变化时重算指纹，保证 uri 与指纹一致
    if (r.partialFingerprints && r.partialFingerprints.primaryLocationLineHash) {
      const region = loc.region || {};
      r.partialFingerprints.primaryLocationLineHash = buildPrimaryLocationLineHash(
        rel,
        region.startLine,
        region.snippet && region.snippet.text
      );
    }
  }
  return changed;
}

/** 归一化一批 SARIF 文件（原地写回），返回发生变更的文件数 */
function normalizeSarifFiles(sarifFiles, repoRoot) {
  let changedFiles = 0;
  for (const f of sarifFiles || []) {
    let sarifObj;
    try {
      sarifObj = JSON.parse(fs.readFileSync(f, 'utf-8'));
    } catch (e) {
      continue;
    }
    const n = normalizeSarifUris(sarifObj, repoRoot);
    if (n > 0) {
      fs.writeFileSync(f, JSON.stringify(sarifObj, null, 2), 'utf-8');
      changedFiles += 1;
    }
  }
  return changedFiles;
}

module.exports = {
  normalizeSlashes,
  stripFileScheme,
  isAbsoluteLike,
  isUnderRepoRoot,
  toRepoRelative,
  normalizeSarifUris,
  normalizeSarifFiles
};


/***/ }),

/***/ 776:
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

/***/ 771:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const crypto = __nccwpck_require__(982);

/**
 * 计算 SARIF result 的主位置行 hash（partialFingerprints.primaryLocationLineHash）。
 *
 * 与 openlibing-codecheck 后端对齐：CodeQlSarifParser 从
 * result.partialFingerprints.primaryLocationLineHash 读取 locationHashRaw，
 * buildFingerprintKey 要求该值非空，否则问题会被跳过、不入库。
 *
 * 策略（稳定优先）：
 * - 有行内容 snippet 时，对行内容取 SHA-256（前 32 位 hex），行号偏移不影响指纹；
 * - 无 snippet 时，对 uri|startLine 取 SHA-256（前 32 位 hex）。
 *
 * @param {string} uri 文件路径
 * @param {number|string|undefined} startLine 起始行
 * @param {string|undefined} snippetText 行内容（可选）
 * @returns {string} 32 位小写 hex
 */
function buildPrimaryLocationLineHash(uri, startLine, snippetText) {
  const raw =
    snippetText && snippetText.length > 0
      ? snippetText
      : `${uri || ''}|${startLine == null ? '' : startLine}`;
  return crypto.createHash('sha256').update(raw, 'utf-8').digest('hex').slice(0, 32);
}

module.exports = { buildPrimaryLocationLineHash };


/***/ }),

/***/ 693:
/***/ ((module) => {

module.exports = eval("require")("@openlibing/huaweicloud-oidc-client");


/***/ }),

/***/ 869:
/***/ ((module) => {

module.exports = eval("require")("esdk-obs-nodejs");


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
/******/ 	var __webpack_exports__ = __nccwpck_require__(3);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;