/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 6136:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const { installFetchPolyfill } = __nccwpck_require__(7849);
// GitCode 插件 runtime 为 node16，无全局 fetch；注入最小 polyfill，否则
// OIDC SDK 会回退 require('undici') 导致 "Cannot find module 'undici'"。
installFetchPolyfill();

const { execSync, execFileSync } = __nccwpck_require__(5317);
const fs = __nccwpck_require__(9896);
const path = __nccwpck_require__(6928);
const os = __nccwpck_require__(857);
const ObsClient = __nccwpck_require__(1728);

const CodeCheckReportParser = __nccwpck_require__(9147);
const SarifGenerator = __nccwpck_require__(9069);
const SarifNormalizer = __nccwpck_require__(5301);
const SarifUriNormalizer = __nccwpck_require__(3389);
const CodeArtsCheckApi = __nccwpck_require__(7739);

// OIDC 签名 SDK：APIG V11-HMAC-SHA256 签名 + HTTPS 请求 + 自包含 OIDC 换证。
// getCredentials() 通过 Actions 兼容流水线环境变量（ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN）
// 自申请 OIDC ID Token，再调用华为云 STS AssumeAgencyWithOIDC 换取临时 AK/SK/SecurityToken，
// 无需在 workflow 中额外运行 huaweicloud-oidc-auth 插件（仅需声明 permissions: id-token: write）。
let V11Signer = null;
let sendRequest = null;
let getCredentials = null;
let configure = null;
try {
  ({ V11Signer, sendRequest, getCredentials, configure } = __nccwpck_require__(8620));
} catch (e) {
  console.log('[ERROR] @openlibing/huaweicloud-oidc-client 加载失败，请重新构建 dist 后重试');
}

// ---------- 常量 ----------

const APIG_SIGN_REGION = 'cn-southwest-2'; // APIG V11 签名区域
const OIDC_API_PREFIX = '/action-api'; // OIDC 回调路径前缀（网关 IAM 认证）
const CALLBACK_PATH = '/codescan/v1/result/receive';
// 业务功能性公网端点集中配置（#10 方案 B），默认值见 src/config/endpoints.js；
// 可通过同名环境变量覆盖（环境切换不改源码）。
const ENDPOINTS = __nccwpck_require__(3242);
const OIDC_PROD_BASE = process.env.OIDC_PROD_BASE || ENDPOINTS.OIDC_PROD_BASE;
const OIDC_BETA_BASE = process.env.OIDC_BETA_BASE || ENDPOINTS.OIDC_BETA_BASE;

// OBS：通用 SARIF 结果统一存放（后端 SarifParseServiceImpl 匿名 HTTP GET 下载）
// 上传端点 server 由 OIDC SDK configure 动态返回 region，不在此写死
const OBS_KEY_ROOT = 'code-arts-check-results'; // buildToolPrefix 兜底前缀（工具名缺失时）
const OBS_BUCKET = process.env.OBS_BUCKET || ENDPOINTS.OBS_BUCKET;
const OBS_READ_ENDPOINT = process.env.OBS_READ_ENDPOINT || ENDPOINTS.OBS_READ_ENDPOINT;
// 结果解析查看页（回调成功后的提示链接），集中配置 + 环境变量覆盖（与上面同模式）
const RESULT_VIEW_BASE = process.env.RESULT_VIEW_BASE || ENDPOINTS.RESULT_VIEW_BASE;
const RESULT_VIEW_BASE_BETA = process.env.RESULT_VIEW_BASE_BETA || ENDPOINTS.RESULT_VIEW_BASE_BETA;

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

/**
 * find 命令数组传参执行（#20 整改：替代 shell 字符串拼接 + 单点转义，零 shell 解析）。
 * 返回首个匹配行；无匹配/失败返回 ''。find 对个别子目录无权限时会以非零码退出
 * 但仍产出部分结果（与原 `2>/dev/null | head -1` 管道行为等价），此时取 e.stdout。
 */
function findFirst(args) {
  let out = '';
  try {
    out = execFileSync('find', args, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) {
    out = (e && e.stdout) || '';
  }
  return (String(out).split('\n').map(s => s.trim()).find(Boolean) || '');
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
  const gitDir = findFirst([workspace, '-maxdepth', '3', '-name', '.git', '-type', 'd']);
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

// ---------- 凭证类规则 snippet 掩码（Ref issues #11/#12） ----------

/** 凭证类规则关键字：result 的规则 ID/规则描述/消息命中即视为凭证类检出，
 * 对应 snippet 中的字符串字面量按疑似明文凭证掩码。 */
const CREDENTIAL_RULE_RE = /(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|credential|auth|硬编码口令|密码|密钥|口令|凭证)/i;

/** 掩码单个疑似凭证字面量：保留前 2 后 2 字符，中间以 *** 替代；长度 <= 6 整体掩码 */
function maskLiteralBody(body) {
  if (!body) return body;
  if (body.length <= 6) return '***';
  return body.slice(0, 2) + '***' + body.slice(-2);
}

/**
 * 凭证类规则 snippet 掩码（Ref issues #11/#12）：命中"硬编码口令/密钥"类规则时，
 * 问题行源码原文（如 String password = "123456"）本身就是明文凭证，随 SARIF
 * 上传 OBS 后形成多副本长期留存。此处对 snippet 按行处理，行内引号包裹的
 * 非空字符串字面量替换为保留前 2 后 2 + *** 的掩码形态。
 * 注意：掩码后 snippet 与源码不再逐字一致，前端内容匹配高亮对凭证类检出
 * 会退化为按行号定位——安全优先，属预期取舍。
 */
function maskCredentialSnippet(text) {
  return String(text || '').split('\n').map(line => line.replace(
    /(["'])((?:(?!\1)[^\n])+?)\1/g,
    (whole, q, body) => (body.trim() ? q + maskLiteralBody(body.trim()) + q : whole)
  )).join('\n');
}

/** 拼装 result 的规则判定素材：ruleId + 规则描述 + 消息文本，供凭证规则匹配 */
function buildRuleInfoText(r, sarifObj) {
  const rules = sarifObj && sarifObj.runs && sarifObj.runs[0] && sarifObj.runs[0].tool &&
    sarifObj.runs[0].tool.driver && sarifObj.runs[0].tool.driver.rules;
  let ruleDesc = '';
  if (Array.isArray(rules) && r.ruleIndex != null && rules[r.ruleIndex]) {
    const rule = rules[r.ruleIndex];
    ruleDesc = [
      rule.name || '',
      (rule.shortDescription && rule.shortDescription.text) || '',
      (rule.fullDescription && rule.fullDescription.text) || ''
    ].join(' ');
  }
  return `${r.ruleId || ''} ${ruleDesc} ${(r.message && r.message.text) || ''}`;
}

// ---------- region.snippet 补齐 ----------

/**
 * 边界校验（#18/#16 整改，CWE-22 防护）：resolveSourceFile 的解析结果必须落在
 * sourceRoots（含 workspace 兜底）之内，超出边界的 uri 一律拒绝读取。
 * SARIF 由扫描工具对 PR 代码运行产生，uri 内容可被恶意 PR 代码影响；
 * 若不校验，file:// 与绝对路径可读 runner 上任意文件并将内容写入 snippet 随 SARIF 上传。
 */
function isWithinRoots(resolved, roots) {
  return roots.some((root) => resolved === root || resolved.startsWith(root + path.sep));
}

/**
 * realpath 终裁（#18/#16 整改回归缺口补齐）：词法前缀校验只比对路径字符串，
 * 挡不住「路径在界内、目标在界外」的符号链接（fs.statSync/readFileSync 会跟随链接）。
 * 此处解析真实路径后重做一次边界校验，越界的符号链接返回 null。
 */
function confirmWithinRootsRealpath(candidate, roots) {
  if (!candidate) return null;
  let real;
  try {
    real = fs.realpathSync(candidate);
  } catch (e) {
    return null;
  }
  return isWithinRoots(real, roots) ? real : null;
}

/**
 * 将 SARIF uri 解析为源码根目录下的真实文件路径；找不到或越出 sourceRoots 边界返回 null。
 * 依次尝试：绝对路径（file:// 或 / 开头）→ sourceRoots 直接拼接 → 按文件名递归兜底查找。
 * 所有路径统一 path.resolve 归一化后做前缀校验（阻断 ../ 越界与工作区外绝对路径），
 * 最终经 realpath 终裁（阻断指向边界外的符号链接）。
 */
function resolveSourceFile(uri, sourceRoots) {
  const roots = (sourceRoots || []).map((r) => path.resolve(r));
  let p = (uri || '').trim();
  if (!p) return null;
  if (p.startsWith('file://')) {
    try {
      let filePath = decodeURIComponent(p.replace(/^file:\/\//i, ''));
      // Windows 盘符形式 file:///e:/xxx → e:/xxx（去掉开头的 /，否则 resolve 会归到错误盘根）
      filePath = filePath.replace(/^\/([a-zA-Z]:)/, '$1');
      const resolved = path.resolve(filePath);
      if (!isWithinRoots(resolved, roots)) return null;
      if (!(fs.existsSync(resolved) && fs.statSync(resolved).isFile())) return null;
      return confirmWithinRootsRealpath(resolved, roots);
    } catch (e) {
      return null;
    }
  }
  if (/^[a-zA-Z]:[\\/]/.test(p) || p.startsWith('/')) {
    const resolved = path.resolve(p);
    if (!isWithinRoots(resolved, roots)) return null;
    if (!(fs.existsSync(resolved) && fs.statSync(resolved).isFile())) return null;
    return confirmWithinRootsRealpath(resolved, roots);
  }
  p = p.replace(/^\.\//, '').replace(/^\/+/, '');
  for (const root of roots) {
    const cand = path.resolve(root, p); // resolve 归一化，../ 被折叠为真实目标
    if (cand !== root && !cand.startsWith(root + path.sep)) continue; // 阻断 ../ 越出该根
    if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
      const confirmed = confirmWithinRootsRealpath(cand, roots);
      if (confirmed) return confirmed;
    }
  }
  const base = path.basename(p);
  if (base) {
    for (const root of roots) {
      const found = findFirst([root, '-name', base, '-type', 'f']);
      if (found) {
        const confirmed = confirmWithinRootsRealpath(found, roots);
        if (confirmed) return confirmed;
      }
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

    // 凭证类规则判定（Ref issues #11/#12）：命中则 snippet/上下文/消息中的字符串字面量掩码
    const isCredentialRule = CREDENTIAL_RULE_RE.test(buildRuleInfoText(r, sarifObj));
    const maskText = (text) => (isCredentialRule ? maskCredentialSnippet(text) : text);

    // 3) result.message.text 掩码（#11/#12 整改回归缺口补齐）：bandit 等工具会把
    //    明文口令写进消息文本（如 B105 `comparison to "123456"`），随 SARIF 上传留存。
    //    与 snippet 掩码同性质：掩码后与工具原始输出不再逐字一致，前端按行号定位。
    if (r.message && typeof r.message.text === 'string' && r.message.text) {
      const maskedMsg = maskText(r.message.text);
      if (maskedMsg !== r.message.text) {
        r.message.text = maskedMsg;
        changed = true;
      }
    }

    // 1) region.snippet 对齐为问题行本身（前端定位高亮依赖，必须与文件内容一致；
    //    凭证类规则例外——原文即明文凭证，掩码后写入）
    const problemText = maskText(problemLines.join('\n'));
    if (!region.snippet || region.snippet.text !== problemText) {
      region.snippet = { text: problemText };
      changed = true;
    }

    // 2) contextRegion：固定为问题范围上下各 2 行的窗口（越界自动裁剪），前端展示统一 5 行；
    //    工具自带的不同窗口（如 3 行）也一律覆盖对齐；凭证类规则同步掩码
    const ctxStart = Math.max(1, startLine - 2);
    const ctxEnd = Math.min(lines.length, endLine + 2);
    const ctxLines = lines.slice(ctxStart - 1, ctxEnd);
    if (ctxLines.length) {
      const ctxText = maskText(ctxLines.join('\n'));
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

/** 遍历 SARIF 文件，缺少 region.snippet / contextRegion 时补齐并写回原文件。
 * Ref issues #11：仅在补齐/掩码导致内容实际变化时回写，避免对用户工作区
 * SARIF 文件做无条件重写（JSON 重排也会改变文件内容）。 */
function enrichSarifFiles(sarifFiles, sourceRoots) {
  for (const f of sarifFiles) {
    let sarifObj;
    let originalContent;
    try {
      originalContent = fs.readFileSync(f, 'utf-8');
      sarifObj = JSON.parse(originalContent);
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
      const gitDir = findFirst([workspace, '-maxdepth', '3', '-name', '.git', '-type', 'd']);
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
  const gitDir = findFirst([workspace, '-maxdepth', '3', '-name', '.git', '-type', 'd']);
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
  // TLS 证书校验（#19 整改）：SDK 默认 sslVerify=false（MITM 可窃取临时凭证与 SARIF 内容），
  // 此处默认开启校验；企业自签 TLS 代理场景可通过 obs_ssl_ca_file 输入指定 CA 证书
  // 文件路径（SDK 支持传路径，内部读取为 ca 选项）。
  const obsSslCaFile = getInput('obs_ssl_ca_file');
  const client = new ObsClient({
    access_key_id: cred.accessKeyId,
    secret_access_key: cred.secretAccessKey,
    security_token: cred.securityToken,
    server,
    sslVerify: obsSslCaFile || true
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
    const resultViewUrl = isBetaEnv ? RESULT_VIEW_BASE_BETA : RESULT_VIEW_BASE;
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

/***/ 578:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * APIG 调用封装模块：callApig 一行调用 APIG 接口。
 * 自动完成：临时凭证获取（带缓存 / force 强制刷新）-> V11-HMAC-SHA256 签名 ->
 * X-Security-Token 注入 -> 发送请求。需精细控制时可自行组合 V11Signer + sendRequest。
 */

const { cfg } = __nccwpck_require__(7269);
const { getCredentials } = __nccwpck_require__(6477);
const { V11Signer } = __nccwpck_require__(9692);
const { sendRequest } = __nccwpck_require__(5531);

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

/***/ 7269:
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

/***/ 6477:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * 临时凭证模块：getCredentials() 获取华为云临时凭证。
 * 调用链 CI 流水线（GitHub Actions / GitCode Actions 等 Actions 兼容平台）OIDC ID Token
 * -> 华为云 STS AssumeAgencyWithOIDC，带缓存自动刷新、force 强制刷新、并发去重。
 */

const { cfg } = __nccwpck_require__(7269);
const { info, debug, error, mask, maskBody } = __nccwpck_require__(9463);
const { sendRequest } = __nccwpck_require__(5531);
const { getOidcToken } = __nccwpck_require__(8790);

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

/***/ 5531:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * HTTP 请求工具模块：sendRequest 发送请求并解析 JSON 响应。
 * 基于 Node 内置 fetch（Node 18+），零第三方依赖。
 * 调试模式打印完整请求/响应日志（敏感字段自动脱敏），非调试模式不打印请求详情。
 */

const { debug, maskHeaders, maskBody, clip } = __nccwpck_require__(9463);

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
    const fetchImpl = typeof fetch === 'function' ? fetch : (...args) => (__nccwpck_require__(8337).fetch)(...args);
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

/***/ 8620:
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
  getCredentials: (__nccwpck_require__(6477).getCredentials),
  configure: (__nccwpck_require__(7269).configure),
  V11Signer: (__nccwpck_require__(9692).V11Signer),
  sendRequest: (__nccwpck_require__(5531).sendRequest)
};


/***/ }),

/***/ 9463:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * 日志与脱敏模块：分级日志（info 关键步骤 / debug 调试定位 / error 失败详情）+ 敏感字段脱敏工具。
 * 各级别日志均带 [INFO] / [DEBUG] / [ERROR] 前缀与 ISO 8601 UTC 时间戳，便于肉眼区分、排序与按级别检索。
 */

const { cfg } = __nccwpck_require__(7269);

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

/***/ 8790:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * OIDC 模块：申请 CI 流水线签发的 OIDC ID Token（自包含，不依赖 @actions/core）。
 * 支持 GitHub Actions、GitCode Actions 等 Actions 兼容流水线：两者签发 OIDC ID Token 的方式
 * 一致，均通过运行时注入的 ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN
 * 环境变量申请（GitCode Actions 流水线与 GitHub Actions 运行器协议兼容）。
 */

const { cfg } = __nccwpck_require__(7269);
const { info, error } = __nccwpck_require__(9463);
const { sendRequest } = __nccwpck_require__(5531);

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

/***/ 9692:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


/**
 * APIG V11-HMAC-SHA256 签名模块（严格复刻华为云官方 APIG Python SDK 的 V11 算法）。
 * 仅适用于 APIG 网关接口，签名作用域服务名固定为 apic。
 */

const crypto = __nccwpck_require__(6982);

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

/***/ 876:
/***/ ((module) => {

"use strict";


function padWithZeros(vNumber, width) {
  var numAsString = vNumber.toString();
  while (numAsString.length < width) {
    numAsString = "0" + numAsString;
  }
  return numAsString;
}

function addZero(vNumber) {
  return padWithZeros(vNumber, 2);
}

/**
 * Formats the TimeOffset
 * Thanks to http://www.svendtofte.com/code/date_format/
 * @private
 */
function offset(timezoneOffset) {
  var os = Math.abs(timezoneOffset);
  var h = String(Math.floor(os / 60));
  var m = String(os % 60);
  h = ("0" + h).slice(-2);
  m = ("0" + m).slice(-2);
  return timezoneOffset === 0 ? "Z" : (timezoneOffset < 0 ? "+" : "-") + h + ":" + m;
}

function asString(format, date) {
  if (typeof format !== "string") {
    date = format;
    format = module.exports.ISO8601_FORMAT;
  }
  if (!date) {
    date = module.exports.now();
  }

  // Issue # 14 - Per ISO8601 standard, the time string should be local time
  // with timezone info.
  // See https://en.wikipedia.org/wiki/ISO_8601 section "Time offsets from UTC"

  var vDay = addZero(date.getDate());
  var vMonth = addZero(date.getMonth() + 1);
  var vYearLong = addZero(date.getFullYear());
  var vYearShort = addZero(vYearLong.substring(2, 4));
  var vYear = format.indexOf("yyyy") > -1 ? vYearLong : vYearShort;
  var vHour = addZero(date.getHours());
  var vMinute = addZero(date.getMinutes());
  var vSecond = addZero(date.getSeconds());
  var vMillisecond = padWithZeros(date.getMilliseconds(), 3);
  var vTimeZone = offset(date.getTimezoneOffset());
  var formatted = format
    .replace(/dd/g, vDay)
    .replace(/MM/g, vMonth)
    .replace(/y{1,4}/g, vYear)
    .replace(/hh/g, vHour)
    .replace(/mm/g, vMinute)
    .replace(/ss/g, vSecond)
    .replace(/SSS/g, vMillisecond)
    .replace(/O/g, vTimeZone);
  return formatted;
}

function setDatePart(date, part, value, local) {
  date['set' + (local ? '' : 'UTC') + part](value);
}

function extractDateParts(pattern, str, missingValuesDate) {
  // Javascript Date object doesn't support custom timezone.  Sets all felds as
  // GMT based to begin with.  If the timezone offset is provided, then adjust
  // it using provided timezone, otherwise, adjust it with the system timezone.
  var local = pattern.indexOf('O') < 0;
  var monthOverflow = false;
  var matchers = [
    {
      pattern: /y{1,4}/,
      regexp: "\\d{1,4}",
      fn: function(date, value) {
        setDatePart(date, 'FullYear', value, local);
      }
    },
    {
      pattern: /MM/,
      regexp: "\\d{1,2}",
      fn: function(date, value) {
        setDatePart(date, 'Month', (value - 1), local);
        if (date.getMonth() !== (value - 1)) {
          // in the event of 31 May --> 31 Feb --> 3 Mar
          // this is correct behavior if no Date is involved
          monthOverflow = true;
        }
      }
    },
    {
      pattern: /dd/,
      regexp: "\\d{1,2}",
      fn: function(date, value) {
        // in the event of 31 May --> 31 Feb --> 3 Mar
        // reset Mar back to Feb, before setting the Date
        if (monthOverflow) {
          setDatePart(date, 'Month', (date.getMonth() - 1), local);
        }
        setDatePart(date, 'Date', value, local);
      }
    },
    {
      pattern: /hh/,
      regexp: "\\d{1,2}",
      fn: function(date, value) {
        setDatePart(date, 'Hours', value, local);
      }
    },
    {
      pattern: /mm/,
      regexp: "\\d\\d",
      fn: function(date, value) {
        setDatePart(date, 'Minutes', value, local);
      }
    },
    {
      pattern: /ss/,
      regexp: "\\d\\d",
      fn: function(date, value) {
        setDatePart(date, 'Seconds', value, local);
      }
    },
    {
      pattern: /SSS/,
      regexp: "\\d\\d\\d",
      fn: function(date, value) {
        setDatePart(date, 'Milliseconds', value, local);
      }
    },
    {
      pattern: /O/,
      regexp: "[+-]\\d{1,2}:?\\d{2}?|Z",
      fn: function(date, value) {
        if (value === "Z") {
          value = 0;
        }
        else {
          value = value.replace(":", "");
        }
        var offset = Math.abs(value);
        var timezoneOffset = (value > 0 ? -1 :  1 ) * ((offset % 100) + Math.floor(offset / 100) * 60);
        // Per ISO8601 standard: UTC = local time - offset
        //
        // For example, 2000-01-01T01:00:00-0700
        //   local time: 2000-01-01T01:00:00
        //   ==> UTC   : 2000-01-01T08:00:00 ( 01 - (-7) = 8 )
        //
        // To make it even more confusing, the date.getTimezoneOffset() is
        // opposite sign of offset string in the ISO8601 standard.  So if offset
        // is '-0700' the getTimezoneOffset() would be (+)420. The line above
        // calculates timezoneOffset to matche Javascript's behavior.
        //
        // The date/time of the input is actually the local time, so the date
        // object that was constructed is actually local time even thought the
        // UTC setters are used.  This means the date object's internal UTC
        // representation was wrong.  It needs to be fixed by substracting the
        // offset (or adding the offset minutes as they are opposite sign).
        //
        // Note: the time zone has to be processed after all other fields are
        // set.  The result would be incorrect if the offset was calculated
        // first then overriden by the other filed setters.
        date.setUTCMinutes(date.getUTCMinutes() + timezoneOffset);
      }
    }
  ];

  var parsedPattern = matchers.reduce(
    function(p, m) {
      if (m.pattern.test(p.regexp)) {
        m.index = p.regexp.match(m.pattern).index;
        p.regexp = p.regexp.replace(m.pattern, "(" + m.regexp + ")");
      } else {
        m.index = -1;
      }
      return p;
    },
    { regexp: pattern, index: [] }
  );

  var dateFns = matchers.filter(function(m) {
    return m.index > -1;
  });
  dateFns.sort(function(a, b) {
    return a.index - b.index;
  });

  var matcher = new RegExp(parsedPattern.regexp);
  var matches = matcher.exec(str);
  if (matches) {
    var date = missingValuesDate || module.exports.now();
    dateFns.forEach(function(f, i) {
      f.fn(date, matches[i + 1]);
    });

    return date;
  }

  throw new Error(
    "String '" + str + "' could not be parsed as '" + pattern + "'"
  );
}

function parse(pattern, str, missingValuesDate) {
  if (!pattern) {
    throw new Error("pattern must be supplied");
  }

  return extractDateParts(pattern, str, missingValuesDate);
}

/**
 * Used for testing - replace this function with a fixed date.
 */
function now() {
  return new Date();
}

module.exports = asString;
module.exports.asString = asString;
module.exports.parse = parse;
module.exports.now = now;
module.exports.ISO8601_FORMAT = "yyyy-MM-ddThh:mm:ss.SSS";
module.exports.ISO8601_WITH_TZ_OFFSET_FORMAT = "yyyy-MM-ddThh:mm:ss.SSSO";
module.exports.DATETIME_FORMAT = "dd MM yyyy hh:mm:ss.SSS";
module.exports.ABSOLUTETIME_FORMAT = "hh:mm:ss.SSS";


/***/ }),

/***/ 6110:
/***/ ((module, exports, __nccwpck_require__) => {

/* eslint-env browser */

/**
 * This is the web browser implementation of `debug()`.
 */

exports.formatArgs = formatArgs;
exports.save = save;
exports.load = load;
exports.useColors = useColors;
exports.storage = localstorage();
exports.destroy = (() => {
	let warned = false;

	return () => {
		if (!warned) {
			warned = true;
			console.warn('Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.');
		}
	};
})();

/**
 * Colors.
 */

exports.colors = [
	'#0000CC',
	'#0000FF',
	'#0033CC',
	'#0033FF',
	'#0066CC',
	'#0066FF',
	'#0099CC',
	'#0099FF',
	'#00CC00',
	'#00CC33',
	'#00CC66',
	'#00CC99',
	'#00CCCC',
	'#00CCFF',
	'#3300CC',
	'#3300FF',
	'#3333CC',
	'#3333FF',
	'#3366CC',
	'#3366FF',
	'#3399CC',
	'#3399FF',
	'#33CC00',
	'#33CC33',
	'#33CC66',
	'#33CC99',
	'#33CCCC',
	'#33CCFF',
	'#6600CC',
	'#6600FF',
	'#6633CC',
	'#6633FF',
	'#66CC00',
	'#66CC33',
	'#9900CC',
	'#9900FF',
	'#9933CC',
	'#9933FF',
	'#99CC00',
	'#99CC33',
	'#CC0000',
	'#CC0033',
	'#CC0066',
	'#CC0099',
	'#CC00CC',
	'#CC00FF',
	'#CC3300',
	'#CC3333',
	'#CC3366',
	'#CC3399',
	'#CC33CC',
	'#CC33FF',
	'#CC6600',
	'#CC6633',
	'#CC9900',
	'#CC9933',
	'#CCCC00',
	'#CCCC33',
	'#FF0000',
	'#FF0033',
	'#FF0066',
	'#FF0099',
	'#FF00CC',
	'#FF00FF',
	'#FF3300',
	'#FF3333',
	'#FF3366',
	'#FF3399',
	'#FF33CC',
	'#FF33FF',
	'#FF6600',
	'#FF6633',
	'#FF9900',
	'#FF9933',
	'#FFCC00',
	'#FFCC33'
];

/**
 * Currently only WebKit-based Web Inspectors, Firefox >= v31,
 * and the Firebug extension (any Firefox version) are known
 * to support "%c" CSS customizations.
 *
 * TODO: add a `localStorage` variable to explicitly enable/disable colors
 */

// eslint-disable-next-line complexity
function useColors() {
	// NB: In an Electron preload script, document will be defined but not fully
	// initialized. Since we know we're in Chrome, we'll just detect this case
	// explicitly
	if (typeof window !== 'undefined' && window.process && (window.process.type === 'renderer' || window.process.__nwjs)) {
		return true;
	}

	// Internet Explorer and Edge do not support colors.
	if (typeof navigator !== 'undefined' && navigator.userAgent && navigator.userAgent.toLowerCase().match(/(edge|trident)\/(\d+)/)) {
		return false;
	}

	let m;

	// Is webkit? http://stackoverflow.com/a/16459606/376773
	// document is undefined in react-native: https://github.com/facebook/react-native/pull/1632
	// eslint-disable-next-line no-return-assign
	return (typeof document !== 'undefined' && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance) ||
		// Is firebug? http://stackoverflow.com/a/398120/376773
		(typeof window !== 'undefined' && window.console && (window.console.firebug || (window.console.exception && window.console.table))) ||
		// Is firefox >= v31?
		// https://developer.mozilla.org/en-US/docs/Tools/Web_Console#Styling_messages
		(typeof navigator !== 'undefined' && navigator.userAgent && (m = navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/)) && parseInt(m[1], 10) >= 31) ||
		// Double check webkit in userAgent just in case we are in a worker
		(typeof navigator !== 'undefined' && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/));
}

/**
 * Colorize log arguments if enabled.
 *
 * @api public
 */

function formatArgs(args) {
	args[0] = (this.useColors ? '%c' : '') +
		this.namespace +
		(this.useColors ? ' %c' : ' ') +
		args[0] +
		(this.useColors ? '%c ' : ' ') +
		'+' + module.exports.humanize(this.diff);

	if (!this.useColors) {
		return;
	}

	const c = 'color: ' + this.color;
	args.splice(1, 0, c, 'color: inherit');

	// The final "%c" is somewhat tricky, because there could be other
	// arguments passed either before or after the %c, so we need to
	// figure out the correct index to insert the CSS into
	let index = 0;
	let lastC = 0;
	args[0].replace(/%[a-zA-Z%]/g, match => {
		if (match === '%%') {
			return;
		}
		index++;
		if (match === '%c') {
			// We only are interested in the *last* %c
			// (the user may have provided their own)
			lastC = index;
		}
	});

	args.splice(lastC, 0, c);
}

/**
 * Invokes `console.debug()` when available.
 * No-op when `console.debug` is not a "function".
 * If `console.debug` is not available, falls back
 * to `console.log`.
 *
 * @api public
 */
exports.log = console.debug || console.log || (() => {});

/**
 * Save `namespaces`.
 *
 * @param {String} namespaces
 * @api private
 */
function save(namespaces) {
	try {
		if (namespaces) {
			exports.storage.setItem('debug', namespaces);
		} else {
			exports.storage.removeItem('debug');
		}
	} catch (error) {
		// Swallow
		// XXX (@Qix-) should we be logging these?
	}
}

/**
 * Load `namespaces`.
 *
 * @return {String} returns the previously persisted debug modes
 * @api private
 */
function load() {
	let r;
	try {
		r = exports.storage.getItem('debug') || exports.storage.getItem('DEBUG') ;
	} catch (error) {
		// Swallow
		// XXX (@Qix-) should we be logging these?
	}

	// If debug isn't set in LS, and we're in Electron, try to load $DEBUG
	if (!r && typeof process !== 'undefined' && 'env' in process) {
		r = process.env.DEBUG;
	}

	return r;
}

/**
 * Localstorage attempts to return the localstorage.
 *
 * This is necessary because safari throws
 * when a user disables cookies/localstorage
 * and you attempt to access it.
 *
 * @return {LocalStorage}
 * @api private
 */

function localstorage() {
	try {
		// TVMLKit (Apple TV JS Runtime) does not have a window object, just localStorage in the global context
		// The Browser also has localStorage in the global context.
		return localStorage;
	} catch (error) {
		// Swallow
		// XXX (@Qix-) should we be logging these?
	}
}

module.exports = __nccwpck_require__(897)(exports);

const {formatters} = module.exports;

/**
 * Map %j to `JSON.stringify()`, since no Web Inspectors do that by default.
 */

formatters.j = function (v) {
	try {
		return JSON.stringify(v);
	} catch (error) {
		return '[UnexpectedJSONParseError]: ' + error.message;
	}
};


/***/ }),

/***/ 897:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


/**
 * This is the common logic for both the Node.js and web browser
 * implementations of `debug()`.
 */

function setup(env) {
	createDebug.debug = createDebug;
	createDebug.default = createDebug;
	createDebug.coerce = coerce;
	createDebug.disable = disable;
	createDebug.enable = enable;
	createDebug.enabled = enabled;
	createDebug.humanize = __nccwpck_require__(744);
	createDebug.destroy = destroy;

	Object.keys(env).forEach(key => {
		createDebug[key] = env[key];
	});

	/**
	* The currently active debug mode names, and names to skip.
	*/

	createDebug.names = [];
	createDebug.skips = [];

	/**
	* Map of special "%n" handling functions, for the debug "format" argument.
	*
	* Valid key names are a single, lower or upper-case letter, i.e. "n" and "N".
	*/
	createDebug.formatters = {};

	/**
	* Selects a color for a debug namespace
	* @param {String} namespace The namespace string for the debug instance to be colored
	* @return {Number|String} An ANSI color code for the given namespace
	* @api private
	*/
	function selectColor(namespace) {
		let hash = 0;

		for (let i = 0; i < namespace.length; i++) {
			hash = ((hash << 5) - hash) + namespace.charCodeAt(i);
			hash |= 0; // Convert to 32bit integer
		}

		return createDebug.colors[Math.abs(hash) % createDebug.colors.length];
	}
	createDebug.selectColor = selectColor;

	/**
	* Create a debugger with the given `namespace`.
	*
	* @param {String} namespace
	* @return {Function}
	* @api public
	*/
	function createDebug(namespace) {
		let prevTime;
		let enableOverride = null;
		let namespacesCache;
		let enabledCache;

		function debug(...args) {
			// Disabled?
			if (!debug.enabled) {
				return;
			}

			const self = debug;

			// Set `diff` timestamp
			const curr = Number(new Date());
			const ms = curr - (prevTime || curr);
			self.diff = ms;
			self.prev = prevTime;
			self.curr = curr;
			prevTime = curr;

			args[0] = createDebug.coerce(args[0]);

			if (typeof args[0] !== 'string') {
				// Anything else let's inspect with %O
				args.unshift('%O');
			}

			// Apply any `formatters` transformations
			let index = 0;
			args[0] = args[0].replace(/%([a-zA-Z%])/g, (match, format) => {
				// If we encounter an escaped % then don't increase the array index
				if (match === '%%') {
					return '%';
				}
				index++;
				const formatter = createDebug.formatters[format];
				if (typeof formatter === 'function') {
					const val = args[index];
					match = formatter.call(self, val);

					// Now we need to remove `args[index]` since it's inlined in the `format`
					args.splice(index, 1);
					index--;
				}
				return match;
			});

			// Apply env-specific formatting (colors, etc.)
			createDebug.formatArgs.call(self, args);

			const logFn = self.log || createDebug.log;
			logFn.apply(self, args);
		}

		debug.namespace = namespace;
		debug.useColors = createDebug.useColors();
		debug.color = createDebug.selectColor(namespace);
		debug.extend = extend;
		debug.destroy = createDebug.destroy; // XXX Temporary. Will be removed in the next major release.

		Object.defineProperty(debug, 'enabled', {
			enumerable: true,
			configurable: false,
			get: () => {
				if (enableOverride !== null) {
					return enableOverride;
				}
				if (namespacesCache !== createDebug.namespaces) {
					namespacesCache = createDebug.namespaces;
					enabledCache = createDebug.enabled(namespace);
				}

				return enabledCache;
			},
			set: v => {
				enableOverride = v;
			}
		});

		// Env-specific initialization logic for debug instances
		if (typeof createDebug.init === 'function') {
			createDebug.init(debug);
		}

		return debug;
	}

	function extend(namespace, delimiter) {
		const newDebug = createDebug(this.namespace + (typeof delimiter === 'undefined' ? ':' : delimiter) + namespace);
		newDebug.log = this.log;
		return newDebug;
	}

	/**
	* Enables a debug mode by namespaces. This can include modes
	* separated by a colon and wildcards.
	*
	* @param {String} namespaces
	* @api public
	*/
	function enable(namespaces) {
		createDebug.save(namespaces);
		createDebug.namespaces = namespaces;

		createDebug.names = [];
		createDebug.skips = [];

		const split = (typeof namespaces === 'string' ? namespaces : '')
			.trim()
			.replace(/\s+/g, ',')
			.split(',')
			.filter(Boolean);

		for (const ns of split) {
			if (ns[0] === '-') {
				createDebug.skips.push(ns.slice(1));
			} else {
				createDebug.names.push(ns);
			}
		}
	}

	/**
	 * Checks if the given string matches a namespace template, honoring
	 * asterisks as wildcards.
	 *
	 * @param {String} search
	 * @param {String} template
	 * @return {Boolean}
	 */
	function matchesTemplate(search, template) {
		let searchIndex = 0;
		let templateIndex = 0;
		let starIndex = -1;
		let matchIndex = 0;

		while (searchIndex < search.length) {
			if (templateIndex < template.length && (template[templateIndex] === search[searchIndex] || template[templateIndex] === '*')) {
				// Match character or proceed with wildcard
				if (template[templateIndex] === '*') {
					starIndex = templateIndex;
					matchIndex = searchIndex;
					templateIndex++; // Skip the '*'
				} else {
					searchIndex++;
					templateIndex++;
				}
			} else if (starIndex !== -1) { // eslint-disable-line no-negated-condition
				// Backtrack to the last '*' and try to match more characters
				templateIndex = starIndex + 1;
				matchIndex++;
				searchIndex = matchIndex;
			} else {
				return false; // No match
			}
		}

		// Handle trailing '*' in template
		while (templateIndex < template.length && template[templateIndex] === '*') {
			templateIndex++;
		}

		return templateIndex === template.length;
	}

	/**
	* Disable debug output.
	*
	* @return {String} namespaces
	* @api public
	*/
	function disable() {
		const namespaces = [
			...createDebug.names,
			...createDebug.skips.map(namespace => '-' + namespace)
		].join(',');
		createDebug.enable('');
		return namespaces;
	}

	/**
	* Returns true if the given mode name is enabled, false otherwise.
	*
	* @param {String} name
	* @return {Boolean}
	* @api public
	*/
	function enabled(name) {
		for (const skip of createDebug.skips) {
			if (matchesTemplate(name, skip)) {
				return false;
			}
		}

		for (const ns of createDebug.names) {
			if (matchesTemplate(name, ns)) {
				return true;
			}
		}

		return false;
	}

	/**
	* Coerce `val`.
	*
	* @param {Mixed} val
	* @return {Mixed}
	* @api private
	*/
	function coerce(val) {
		if (val instanceof Error) {
			return val.stack || val.message;
		}
		return val;
	}

	/**
	* XXX DO NOT USE. This is a temporary stub function.
	* XXX It WILL be removed in the next major release.
	*/
	function destroy() {
		console.warn('Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.');
	}

	createDebug.enable(createDebug.load());

	return createDebug;
}

module.exports = setup;


/***/ }),

/***/ 2830:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/**
 * Detect Electron renderer / nwjs process, which is node, but we should
 * treat as a browser.
 */

if (typeof process === 'undefined' || process.type === 'renderer' || process.browser === true || process.__nwjs) {
	module.exports = __nccwpck_require__(6110);
} else {
	module.exports = __nccwpck_require__(5108);
}


/***/ }),

/***/ 5108:
/***/ ((module, exports, __nccwpck_require__) => {

/**
 * Module dependencies.
 */

const tty = __nccwpck_require__(2018);
const util = __nccwpck_require__(9023);

/**
 * This is the Node.js implementation of `debug()`.
 */

exports.init = init;
exports.log = log;
exports.formatArgs = formatArgs;
exports.save = save;
exports.load = load;
exports.useColors = useColors;
exports.destroy = util.deprecate(
	() => {},
	'Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.'
);

/**
 * Colors.
 */

exports.colors = [6, 2, 3, 4, 5, 1];

try {
	// Optional dependency (as in, doesn't need to be installed, NOT like optionalDependencies in package.json)
	// eslint-disable-next-line import/no-extraneous-dependencies
	const supportsColor = __nccwpck_require__(1450);

	if (supportsColor && (supportsColor.stderr || supportsColor).level >= 2) {
		exports.colors = [
			20,
			21,
			26,
			27,
			32,
			33,
			38,
			39,
			40,
			41,
			42,
			43,
			44,
			45,
			56,
			57,
			62,
			63,
			68,
			69,
			74,
			75,
			76,
			77,
			78,
			79,
			80,
			81,
			92,
			93,
			98,
			99,
			112,
			113,
			128,
			129,
			134,
			135,
			148,
			149,
			160,
			161,
			162,
			163,
			164,
			165,
			166,
			167,
			168,
			169,
			170,
			171,
			172,
			173,
			178,
			179,
			184,
			185,
			196,
			197,
			198,
			199,
			200,
			201,
			202,
			203,
			204,
			205,
			206,
			207,
			208,
			209,
			214,
			215,
			220,
			221
		];
	}
} catch (error) {
	// Swallow - we only care if `supports-color` is available; it doesn't have to be.
}

/**
 * Build up the default `inspectOpts` object from the environment variables.
 *
 *   $ DEBUG_COLORS=no DEBUG_DEPTH=10 DEBUG_SHOW_HIDDEN=enabled node script.js
 */

exports.inspectOpts = Object.keys(process.env).filter(key => {
	return /^debug_/i.test(key);
}).reduce((obj, key) => {
	// Camel-case
	const prop = key
		.substring(6)
		.toLowerCase()
		.replace(/_([a-z])/g, (_, k) => {
			return k.toUpperCase();
		});

	// Coerce string value into JS value
	let val = process.env[key];
	if (/^(yes|on|true|enabled)$/i.test(val)) {
		val = true;
	} else if (/^(no|off|false|disabled)$/i.test(val)) {
		val = false;
	} else if (val === 'null') {
		val = null;
	} else {
		val = Number(val);
	}

	obj[prop] = val;
	return obj;
}, {});

/**
 * Is stdout a TTY? Colored output is enabled when `true`.
 */

function useColors() {
	return 'colors' in exports.inspectOpts ?
		Boolean(exports.inspectOpts.colors) :
		tty.isatty(process.stderr.fd);
}

/**
 * Adds ANSI color escape codes if enabled.
 *
 * @api public
 */

function formatArgs(args) {
	const {namespace: name, useColors} = this;

	if (useColors) {
		const c = this.color;
		const colorCode = '\u001B[3' + (c < 8 ? c : '8;5;' + c);
		const prefix = `  ${colorCode};1m${name} \u001B[0m`;

		args[0] = prefix + args[0].split('\n').join('\n' + prefix);
		args.push(colorCode + 'm+' + module.exports.humanize(this.diff) + '\u001B[0m');
	} else {
		args[0] = getDate() + name + ' ' + args[0];
	}
}

function getDate() {
	if (exports.inspectOpts.hideDate) {
		return '';
	}
	return new Date().toISOString() + ' ';
}

/**
 * Invokes `util.formatWithOptions()` with the specified arguments and writes to stderr.
 */

function log(...args) {
	return process.stderr.write(util.formatWithOptions(exports.inspectOpts, ...args) + '\n');
}

/**
 * Save `namespaces`.
 *
 * @param {String} namespaces
 * @api private
 */
function save(namespaces) {
	if (namespaces) {
		process.env.DEBUG = namespaces;
	} else {
		// If you set a process.env field to null or undefined, it gets cast to the
		// string 'null' or 'undefined'. Just delete instead.
		delete process.env.DEBUG;
	}
}

/**
 * Load `namespaces`.
 *
 * @return {String} returns the previously persisted debug modes
 * @api private
 */

function load() {
	return process.env.DEBUG;
}

/**
 * Init logic for `debug` instances.
 *
 * Create a new `inspectOpts` object in case `useColors` is set
 * differently for a particular `debug` instance.
 */

function init(debug) {
	debug.inspectOpts = {};

	const keys = Object.keys(exports.inspectOpts);
	for (let i = 0; i < keys.length; i++) {
		debug.inspectOpts[keys[i]] = exports.inspectOpts[keys[i]];
	}
}

module.exports = __nccwpck_require__(897)(exports);

const {formatters} = module.exports;

/**
 * Map %o to `util.inspect()`, all on a single line.
 */

formatters.o = function (v) {
	this.inspectOpts.colors = this.useColors;
	return util.inspect(v, this.inspectOpts)
		.split('\n')
		.map(str => str.trim())
		.join(' ');
};

/**
 * Map %O to `util.inspect()`, allowing multiple lines if needed.
 */

formatters.O = function (v) {
	this.inspectOpts.colors = this.useColors;
	return util.inspect(v, this.inspectOpts);
};


/***/ }),

/***/ 8208:
/***/ ((__unused_webpack_module, exports) => {

/**
 * Copyright 2019 Huawei Technologies Co.,Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 */

exports.AclPrivate = 'private';
exports.AclPublicRead = 'public-read';
exports.AclPublicReadWrite = 'public-read-write';
exports.AclPublicReadDelivered = 'public-read-delivered';
exports.AclPublicReadWriteDelivered = 'public-read-write-delivered';
exports.AclAuthenticatedRead = 'authenticated-read';
exports.AclBucketOwnerRead = 'bucket-owner-read';
exports.AclBucketOwnerFullControl = 'bucket-owner-full-control';
exports.AclLogDeliveryWrite = 'log-delivery-write';

exports.StorageClassStandard = 'STANDARD';
exports.StorageClassWarm = 'WARM';
exports.StorageClassCold = 'COLD';
exports.StorageClassDeepArchive = 'DEEP_ARCHIVE';
exports.StorageClassIntelligentTiering = 'INTELLIGENT_TIERING';

exports.PermissionRead = 'READ';
exports.PermissionWrite = 'WRITE';
exports.PermissionReadAcp = 'READ_ACP';
exports.PermissionWriteAcp = 'WRITE_ACP';
exports.PermissionFullControl = 'FULL_CONTROL';

exports.GroupAllUsers = 'AllUsers';
exports.GroupAuthenticatedUsers = 'AuthenticatedUsers';
exports.GroupLogDelivery = 'LogDelivery';

exports.RestoreTierExpedited = 'Expedited';
exports.RestoreTierStandard = 'Standard';
exports.RestoreTierBulk = 'Bulk';

exports.GranteeGroup = 'Group';
exports.GranteeUser = 'CanonicalUser';

exports.CopyMetadata = 'COPY';
exports.ReplaceMetadata = 'REPLACE';

exports.EventObjectCreatedAll = 'ObjectCreated:*';
exports.EventObjectCreatedPut = 'ObjectCreated:Put';
exports.EventObjectCreatedPost = 'ObjectCreated:Post';
exports.EventObjectCreatedCopy = 'ObjectCreated:Copy';
exports.EventObjectCreatedCompleteMultipartUpload = 'ObjectCreated:CompleteMultipartUpload';
exports.EventObjectRemovedAll = 'ObjectRemoved:*';
exports.EventObjectRemovedDelete = 'ObjectRemoved:Delete';
exports.EventObjectRemovedDeleteMarkerCreated = 'ObjectRemoved:DeleteMarkerCreated';

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

exports.KB = KB;
exports.MB = MB;
exports.GB = GB;

exports.MAX_UPLOAD_PART_COUNT = 10000;
exports.MAX_UPLOAD_PART_SIZE = 5 * GB;
exports.DEFAULT_UPLOAD_PART_SIZE = 5 * MB;
exports.MIN_UPLOAD_PART_SIZE = 100 * KB;

exports.MAX_DOWNLOAD_PART_SIZE = 5 * GB;
exports.DEFAULT_DOWNLOAD_PART_SIZE = 5 * MB;
exports.MIN_DOWNLOAD_PART_SIZE = 100 * KB;

exports.IAM_DOMAIN_PATH_EXTENSION = '/v3.0/OS-CREDENTIAL/securitytokens';

// Object Lock (WORM) Mode
exports.ObjectLockModeCompliance = 'COMPLIANCE';
exports.ObjectLockModeGovernance = 'GOVERNANCE';

// Inventory Frequency
exports.InventoryFrequencyDaily = 'Daily';
exports.InventoryFrequencyWeekly = 'Weekly';

// Inventory Format
exports.InventoryFormatCSV = 'CSV';
exports.InventoryFormatParquet = 'Parquet';

// Inventory Included Object Versions
exports.IncludedObjectVersionsAll = 'All';
exports.IncludedObjectVersionsCurrent = 'Current';

// Inventory Optional Fields
exports.InventoryFieldSize = 'Size';
exports.InventoryFieldLastModified = 'LastModifiedDate';
exports.InventoryFieldStorageClass = 'StorageClass';
exports.InventoryFieldETag = 'ETag';
exports.InventoryFieldIsMultipartUploaded = 'IsMultipartUploaded';
exports.InventoryFieldReplicationStatus = 'ReplicationStatus';
exports.InventoryFieldEncryptionStatus = 'EncryptionStatus';


/***/ }),

/***/ 9904:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/**
 * Copyright 2019 Huawei Technologies Co.,Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 */

const fs = __nccwpck_require__(9896);
const path = __nccwpck_require__(6928);
const log4js = __nccwpck_require__(892);

function ensureDir(dir){
	fs.mkdirSync(dir, {recursive: true});
}

function LogUtil(){
	this.loggerInf = null;
	this.loggerRun = null;
	this.consoleLog = null;
}

LogUtil.prototype.initLog = function(filename, maxLogSize, backups, level, logToConsole, name, logger){
	if(logger){
		this.loggerInf = logger;
		return;
	}

	if(!filename){
		return;
	}

	let dir = path.dirname(filename);
	ensureDir(dir);
	let ext = path.extname(filename);
	let file = path.basename(filename, ext);
	if(!ext){
		ext = '.log';
	}

	level = level === undefined ? 'info' : String(level);
	maxLogSize = maxLogSize === undefined ? 102400 : parseInt(maxLogSize, 10);
	backups = backups === undefined ? 10 : parseInt(backups, 10);

	let fileInterface = path.join(dir, file + ext);
	let layoutFormat = '%d{yyyy/MM/dd HH:mm:ss SSS}|%c|%-5p|%m';
	let cateInterface = 'sdk-file';
	let cateConsole = 'sdk-console';
	if(name){
		cateInterface += ':' + String(name);
		cateConsole += ':' + String(name);
	}

	let appenders = {};
	appenders[cateConsole] = {
        type:'console',
    };
	appenders[cateInterface] = {
        type: 'file',
        filename: fileInterface,
        maxLogSize:maxLogSize,
        backups:backups,
        layout: {
            type: 'pattern',
            pattern : layoutFormat,
        }
    };

	let categories = {
		default: { appenders: [cateConsole], level: 'off' }
	};
	categories[cateInterface] =  { appenders: [cateInterface], level:level.toLowerCase()};
	categories[cateConsole] =  { appenders: [cateConsole], level:level.toLowerCase()};

	log4js.configure({
		categories: categories,
	    appenders: appenders,
	    replaceConsole: true
	});

	this.loggerInf = log4js.getLogger(cateInterface);
	if(logToConsole){
		this.consoleLog = log4js.getLogger(cateConsole);
	}
};

LogUtil.prototype._doLog = function(level, form){
	if(level.toLowerCase() === 'debug'){
		if(this.loggerInf){
			this.loggerInf.debug(form);
		}
		if(this.consoleLog){
			this.consoleLog.debug(form);
		}
	}else if(level.toLowerCase() === 'info'){
		if(this.loggerInf){
			this.loggerInf.info(form);
		}
		if(this.consoleLog){
			this.consoleLog.info(form);
		}
	}else if(level.toLowerCase() === 'warn'){
		if(this.loggerInf){
			this.loggerInf.warn(form);
		}
		if(this.consoleLog){
			this.consoleLog.warn(form);
		}
	}else if(level.toLowerCase() === 'error'){
		if(this.loggerInf){
			this.loggerInf.error(form);
		}
		if(this.consoleLog){
			this.consoleLog.error(form);
		}
	}
};

LogUtil.prototype.isLevelEnabled = function(level){
	return (this.loggerInf && this.loggerInf.isLevelEnabled(level)) || (this.consoleLog && this.consoleLog.isLevelEnabled(level));
};

LogUtil.prototype.runLog = function(level, methodName, msg){
	if(!this.loggerInf && !this.consoleLog){
		return;
	}
	let form = methodName + '|' + msg;
	this._doLog(level, form);
};


module.exports = LogUtil;


/***/ }),

/***/ 1728:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/**
 * Copyright 2019 Huawei Technologies Co.,Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 */

const util = __nccwpck_require__(9023);
const Utils = __nccwpck_require__(395);
const LogUtil = __nccwpck_require__(9904);
const enums = __nccwpck_require__(8208);
const {
	MAX_UPLOAD_PART_COUNT,

	MIN_UPLOAD_PART_SIZE,
	MAX_UPLOAD_PART_SIZE,
	DEFAULT_UPLOAD_PART_SIZE,

	MIN_DOWNLOAD_PART_SIZE,
	MAX_DOWNLOAD_PART_SIZE,
	DEFAULT_DOWNLOAD_PART_SIZE,
} = enums;
function ObsClient(param){
	this.factory(param);
}

function capitalize(key){
	return key.slice(0,1).toUpperCase() + key.slice(1);
}

const methods = [
    'headBucket',
    'getBucketMetadata',
    'deleteBucket',
    'setBucketQuota',
    'getBucketQuota',
    'getBucketStorageInfo',
    'setBucketPolicy',
    'getBucketPolicy',
    'deleteBucketPolicy',
    'setBucketVersioningConfiguration',
    'getBucketVersioningConfiguration',
    'getBucketLocation',
    'listVersions',
    'listObjects',
    'setBucketLifecycleConfiguration',
    'getBucketLifecycleConfiguration',
    'deleteBucketLifecycleConfiguration',
    'setBucketAcl',
    'getBucketAcl',
    'setBucketLoggingConfiguration',
    'getBucketLoggingConfiguration',
    'setBucketWebsiteConfiguration',
    'getBucketWebsiteConfiguration',
    'deleteBucketWebsiteConfiguration',
    'setBucketNotification',
    'getBucketNotification',
    'setBucketTagging',
    'deleteBucketTagging',
    'getBucketTagging',
    'setObjectTagging',
    'deleteObjectTagging',
    'getObjectTagging',
    'setBucketReplication',
    'deleteBucketReplication',
    'getBucketReplication',
    'getObject',
    'setObjectMetadata',
    'getObjectMetadata',
    'setObjectAcl',
    'getObjectAcl',
    'deleteObject',
    'deleteObjects',
    'listMultipartUploads',
    'listParts',
    'abortMultipartUpload',
    'completeMultipartUpload',
    'setBucketCors',
    'getBucketCors',
    'deleteBucketCors',
    'optionsBucket',
    'optionsObject',
    'setBucketStoragePolicy',
    'getBucketStoragePolicy',
    'getBucketEncryption',
    'setBucketEncryption',
    'deleteBucketEncryption',
    'getBucketDirectColdAccess',
    'setBucketDirectColdAccess',
    'deleteBucketDirectColdAccess',
    'renameObject',
    'getBucketRequesterPayment',
    'setBucketRequesterPayment',
    'putBucketPublicAccessBlock',
    'getBucketPublicAccessBlock',
    'deleteBucketPublicAccessBlock',
    'getBucketPolicyPublicStatus',
    'getBucketPublicStatus',
    'setBucketCustomDomain',
    'getBucketCustomDomain',
    'deleteBucketCustomDomain',
    'setBucketInventory',
    'getBucketInventory',
    'listBucketInventory',
    'deleteBucketInventory',
    'setObjectLockConfiguration',
    'getObjectLockConfiguration',
    'setObjectRetention',
    'setBucketMirrorBackToSource',
    'getBucketMirrorBackToSource',
    'deleteBucketMirrorBackToSource',
    'setBucketCompressPolicy',
    'getBucketCompressPolicy',
    'deleteBucketCompressPolicy',
    'truncateObject',
];

function createAction(method){
	return function(param, callback){
		this.exec(capitalize(method), param, callback);
	};
}

for(let i=0;i<methods.length;i++){
	let method = methods[i];
	ObsClient.prototype[method] = createAction(method);
}

ObsClient.prototype.createBucket = function(param, callback){
	if(this.util && this.util.isCname){
		return callback('createBucket is not allowed in customdomain mode', null);
	}
	this.exec('CreateBucket', param, callback);
};

ObsClient.prototype.listBuckets = function(param, callback){
	if(this.util && this.util.isCname){
		return callback('listBuckets is not allowed in customdomain mode', null);
	}
	this.exec('ListBuckets', param, callback);
};

ObsClient.prototype.putObject = function(param, callback){

	if(('Body' in param) && ('SourceFile' in param)){
		let err = 'the input body and sourcefile exist at same time,please specify one of either a string or file to be send!';
		if(this.log.isLevelEnabled('error')){
			this.log.runLog('error', 'PutObject', err);
		}
		return callback(new Error(err), null);
	}

	if(!('ContentType' in param)){
		if('Key' in param){
			param.ContentType = this.util.mimeTypes[param.Key.substring(param.Key.lastIndexOf('.') + 1)];
		}
		if(!param.ContentType && ('SourceFile' in param)){
			param.ContentType = this.util.mimeTypes[param.SourceFile.substring(param.SourceFile.lastIndexOf('.') + 1)];
		}
	}

	this.exec('PutObject', param, callback);
};

ObsClient.prototype.modifyObject = function(param, callback){

	if(('Body' in param) && ('SourceFile' in param)){
		let err = 'the input body and sourcefile exist at same time,please specify one of either a string or file to be send!';
		if(this.log.isLevelEnabled('error')){
			this.log.runLog('error', 'ModifyObject', err);
		}
		return callback(new Error(err), null);
	}

	if(!('ContentType' in param)){
		if('Key' in param){
			param.ContentType = this.util.mimeTypes[param.Key.substring(param.Key.lastIndexOf('.') + 1)];
		}
		if(!param.ContentType && ('SourceFile' in param)){
			param.ContentType = this.util.mimeTypes[param.SourceFile.substring(param.SourceFile.lastIndexOf('.') + 1)];
		}
	}

	this.exec('ModifyObject', param, callback);
};

ObsClient.prototype.appendObject = function(param, callback){

	if(('Body' in param) && ('SourceFile' in param)){
		let err = 'the input body and sourcefile exist at same time,please specify one of either a string or file to be send!';
		if(this.log.isLevelEnabled('error')){
			this.log.runLog('error', 'PutObject', err);
		}
		return callback(new Error(err), null);
	}

	if(!('ContentType' in param)){
		if('Key' in param){
			param.ContentType = this.util.mimeTypes[param.Key.substring(param.Key.lastIndexOf('.') + 1)];
		}
		if(!param.ContentType && ('SourceFile' in param)){
			param.ContentType = this.util.mimeTypes[param.SourceFile.substring(param.SourceFile.lastIndexOf('.') + 1)];
		}
	}

	this.exec('AppendObject', param, callback);
};

ObsClient.prototype.copyObject = function(param, callback){
	let key = 'CopySource';
	if(key in param){
		let val = param[key];
		let index = val.lastIndexOf('?versionId=');
		if(index > 0){
			param[key] = this.util.encodeURIWithSafe(val.slice(0, index)) + val.slice(index);
		}else{
			param[key] = this.util.encodeURIWithSafe(val);
		}
	}
	this.exec('CopyObject', param, callback);
};

ObsClient.prototype.copyPart = function(param, callback){
	let key = 'CopySource';
	if(key in param){
		let val = param[key];
		let index = val.lastIndexOf('?versionId=');
		if(index > 0){
			param[key] = this.util.encodeURIWithSafe(val.slice(0, index)) + val.slice(index);
		}else{
			param[key] = this.util.encodeURIWithSafe(val);
		}
	}
	this.exec('CopyPart', param, callback);
};

ObsClient.prototype.restoreObject = function(param, callback){
	this.exec('RestoreObject', param, function(err, result){
		if(!err && result.InterfaceResult && result.CommonMsg.Status < 300){
			result.InterfaceResult.RestoreStatus = result.CommonMsg.Status === 200 ? 'AVAILABLE' : 'INPROGRESS';
		}
		callback(err, result);
	});
};

ObsClient.prototype.initiateMultipartUpload = function(param, callback){
	if(!('ContentType' in param) && 'Key' in param){
		param.ContentType = this.util.mimeTypes[param.Key.substring(param.Key.lastIndexOf('.') + 1)];
	}
	this.exec('InitiateMultipartUpload', param, callback);
};


ObsClient.prototype.uploadPart = function(param, callback){
	if(('Body' in param) && ('SourceFile' in param)){
		let err = 'the input body and sourcefile exist at same time,please specify one of either a string or file to be send!';
		if(this.log.isLevelEnabled('error')){
			this.log.runLog('error', 'UploadPart', err);
		}
		return callback(new Error(err), null);
	}
	this.exec('UploadPart', param, callback);
};


ObsClient.prototype.uploadFile = function(param, callback){
	param = param || {};
	let _log = this.log;
	let obsClient = this;
	let funcName = 'uploadFile';
	let start = new Date().getTime();
	// 接收参数
	let progressCallback = param.ProgressCallback || function(){};
	let resumeCallback = param.ResumeCallback || function(){};
	callback = callback || function(){};
	let _callback = function(code, message, result){
		if(_log.isLevelEnabled('info')){
			_log.runLog('info', funcName, 'ObsClient cost ' +  (new Date().getTime()-start) + ' ms');
		}
		if(typeof code === 'string'){
			if(message){
				code += ':' + String(message);
			}
			callback(code, result);
			return;
		}
		callback(code ? (code.CommonMsg.Code + ':' + code.CommonMsg.Message) : null, result);
	};

	if(_log.isLevelEnabled('info')){
		_log.runLog('info', funcName, 'enter ' + funcName + '...' );
	}

	let bucket = param.Bucket;
	if(!bucket){
		_callback('InvalidArgument','Bucket is a required element!');
		return;
	}
	bucket = String(bucket);

	let key = param.Key;
	if(!key){
		_callback('InvalidArgument', 'Key is a required element!');
		return;
	}
	key = String(key);

	let uploadFile = param.UploadFile;
	if(!uploadFile){
		_callback('InvalidArgument', 'UploadFile is a required element!');
		return;
	}
	let fs = __nccwpck_require__(9896);
	uploadFile = String(uploadFile);

	if(!fs.existsSync(uploadFile)){
		_callback('InvalidArgument', 'UploadFile does not exist!');
		return;
	}
	let fstat = fs.statSync(uploadFile);
	if(!fstat.isFile()){
		_callback('InvalidArgument', 'UploadFile is not a file!');
		return;
	}

	let fileSize = fstat.size;

	let enableCheckpoint = param.EnableCheckpoint;
	let checkpointFile = null;
	let enableCheckSum = false;

	let taskNum = parseInt(param.TaskNum, 10) || 20;

	if(enableCheckpoint){
		checkpointFile = param.CheckpointFile;
		checkpointFile = (checkpointFile && checkpointFile !== '') ? String(checkpointFile) : uploadFile + '.upload_record';
		let pathLib = __nccwpck_require__(6928);
		let fileDir = pathLib.dirname(checkpointFile);
		if(!fs.existsSync(fileDir)){
			let mkdirsSync = function(dirname){
			    if(fs.existsSync(dirname)){
			        return true;
			    }else{
			        if(mkdirsSync(pathLib.dirname(dirname))){
			            fs.mkdirSync(dirname);
			            return true;
			        }
			    }
			};
			mkdirsSync(fileDir);
		}
		enableCheckSum = param.EnableCheckSum;
	}
	if(_log.isLevelEnabled('debug')){
		_log.runLog('debug', funcName, 'Begin to uploadFile to OBS from file:' + uploadFile);
	}

	let events = __nccwpck_require__(4434);
	let eventEmitter = new events.EventEmitter();

	let calculateUploadCheckpointMD5 = function(uploadCheckpoint){
		let data = [];
		data.push(uploadCheckpoint.bucketName);
		data.push(uploadCheckpoint.objectKey);
		data.push(uploadCheckpoint.uploadFile);
		data.push(String(uploadCheckpoint.partSize));
		data.push(String(uploadCheckpoint.partCount));
		if(uploadCheckpoint.contentType){
			data.push(uploadCheckpoint.contentType);
		}
		if(uploadCheckpoint.acl){
			data.push(uploadCheckpoint.acl);
		}
		if(uploadCheckpoint.websiteRedirectLocation){
			data.push(uploadCheckpoint.websiteRedirectLocation);
		}
		if(uploadCheckpoint.sseKms){
			data.push(uploadCheckpoint.sseKms);
		}
		if(uploadCheckpoint.sseKmsKey){
			data.push(uploadCheckpoint.sseKmsKey);
		}
		if(uploadCheckpoint.sseC){
			data.push(uploadCheckpoint.sseC);
		}
		if(uploadCheckpoint.sseCKey){
			data.push(uploadCheckpoint.sseCKey);
		}
		if(uploadCheckpoint.metadata){
			data.push(JSON.stringify(uploadCheckpoint.metadata));
		}
		if(uploadCheckpoint.uploadId){
			data.push(uploadCheckpoint.uploadId);
		}
		if(uploadCheckpoint.partsMeta && (uploadCheckpoint.partsMeta instanceof Object)){
			for(let key in uploadCheckpoint.partsMeta){
				if ({}.hasOwnProperty.call(uploadCheckpoint.partsMeta, key)) {
					data.push(String(key));
					let partMeta = uploadCheckpoint.partsMeta[key];
					if(partMeta){
						data.push(String(partMeta.offset));
						data.push(String(partMeta.partSize));
						data.push(String(partMeta.isCompleted));
						data.push(String(partMeta.etag));
					}
				}
			}
		}
		return obsClient.util.bufMD5(Buffer.from(data.join(''), 'utf8'));
	};

	let writeCheckpointFileSync = function(checkpointFile, uploadCheckpoint){
		try{
			fs.writeFileSync(checkpointFile, JSON.stringify(uploadCheckpoint));
			return true;
		}catch(e){
			_callback('WriteCheckpointFileError', e);
			if(_log.isLevelEnabled('debug')){
				_log.runLog('debug', funcName, 'Write checkpoint file failed and abort upload, uploadId ' + uploadCheckpoint.uploadId);
			}
			if(uploadCheckpoint.uploadId){
				obsClient.abortMultipartUpload({
					Bucket:uploadCheckpoint.bucketName,
					Key:uploadCheckpoint.objectKey,
					UploadId:uploadCheckpoint.uploadId,
				},function(e, r){
					if(!e && (r.CommonMsg.Status < 300 || r.CommonMsg.Status === 404)){
						fs.unlink(checkpointFile, function(){});
					}
				});
			}else{
				fs.unlink(checkpointFile, function(){});
			}
			return false;
		}
	};

	let abortRequest = function(uploadCheckpoint, checkpointFile, code, message){
		if(uploadCheckpoint && uploadCheckpoint.uploadId){
			obsClient.abortMultipartUpload({
				Bucket:uploadCheckpoint.bucketName,
				Key:uploadCheckpoint.objectKey,
				UploadId:uploadCheckpoint.uploadId,
			},function(e, r){
				if(!e && (r.CommonMsg.Status < 300 || r.CommonMsg.Status === 404)){
					if(checkpointFile){
						fs.unlink(checkpointFile, function(){});
					}
				}
				_callback(code, message);
			});
		}else{
			if(checkpointFile){
				fs.unlink(checkpointFile, function(){});
			}
			_callback(code, message);
		}
	};

	let transResultToError = function(result){
		let ret = [];
		if(result && result.CommonMsg){
			ret.push('Status:' + result.CommonMsg.Status);
			ret.push('Code:' + result.CommonMsg.Code);
			ret.push('Message:' + result.CommonMsg.Message);
		}
		return ret.join(',');
	};

	eventEmitter.on('start to uploadFile', function(uploadCheckpoint){
		if(!uploadCheckpoint){
			uploadCheckpoint = {};
		}
		if(!uploadCheckpoint.partsMeta){
			uploadCheckpoint.partsMeta = {};
		}
		let startToUploadFile = function(uploadId){
			let finishedCount = 0;
			let hasError = false;
			let isAbort = false;
			let finishedBytes = 0;
			if(uploadCheckpoint.partsMeta){
				for(let i of Object.keys(uploadCheckpoint.partsMeta)){
					if(uploadCheckpoint.partsMeta[i].isCompleted){
						finishedBytes += uploadCheckpoint.partSize
					}
				}
			}
			let partsLoaded = {};
			let startTime = new Date().getTime();

			resumeCallback({
				cancel : function(){
					isAbort = true;
					_callback('Upload suspened', 'The process of uploadFile is suspened, you can try again')
				},
				abort : function(){
					isAbort = true;
					abortRequest(uploadCheckpoint, checkpointFile, 'Upload isAbort', 'The process of uploadFile is isAbort');
				},
			});

			let progressCallbacks = function(partNumber, loaded){
				if(isAbort){
					return;
				}
				finishedBytes += loaded;
				if(partsLoaded[partNumber]){
					finishedBytes -= partsLoaded[partNumber];
				}
				partsLoaded[partNumber] = loaded;
				progressCallback(finishedBytes, uploadCheckpoint.uploadFileStat.fileSize, (new Date().getTime() - startTime) / 1000);
			};

			// 段进度
			let createProgressCallbackByPartNumber = function(partNumber){
				return function(loaded, total, cost){
					progressCallbacks(partNumber, loaded);
				};
			};
			let completedRequest = function(){
				if(finishedCount === uploadCheckpoint.partCount){
					if(!hasError){
						let parts = [];
						for(let partNumber in uploadCheckpoint.partsMeta){
							if ({}.hasOwnProperty.call(uploadCheckpoint.partsMeta, partNumber)) {
								parts.push({
									PartNumber : partNumber,
									ETag : uploadCheckpoint.partsMeta[partNumber].etag
								});
							}
						}
						obsClient.completeMultipartUpload({
							Bucket: uploadCheckpoint.bucketName,
							Key : uploadCheckpoint.objectKey,
							UploadId : uploadId,
							Parts: parts
						}, function(err, result){
							if(err || result.CommonMsg.Status >= 500){
								if(checkpointFile){
									_callback('IncompletedUpload', err ? err : transResultToError(result));
								}else{
									abortRequest(uploadCheckpoint, checkpointFile, 'UploadFileFailed', err ? err : transResultToError(result));
								}
							}else if(result.CommonMsg.Status >= 300 && result.CommonMsg.Status < 500){
								abortRequest(uploadCheckpoint, checkpointFile, result.CommonMsg.Code, result.CommonMsg.Message);
							}else{
								if(checkpointFile){
									fs.unlink(checkpointFile, function(){});
								}
								_callback(null, null, result);
							}
						});
					}else{
						if(checkpointFile){
							_callback('IncompletedUpload','UploadFile finished with error, you can retry with the same parameters');
						}else{
							abortRequest(uploadCheckpoint, checkpointFile, 'UploadFileFailed', 'UploadFile finished with error!');
						}
					}
				}
			};

			eventEmitter.on('doUpload', function(currentGroupIndex, groupCount, taskNum){
				let start = (currentGroupIndex - 1) * taskNum;
				let end = (currentGroupIndex === groupCount) ? uploadCheckpoint.partCount : currentGroupIndex * taskNum;
				let finishedCountGroup = 0;
				while(start<end){
					if(isAbort){
						return
					}
					let partNumber = start + 1;
					if(uploadCheckpoint.partsMeta[partNumber] && uploadCheckpoint.partsMeta[partNumber].isCompleted){
						finishedCount++;
						finishedCountGroup++;
						let _taskNum = (currentGroupIndex === groupCount) ? (uploadCheckpoint.partCount - (currentGroupIndex - 1) * taskNum) : taskNum;
						if(finishedCountGroup === _taskNum && finishedCount < uploadCheckpoint.partCount){
							eventEmitter.emit('doUpload', currentGroupIndex + 1, groupCount, taskNum);
						}
						completedRequest();
					}else{
						let offset = start * uploadCheckpoint.partSize;
						let currPartSize = (start + 1 === uploadCheckpoint.partCount) ? uploadCheckpoint.uploadFileStat.fileSize - offset : uploadCheckpoint.partSize;
						obsClient.uploadPart({
							Bucket : uploadCheckpoint.bucketName,
							Key: uploadCheckpoint.objectKey,
							PartNumber: partNumber,
							UploadId : uploadId,
							SourceFile: uploadCheckpoint.uploadFile,
							Offset : offset,
							PartSize : currPartSize,
							SseC : uploadCheckpoint.sseC,
							SseCKey : uploadCheckpoint.sseCKey,
							ProgressCallback : createProgressCallbackByPartNumber(partNumber),
						}, function(err, result) {
							if(isAbort){
								return
							}
							let partMeta = {offset : offset, partSize : currPartSize};
							if(err || result.CommonMsg.Status >= 500){
								partMeta.isCompleted = false;
								hasError = true;
							}else if(result.CommonMsg.Status >= 300 && result.CommonMsg.Status < 500){
								isAbort = true;
								abortRequest(uploadCheckpoint, checkpointFile, result.CommonMsg.Code, result.CommonMsg.Message);
								return;
							}else{
								partMeta.etag = result.InterfaceResult.ETag;
								partMeta.isCompleted = true;
							}
							uploadCheckpoint.partsMeta[partNumber] = partMeta;
							if(_log.isLevelEnabled('debug')){
								_log.runLog('debug', funcName, 'Part ' + String(partNumber) + ' is finished, uploadId ' + uploadId);
							}
							uploadCheckpoint.md5 = calculateUploadCheckpointMD5(uploadCheckpoint);
							if(checkpointFile && !writeCheckpointFileSync(checkpointFile, uploadCheckpoint)){
								return;
							}
							finishedCount++;
							finishedCountGroup++;
							let _taskNum = (currentGroupIndex === groupCount) ? (uploadCheckpoint.partCount - (currentGroupIndex - 1) * taskNum) : taskNum;
							if(finishedCountGroup === _taskNum && finishedCount < uploadCheckpoint.partCount){
								eventEmitter.emit('doUpload', currentGroupIndex + 1, groupCount, taskNum);
							}
							completedRequest();
						});
					}
					start++;
				}
			});

			let groupCount = (uploadCheckpoint.partCount % taskNum === 0) ? (uploadCheckpoint.partCount / taskNum) : (Math.floor(uploadCheckpoint.partCount / taskNum) + 1);
			eventEmitter.emit('doUpload', 1, groupCount, taskNum);
		};

		let uploadId = uploadCheckpoint.uploadId;
		if(!uploadId){
			let contentType = uploadCheckpoint.contentType ? uploadCheckpoint.contentType : obsClient.util.mimeTypes[key.substring(key.lastIndexOf('.') + 1)];

			if(!contentType){
				contentType = obsClient.util.mimeTypes[uploadFile.substring(uploadFile.lastIndexOf('.') + 1)];
			}

			obsClient.initiateMultipartUpload({
				Bucket : uploadCheckpoint.bucketName,
				Key : uploadCheckpoint.objectKey,
				ACL : uploadCheckpoint.acl,
				Metadata : uploadCheckpoint.metadata,
				WebsiteRedirectLocation : uploadCheckpoint.websiteRedirectLocation,
				ContentType : contentType,
				SseKms : uploadCheckpoint.sseKms,
				SseKmsKey : uploadCheckpoint.sseKmsKey,
				SseC : uploadCheckpoint.sseC,
				SseCKey : uploadCheckpoint.sseCKey,
				Expires : uploadCheckpoint.expires
			}, function(err, result){
				if(err){
					if(checkpointFile){
						fs.unlink(checkpointFile, function(){});
					}
					_callback('InitiateMultipartUploadFailed',err);
					return;
				}
				if(result.CommonMsg.Status >= 300){
					if(checkpointFile){
						fs.unlink(checkpointFile, function(){});
					}
					_callback(result);
					return;
				}

				uploadId = result.InterfaceResult.UploadId;
				uploadCheckpoint.uploadId = uploadId;
				uploadCheckpoint.md5 = calculateUploadCheckpointMD5(uploadCheckpoint);
				if(_log.isLevelEnabled('debug')){
					_log.runLog('debug', funcName, 'Claim a new upload id ' + uploadId);
				}
				if(checkpointFile && !writeCheckpointFileSync(checkpointFile, uploadCheckpoint)){
					return;
				}
				startToUploadFile(uploadId);
			});
		}else{
			startToUploadFile(uploadId);
		}
	});

	let uploadCheckpoint;
	let partSize = parseInt(param.PartSize, 10);
	let partCount;
	if(fileSize === 0){
		partSize = 0;
		partCount = 1;
	}else{
		if (isNaN(partSize) || partSize < MIN_UPLOAD_PART_SIZE || partSize > MAX_UPLOAD_PART_SIZE) {
			partSize = DEFAULT_UPLOAD_PART_SIZE;
		}
		partCount = Math.floor(fileSize / partSize);
		if (partCount > MAX_UPLOAD_PART_COUNT) {
			partCount = MAX_UPLOAD_PART_COUNT;
			partSize = Math.ceil(fileSize / partCount);
		} else {
			if(fileSize % partSize !== 0){
				partCount++;
			}
		}
	}
	if(_log.isLevelEnabled('debug')){
		_log.runLog('debug', funcName, 'Total parts count ' + partCount);
	}
	uploadCheckpoint = {bucketName: bucket, objectKey: key, uploadFile : uploadFile, partSize : partSize, partCount : partCount};
	uploadCheckpoint.contentType = param.ContentType;
	uploadCheckpoint.acl = param.ACL;
	uploadCheckpoint.websiteRedirectLocation = param.WebsiteRedirectLocation;
	uploadCheckpoint.sseKms = param.SseKms;
	uploadCheckpoint.sseKmsKey = param.SseKmsKey;
	uploadCheckpoint.sseC = param.sseC;
	uploadCheckpoint.sseCKey = param.SseCKey;
	uploadCheckpoint.metadata = param.Metadata;
	uploadCheckpoint.expires = param.Expires;
	uploadCheckpoint.md5 = calculateUploadCheckpointMD5(uploadCheckpoint);
	uploadCheckpoint.uploadFileStat = {fileSize : fileSize, lastModified : fstat.mtime.toUTCString()};

	if(checkpointFile){
		if(!fs.existsSync(checkpointFile)){// call uploadFile first time
			eventEmitter.on('start to writeFile', function(){
				fs.writeFile(checkpointFile, JSON.stringify(uploadCheckpoint), function(err){
					if(err){
						_callback('WriteCheckpointFileError',err);
						return;
					}
					eventEmitter.emit('start to uploadFile', uploadCheckpoint);
				});
			});
			if(enableCheckSum){
				obsClient.util.fileMD5(uploadFile, function(err, checkSum){
					if(err){
						checkSum = '';
					}
					uploadCheckpoint.uploadFileStat.checkSum = checkSum;
					eventEmitter.emit('start to writeFile');
				});
			}else{
				eventEmitter.emit('start to writeFile');
			}
		}else{
			fs.readFile(checkpointFile, function(err, data){
				if(err){
					fs.unlink(checkpointFile, function(){});
					_callback('ReadCheckpointFileError',err);
					return;
				}
				try{
					uploadCheckpoint = JSON.parse(data);
				}catch(e){
					fs.unlink(checkpointFile, function(){});
					_callback('ParseCheckpointFileError', e);
					return;
				}
				if(!uploadCheckpoint || uploadCheckpoint.bucketName !== bucket || uploadCheckpoint.objectKey !== key || uploadCheckpoint.uploadFile !== uploadFile ||
						!uploadCheckpoint.uploadFileStat || uploadCheckpoint.uploadFileStat.fileSize !== fstat.size || uploadCheckpoint.uploadFileStat.lastModified !== fstat.mtime.toUTCString() ||
						uploadCheckpoint.md5 !== calculateUploadCheckpointMD5(uploadCheckpoint)){
					abortRequest(uploadCheckpoint, checkpointFile, 'CheckpointFileInvalid', 'CheckpointFile is invalid!');
					return;
				}

				if(uploadCheckpoint.uploadFileStat.checkSum){
					obsClient.util.fileMD5(uploadFile, function(err, checkSum){
						if(err || checkSum !== uploadCheckpoint.uploadFileStat.checkSum){
							abortRequest(uploadCheckpoint, checkpointFile, 'CheckpointFileInvalid','CheckpointFile is invalid!');
							return;
						}
						eventEmitter.emit('start to uploadFile', uploadCheckpoint);
					});
				}else{
					eventEmitter.emit('start to uploadFile', uploadCheckpoint);
				}
			});
		}
	}else{
		eventEmitter.emit('start to uploadFile', uploadCheckpoint);
	}
};

// 当指定了参数DownloadFile，将使用此值作为保存文件名，否则使用对象名作为保存文件名， 保存时将覆盖同名文件。
// 另外，还将使用 保存文件名+".obsnodejssdk.tmp"后缀的形式 作为下载过程中的临时中间文件名，且也会覆盖同名文件。
// 另外，当开启了断点延续下载（EnableCheckpoint=true），还将使用 参数CheckpointFile（如果没有指定CheckpointFile将使用对象名）+".obsnodejssdk.chkpt"后缀的形式 作为保存历史下载情况和校验信息的文件名，且也会覆盖同名文件。
ObsClient.prototype.downloadFile = function(param, callback){
	param = param || {};
	let _log = this.log;
	let obsClient = this;
	let funcName = 'downloadFile';
	let start = new Date().getTime();
	let progressCallback = param.ProgressCallback || function(){};
	let resumeCallback = param.ResumeCallback || function(){};
	callback = callback || function(){};
	let _callback = function(code, message, result){
		if(_log.isLevelEnabled('info')){
			_log.runLog('info', funcName, 'ObsClient cost ' +  (new Date().getTime() - start) + ' ms');
		}
		if(typeof code === 'string'){
			if(message){
				code += ':' + String(message);
			}
			callback(code, result);
		}else{
			callback(code ? (code.CommonMsg.Code + ':' + code.CommonMsg.Message) : null, result);
		}
	};

	_log.runLog('debug', funcName, 'enter ' + funcName + '...' );

	let bucket = param.Bucket;
	if(!bucket){
		_log.runLog('error', funcName, 'Bucket is a required element!');
		_callback('InvalidArgument','Bucket is a required element!');
		return;
	}
	bucket = String(bucket);

	let key = param.Key;
	if(!key){
		_log.runLog('error', funcName, 'Key is a required element!');
		_callback('InvalidArgument', 'Key is a required element!');
		return;
	}
	key = String(key);

	let pathLib = __nccwpck_require__(6928);

	let downloadFile;
	if(!param.DownloadFile){
		downloadFile = (__nccwpck_require__(932).cwd)() + pathLib.sep + key;
		_log.runLog('info', funcName, 'DownloadFile is not set, will put file to path:' + downloadFile + ", by default");
	}else{
		downloadFile = String(param.DownloadFile);
	}
	let tmpSuffix = ".obsnodejssdk.tmp";
	let chkSuffix = ".obsnodejssdk.chkpt";
	let downloadTempFile = downloadFile + tmpSuffix;
	let fs = __nccwpck_require__(9896);

	let taskNum = parseInt(param.TaskNum, 10) || 10;

	let initWriteAndClose4DownloadTmpFile = function(tmpFileFd, tmpFile, tmpFileSize, callback) {
		let buffer = Buffer.from('1', 'utf8');
		let start = new Date().getTime();
		fs.write(tmpFileFd, buffer, 0, 1, tmpFileSize - 1, (werr)=>{
			_log.runLog('debug', 'prepareDownloadTempFile', ` prepare ${tmpFile} cost ` + (new Date().getTime() - start) + ' ms');
			if(werr){
				_log.runLog('error', 'prepareDownloadTempFile', `ftruncate temp file:${tmpFile} failed , and cost: ${(new Date().getTime() - start) / 1000}`);
				_log.runLog('error', 'prepareDownloadTempFile', `ftruncate temp file:${tmpFile} failed , err:${werr.stack}`);
				fs.unlinkSync(tmpFile);
				return callback(false, tmpFile);
			}
			fs.close(tmpFileFd, (err)=>{
				if(err){
					_log.runLog('error', 'prepareDownloadTempFile', `close fd failed, err:${err.stack}`);
					fs.unlinkSync(tmpFile);
					return callback(false, tmpFile);
				}
				return callback(true, tmpFile);
			});
		});
	}

	let initDownloadTmpFile = function(tmpFile, tmpFileSize, callback) {
		fs.open(tmpFile, 'w', (oerr, fd)=>{
			if(oerr){
				_log.runLog('error', 'prepareDownloadTempFile', `create temp download file ${tmpFile}  failed, error:${oerr.stack}`);
				_callback('InnerError',  `create temp download file ${tmpFile}  failed, error:${oerr.stack}`);
				return callback(false, tmpFile);
			}

			let start = new Date().getTime();
			fs.ftruncate(fd, tmpFileSize, (terr)=>{
				if(terr){
					// 例如fat、exfat文件系统，将导致fs.ftruncate()报错
					initWriteAndClose4DownloadTmpFile(fd, tmpFile, tmpFileSize, callback);
				}
				else {
					_log.runLog('debug', 'prepareDownloadTempFile', ` prepare ${tmpFile} cost ` + (new Date().getTime() - start) + ' ms');
					fs.close(fd, (err)=>{
						if(err){
							_log.runLog('error', 'prepareDownloadTempFile', `close fd failed, err:${err.stack}`);
							fs.unlinkSync(tmpFile);
							return callback(false, tmpFile);
						}
						return callback(true, tmpFile);
					});
				}
			});
		});
	}

	const prepareDownloadTempFile = util.promisify((tmpFile, tmpFileSize, callback) => {
		if(fs.existsSync(tmpFile)){
			try{
				fs.unlinkSync(tmpFile);
			}catch(e){
				_log.runLog('error', 'prepareDownloadTempFile',  `delete ${tmpFile} file failed , exception: ${e}`);
				_callback('DeleteTempFileError', `delete ${tmpFile} file failed , exception: ${e}`);
				return;
			}
		}

		initDownloadTmpFile(tmpFile, tmpFileSize, callback);
	});

	let mkdirsSync = function(dirname){
		if(fs.existsSync(dirname)){
			return true;
		}else{
			if(mkdirsSync(pathLib.dirname(dirname))){
				fs.mkdirSync(dirname);
				return true;
			}
		}
	};

	obsClient.getObjectMetadata({
		Bucket : bucket,
		Key : key,
		VersionId : param.VersionId,
		SseC: param.SseC,
		SseCKey: param.SseCKey,
	}, function(err, result){
		_log.runLog('debug', funcName, ` getObjectMetadata of ${key} cost ` + (new Date().getTime() - start) + ' ms');

		let enableCheckpoint = param.EnableCheckpoint;
		let checkpointFile = null;

		if(enableCheckpoint){
			checkpointFile = param.CheckpointFile;
			checkpointFile = (checkpointFile && checkpointFile !== '') ? String(checkpointFile) : downloadFile + chkSuffix;
			let checkPointFileDir = pathLib.dirname(checkpointFile);
			if(!fs.existsSync(checkPointFileDir)){
				mkdirsSync(checkPointFileDir);
			}
		}

		let tempFileDir = pathLib.dirname(downloadTempFile);
		if(!fs.existsSync(tempFileDir)){
			mkdirsSync(tempFileDir);
		}

		if(err || result.CommonMsg.Status >= 500){
			_log.runLog('warn', funcName,  'the peer server occur exception!');
			_callback('GetObjectSizeError', err);
			return;
		}

		if(result.CommonMsg.Status >= 300 && result.CommonMsg.Status < 500){
			_log.runLog('warn', funcName,  result.CommonMsg.Message);
			_callback(result);
			return;
		}

		let objectSize = parseInt(result.InterfaceResult.ContentLength, 10);

		if(objectSize === 0){
			fs.writeFileSync(downloadFile, Buffer.from(''));
			callback(null, result);
			return;
		}

		let objestStat = result;

		let events = __nccwpck_require__(4434);
		let eventEmitter = new events.EventEmitter();

		let calculateDownloadCheckpointMD5 = function(downloadCheckpoint){
			let data = [];
			data.push(downloadCheckpoint.bucketName);
			data.push(downloadCheckpoint.objectKey);
			data.push(downloadCheckpoint.downloadFile);
			data.push(String(downloadCheckpoint.partSize));
			data.push(String(downloadCheckpoint.partCount));
			if(downloadCheckpoint.versionId){
				data.push(downloadCheckpoint.versionId);
			}
			if(downloadCheckpoint.ifMatch){
				data.push(downloadCheckpoint.ifMatch);
			}
			if(downloadCheckpoint.ifModifiedSince){
				data.push(downloadCheckpoint.ifModifiedSince);
			}
			if(downloadCheckpoint.ifNoneMatch){
				data.push(downloadCheckpoint.ifNoneMatch);
			}
			if(downloadCheckpoint.ifUnmodifiedSince){
				data.push(downloadCheckpoint.ifUnmodifiedSince);
			}
			if(downloadCheckpoint.sseC){
				data.push(downloadCheckpoint.sseC);
			}
			if(downloadCheckpoint.sseCKey){
				data.push(downloadCheckpoint.sseCKey);
			}
			if(downloadCheckpoint.partsMeta && (downloadCheckpoint.partsMeta instanceof Object)){
				// key是分段段号，且在partsMeta上最小编号是1。
				for(let key in downloadCheckpoint.partsMeta){
					if ({}.hasOwnProperty.call(downloadCheckpoint.partsMeta, key)) {
						data.push(String(key));
						let partMeta = downloadCheckpoint.partsMeta[key];
						if(partMeta){
							data.push(String(partMeta.startPos));
							data.push(String(partMeta.endPos));
							data.push(String(partMeta.isCompleted));
						}
					}
				}
			}
			return obsClient.util.bufMD5(Buffer.from(data.join(''), 'utf8'));
		};

		let writeCheckpointFileSync = function(checkpointFile, downloadCheckpoint){
			try{
				if(fs.existsSync(downloadTempFile)){
					let tempFileStat = fs.statSync(downloadTempFile);
					if(!downloadCheckpoint.tempFileStatus){
						downloadCheckpoint.tempFileStatus = {};
					}
					downloadCheckpoint.tempFileStatus.fileName = downloadTempFile;
					downloadCheckpoint.tempFileStatus.fileSize = tempFileStat.size;
					downloadCheckpoint.tempFileStatus.lastModified = tempFileStat.mtime.toUTCString();
				}
				fs.writeFileSync(checkpointFile, JSON.stringify(downloadCheckpoint));
				return true;
			}catch(e){
				fs.unlinkSync(checkpointFile, function(){});
				fs.unlinkSync(downloadTempFile, function(){});
				_callback('WriteCheckpointFileError', e);
				_log.runLog('error', funcName, 'Write checkpoint file failed, err: ' + e);
				return false;
			}
		};

		eventEmitter.on('start to downloadFile', function(downloadCheckpoint){
			if(!downloadCheckpoint){
				downloadCheckpoint = {};
			}

			if(!downloadCheckpoint.partsMeta){
				downloadCheckpoint.partsMeta = {};
			}

			_log.runLog('debug', funcName, 'Begin to downloadFile from OBS to:' + downloadFile);

			let finishedCount = 0;
			let hasError = false;
			let isAbort = false;
			let finishedBytes = 0;
			if(downloadCheckpoint.partsMeta){
				for(let i of Object.keys(downloadCheckpoint.partsMeta)){
					if(downloadCheckpoint.partsMeta[i].isCompleted){
						finishedBytes += downloadCheckpoint.partSize
					}
				}
			}
			let partsLoaded = {};
			let startTime = new Date().getTime();

			resumeCallback({
				cancel : function(){
					isAbort = true;
					_callback('Download suspened', 'The process of downloadFile is suspened, you can try again')
				}
			});

			let progressCallbacks = function(partNumber, loaded){
				if(isAbort){
					return;
				}
				finishedBytes += loaded;
				if(partsLoaded[partNumber]){
					finishedBytes -= partsLoaded[partNumber];
				}
				partsLoaded[partNumber] = loaded;
				progressCallback(finishedBytes, downloadCheckpoint.objectStatus.objectSize, (new Date().getTime() - startTime) / 1000);
			};

			// 段进度
			let createProgressCallbackByStartPart = function(partNumber){
				return function(loaded, total, cost){
					progressCallbacks(partNumber, loaded);
				};
			};
			let tryCompletedDownload = function(){
				if(finishedCount !== downloadCheckpoint.partCount){
					return;
				}

				_log.runLog('debug', funcName, ` getObject of ${key} cost ` + (new Date().getTime() - start) + ' ms');

				if(!hasError){
					fs.rename(downloadTempFile, downloadFile, function(err){
						if(err){
							_log.runLog('error', 'completedDownload',  `DownloadFile finished but rename temp file error: ${err.stack}`);
							if(checkpointFile){
								if(!writeCheckpointFileSync(checkpointFile, downloadCheckpoint)){
									return;
								}
								_callback('IncompletedDownload',`you can retry with the same parameters, DownloadFile finished but rename temp file error: ${err.stack}`);
							}else{
								try { fs.unlinkSync(downloadTempFile); } catch(e) {}
								_callback('DownloadFileFailed', `DownloadFile finished but rename temp file error: ${err.stack}`);
							}
							return;
						}

						// rename成功后，删除checkpointFile
						if(checkpointFile){
							try { fs.unlinkSync(checkpointFile); } catch(e) {}
						}
						if(result && result.InterfaceResult){
							delete result.InterfaceResult.ContentLength;
						}
						_callback(null, null, result);
					});
				}else{
					if(checkpointFile){
						if(!writeCheckpointFileSync(checkpointFile, downloadCheckpoint)){
							return;
						}
						_callback('IncompletedDownload','DownloadFile finished with error, you can retry with the same parameters');
					}else{
						try { fs.unlinkSync(downloadTempFile); } catch(e) {}
						_callback('DownloadFileFailed','DownloadFile finished with error');
					}
				}
			};

			eventEmitter.on('doDownload', function(currentGroupIndex, groupCount, taskNum){
				let start = (currentGroupIndex - 1) * taskNum;
				let end = (currentGroupIndex === groupCount) ? downloadCheckpoint.partCount : currentGroupIndex * taskNum;
				let finishedCountInGroup = 0;

				let currStepEnd = function(i, partMeta, doNextRoundDownload) {
					downloadCheckpoint.partsMeta[i] = partMeta;
					downloadCheckpoint.md5 = calculateDownloadCheckpointMD5(downloadCheckpoint);
					if(checkpointFile && !writeCheckpointFileSync(checkpointFile, downloadCheckpoint)){
						return;
					}
					finishedCount++;
					finishedCountInGroup++;

					if(!doNextRoundDownload) {
						return;
					}

					let _taskNum = (currentGroupIndex === groupCount) ? (downloadCheckpoint.partCount - (currentGroupIndex - 1) * taskNum) : taskNum;
					if(finishedCountInGroup === _taskNum && finishedCount < downloadCheckpoint.partCount){
						eventEmitter.emit('doDownload', currentGroupIndex + 1, groupCount, taskNum);
					}
					else if(finishedCountInGroup === _taskNum && finishedCount === downloadCheckpoint.partCount){
						tryCompletedDownload();
					}
				}

				let checkSkipPartI = function(i) {
					if(downloadCheckpoint.partsMeta[i] && downloadCheckpoint.partsMeta[i].isCompleted){
						finishedCount++;
						finishedCountInGroup++;
						let _taskNum = (currentGroupIndex === groupCount) ? (downloadCheckpoint.partCount - (currentGroupIndex - 1) * taskNum) : taskNum;
						if(finishedCountInGroup === _taskNum && finishedCount < downloadCheckpoint.partCount){
							// 开启下一组下载
							eventEmitter.emit('doDownload', currentGroupIndex + 1, groupCount, taskNum);
						}
						else if(finishedCountInGroup === _taskNum && finishedCount === downloadCheckpoint.partCount){
							tryCompletedDownload();
						}
						return true;
					}else {
						return false;
					}
				}

				let savePartIdata = function(i, startPos, partMeta, result) {
					let stream;

					try{
						let res = result.InterfaceResult.Content;

						stream = fs.createWriteStream(downloadTempFile, {
							flags : 'r+',
							start : startPos,
							autoClose: true // 如果 autoClose 被设置为 true（默认的行为），则当 'error' 或 'finish' 事件时，文件描述符会被自动地关闭
						});
						stream.on('error', (err) => {
							hasError = true;
							partMeta.isCompleted = false;
							currStepEnd(i, partMeta, false);
							_log.runLog('warn', funcName, `write to downloadTempFile occur exception : ${err.stack}`);
							_callback('DownloadFileFailed',`write to downloadTempFile occur exception : ${err.stack}`);
							delete result.InterfaceResult.Content;
						});

						res.on('error', (err) => {
							// 如果可读流在处理期间发送错误，则可写流目标不会自动关闭。 如果发生错误，则需要手动关闭每个流以防止内存泄漏。
							hasError = true;
							try {
								stream.close();
							} catch (error) {
								_log.runLog('warn', funcName, 'close downloadTempFile stream failed!');
							}

							// error事件之后，不会有除了close事件之外的其他事件

							partMeta.isCompleted = false;
							currStepEnd(i, partMeta, false);
							_log.runLog('warn', funcName, `getObject occur exception during the processing data time : ${err.stack}!`);
							_callback('DownloadFileFailed',`getObject occur exception during the processing data time : ${err.stack}!`);
							delete result.InterfaceResult.Content;
						}).on('end', () => {
							if (!res.complete) {
								hasError = true;
								partMeta.isCompleted = false;
								_log.runLog('warn', funcName, 'getObject occur exception that does not complete the data transmission!');
								_callback('DownloadFileFailed','getObject occur exception that does not complete the data transmission!');
								delete result.InterfaceResult.Content;
							}
							else {
								partMeta.isCompleted = true;
							}

							currStepEnd(i, partMeta, true);
						});

						res.pipe(stream, {end: true});
					}catch(e){
						hasError = true;
						_log.runLog('warn', funcName, 'write to downloadTempFile occering execption:' + e);
					}
				}

				let downLoadPartI = function(i) {
					if(checkSkipPartI(i)) {
						return;
					}

					let startPos = (i-1) * downloadCheckpoint.partSize;
					let endPos = (i === downloadCheckpoint.partCount) ? (downloadCheckpoint.objectStatus.objectSize-1) : (i * downloadCheckpoint.partSize - 1);
					let partStartTime = new Date().getTime();

					obsClient.getObject({
						Bucket: downloadCheckpoint.bucketName,
						Key: downloadCheckpoint.objectKey,
						VersionId : downloadCheckpoint.versionId,
						Range: 'bytes=' + startPos + '-' + endPos,
						SaveAsStream : true,
						IfMatch : downloadCheckpoint.ifMatch,
						IfModifiedSince : downloadCheckpoint.ifModifiedSince,
						IfNoneMatch : downloadCheckpoint.ifNoneMatch,
						IfUnmodifiedSince : downloadCheckpoint.ifUnmodifiedSince,
						SseC : downloadCheckpoint.sseC,
						SseCKey : downloadCheckpoint.sseCKey,
						ProgressCallback : createProgressCallbackByStartPart(i),
					}, function(err, result) {
						_log.runLog('debug', funcName, ` get part data, first to get the response, cost ` + (new Date().getTime() - partStartTime) + ' ms');

						let partMeta = {startPos : startPos, endPos : endPos};

						if(err || result.CommonMsg.Status >= 500){
							partMeta.isCompleted = false;
							// hasError 控制completedDownload()是否rename tempDownloadFile to DownloadFile.
							hasError = true;
							currStepEnd(i, partMeta, true);
							_callback('DownloadFileFailed','the peer server occur exception!');
							_log.runLog('warn', funcName, 'the peer server occur exception!');
						}else if(result.CommonMsg.Status >= 300 && result.CommonMsg.Status < 500){
							isAbort = true;
							_callback(result);
							_log.runLog('warn', funcName,  result.CommonMsg.Message);
							return;
						}else{
							savePartIdata(i, startPos, partMeta, result);
						}
					});
				}

				while(start < end) {
					if(isAbort){
						return;
					}

					let i = start + 1;
					downLoadPartI(i);
					start++;
				}
			});

			let groupCount = (downloadCheckpoint.partCount % taskNum === 0) ? (downloadCheckpoint.partCount / taskNum) : (Math.floor(downloadCheckpoint.partCount / taskNum) + 1);
			let defaultMaxListeners = eventEmitter.getMaxListeners();
			if(groupCount > defaultMaxListeners) {
				eventEmitter.setMaxListeners(groupCount + 1);
				_log.runLog('debug', funcName, 'eventEmitter setMaxListeners from  ' + defaultMaxListeners + ' to ' + eventEmitter.getMaxListeners());
			}

			eventEmitter.emit('doDownload', 1, groupCount, taskNum);
		});

		let downloadCheckpoint;
		let _tmpDownloadCheckpoint;
		let partSize = parseInt(param.PartSize, 10);
		if (isNaN(partSize) || partSize < MIN_DOWNLOAD_PART_SIZE || partSize > MAX_DOWNLOAD_PART_SIZE) {
			partSize = DEFAULT_DOWNLOAD_PART_SIZE;
		}
		let partCount = objectSize % partSize === 0 ? Math.floor(objectSize / partSize) : Math.floor(objectSize / partSize) + 1;
		_log.runLog('debug', funcName, 'Total parts count ' + partCount);
		downloadCheckpoint = {bucketName: bucket, objectKey: key, downloadFile : downloadFile, partSize : partSize, partCount : partCount};
		downloadCheckpoint.versionId = param.VersionId;
		downloadCheckpoint.ifMatch = param.IfMatch;
		downloadCheckpoint.ifModifiedSince = param.IfModifiedSince;
		downloadCheckpoint.ifNoneMatch = param.IfNoneMatch;
		downloadCheckpoint.ifUnmodifiedSince = param.IfUnmodifiedSince;
		downloadCheckpoint.sseC = param.SseC;
		downloadCheckpoint.sseCKey = param.SseCKey;
		downloadCheckpoint.md5 = calculateDownloadCheckpointMD5(downloadCheckpoint);
		downloadCheckpoint.objectStatus = {objectSize : objectSize, lastModified : objestStat.InterfaceResult.LastModified, etag: objestStat.InterfaceResult.ETag};

		let tryContinueDownload_noChkFile = function() {
			fs.writeFile(checkpointFile, JSON.stringify(downloadCheckpoint), function(err){
				if(err){
					_log.runLog('error', funcName, `failed to write to checkpointFile: ${err.stack}`);
					_callback('WriteCheckpointFileError', `failed to write to checkpointFile: ${err.stack}`);
					return;
				}
				prepareDownloadTempFile(downloadTempFile, objectSize, (isPrepareSucceed, tmpFile) => {
					if(isPrepareSucceed){
						eventEmitter.emit('start to downloadFile', downloadCheckpoint);
					}
				}).catch((reason) => {
					_log.runLog('error', funcName, 'failed to download file: ' + key + ', reason: ' + reason);
				});
			});
		}

		let verifyDownloadTempFileStatus = function(tempFileStatusInChk){
			if(!tempFileStatusInChk || !tempFileStatusInChk.fileName || !tempFileStatusInChk.lastModified || !tempFileStatusInChk.fileSize){
				_log.runLog('warn',  'verifyTempFileStatus' , ' tempFileStatus infomation is not integrity.');
				return false;
			}

			if(!fs.existsSync(downloadTempFile)){
				_log.runLog('warn', 'verifyTempFileStatus',  downloadTempFile + ' does not exist.');
				return false;
			}

			let tempFileStat = fs.statSync(downloadTempFile);
			if( tempFileStatusInChk.fileName !== downloadTempFile
				|| tempFileStatusInChk.lastModified !== tempFileStat.mtime.toUTCString()
				|| tempFileStatusInChk.fileSize !==  tempFileStat.size){
				_log.runLog('warn',  'verifyTempFileStatus' , ' the tempFileStatus information in checkpointfile is not consistent.');
				return false;
			}

			return true;
		};

		let tryContinueDownload_hasChkFile = function() {
			fs.readFile(checkpointFile, function(err, data){
				_tmpDownloadCheckpoint = downloadCheckpoint;

				if(err){
					_log.runLog('error', funcName, `read checkpointFile occur error: ${err.stack}`);
					fs.unlinkSync(checkpointFile, function(){});
					_callback('ReadCheckpointFileError', `read checkpointFile occur error: ${err.stack}`);
				}
				else {
					try{
						downloadCheckpoint = JSON.parse(data);
					}catch(e){
						_log.runLog('error', funcName, 'pasre checkpointFile data occur exception : ' + e);
						fs.unlinkSync(checkpointFile, function(){});
						_callback('ParseCheckpointFileError', 'pasre checkpointFile data occur exception : ' + e);
					}
				}

				// verify : downloadTempFile  vs  checkpointfile
				if(!downloadCheckpoint || downloadCheckpoint.bucketName !== bucket || downloadCheckpoint.objectKey !== key || downloadCheckpoint.downloadFile !== downloadFile ||
						!downloadCheckpoint.objectStatus || downloadCheckpoint.objectStatus.objectSize !== objectSize || downloadCheckpoint.objectStatus.lastModified !== objestStat.InterfaceResult.LastModified || downloadCheckpoint.objectStatus.etag !== objestStat.InterfaceResult.ETag
						|| !verifyDownloadTempFileStatus(downloadCheckpoint.tempFileStatus) || downloadCheckpoint.md5 !== calculateDownloadCheckpointMD5(downloadCheckpoint)){
					// 校验不通过，不使用延续下载，需执行prepareDownloadTempFile()
					fs.unlinkSync(checkpointFile, function(){});
					_log.runLog('warn',  funcName , 'CheckpointFile is invalid!');

					downloadCheckpoint = _tmpDownloadCheckpoint;
					prepareDownloadTempFile(downloadTempFile, objectSize, (isPrepareSucceed, tmpFile) => {
						if(isPrepareSucceed){
							eventEmitter.emit('start to downloadFile', downloadCheckpoint);
						}
					}).catch((reason) => {
						_log.runLog('error', funcName, 'failed to download file: ' + key + ', reason: ' + reason);
					});
				}
				else {
					// 校验通过，使用断点延续下载，即不执行prepareDownloadTempFile()
					_log.runLog('debug',  funcName , 'CheckpointFile is valid!');
					eventEmitter.emit('start to downloadFile', downloadCheckpoint);
				}

			});
		}

		let tryContinueDownload = function() {
			if(!fs.existsSync(checkpointFile)){
				tryContinueDownload_noChkFile();
			}else{
				tryContinueDownload_hasChkFile();
			}
		}

		if(checkpointFile){
			// 启用l了断点续接下载
			tryContinueDownload();
		}else{
			// 没有启用断点续接下载
			prepareDownloadTempFile(downloadTempFile, objectSize, (isPrepareSucceed, tmpFile) => {
				if(isPrepareSucceed){
					eventEmitter.emit('start to downloadFile', downloadCheckpoint);
				}
			}).catch((reason) => {
				_log.runLog('error', funcName, 'failed to download file: ' + key + ', reason: ' + reason);
			});
		}
	});
};

function isFunction(obj){
	return Object.prototype.toString.call(obj) === '[object Function]';
}

function createPromise(current){
	return function(param, callback){
		if(isFunction(param)){
			current.call(this, null, param);
			return;
		}
		if(isFunction(callback)){
			current.call(this, param, callback);
			return;
		}

		let that = this;
		return new Promise(function(resolve, reject) {
			current.call(that, param, function(err, result){
				if(err){
					return reject(err);
				}
				resolve(result);
			});
		});
	};
}

if(isFunction(Promise)){
	for(let key in ObsClient.prototype){
		if ({}.hasOwnProperty.call(ObsClient.prototype, key)) {
			let current = ObsClient.prototype[key];
			ObsClient.prototype[key] = createPromise(current);
		}
	}
}

ObsClient.prototype.close = function(){
	if(this.util){
		this.util.close();
		delete this.util;
	}
};

ObsClient.prototype.refreshShadowClient = function () {
  if (this.util) {
    this.util.refreshShadowClient();
	}
};

ObsClient.prototype.exec = function(funcName, param, callback){
	let _log = this.log;
	if(_log.isLevelEnabled('info')){
		_log.runLog('info', funcName, 'enter ' + funcName + '...' );
	}
	let start = new Date().getTime();
	param = param || {};
	let _callback = function(err, msg){
		if(_callback.$called){
			return;
		}
		_callback.$called = true;
		if(_log.isLevelEnabled('info')){
			_log.runLog('info', funcName, 'ObsClient cost ' +  (new Date().getTime() - start) + ' ms');
		}

		if(err && !(err instanceof Error)){
			err = new Error(err);
		}
		callback(err, msg);
	};
	this.util.exec(funcName, param , _callback);
};

ObsClient.prototype.initLog = function(param){
	param = param || {};
	this.log.initLog(param.file_full_path, param.max_log_size, param.backups, param.level, param.log_to_console, param.name, param.logger);
	if(this.log.isLevelEnabled('warn')){
		let msg = ['[OBS SDK Version=' + this.util.obsSdkVersion];
		if(this.util.server){
			let port = this.util.port ? ':' + this.util.port : '';
			msg.push('Endpoint=' + (this.util.is_secure? 'https' : 'http') + '://' + this.util.server + port);
		}
		msg.push('Access Mode=' + (this.util.path_style ? 'Path' : 'Virtual Hosting') + ']');
		this.log.runLog('warn', 'init', msg.map(function(m) { return '[' + m + ']'; }).join(''));
	}
};

ObsClient.prototype.factory = function(param){
	this.log = new LogUtil();
	this.util = new Utils(this.log);
	param = param || {};
	this.util.initFactory(param.access_key_id, param.secret_access_key, param.is_secure,
			param.server, param.path_style, param.signature, param.region, param.port, param.max_retry_count,
			param.timeout, param.ssl_verify, param.long_conn_param, param.security_token, param.is_signature_negotiation, param.is_cname,
			param.max_connections, param.http_agent, param.https_agent, param.user_agent, param.third_http_lib, param.no_proxy_list,param.is_shadow_client, param.iam_domain, param.shadow_expires, param.verify_host_name);
};

ObsClient.prototype.refresh = function(access_key_id, secret_access_key, security_token,is_shadow_client){
	this.util.refresh(access_key_id, secret_access_key, security_token,is_shadow_client);
};

ObsClient.prototype.enums = enums;

ObsClient.prototype.createV2SignedUrlSync = function(param){
	return this.util.createV2SignedUrlSync(param);
};

ObsClient.prototype.createV4SignedUrlSync = function(param){
	return this.util.createV4SignedUrlSync(param);
};


ObsClient.prototype.createSignedUrlSync = function(param){
	return this.util.createSignedUrlSync(param);
};

ObsClient.prototype.createV4PostSignatureSync = function(param){
	return this.util.createV4PostSignatureSync(param);
};

ObsClient.prototype.createPostSignatureSync = function(param){
	return this.util.createPostSignatureSync(param);
};

for(let key in ObsClient.prototype){
	if ({}.hasOwnProperty.call(ObsClient.prototype, key)) {
		ObsClient.prototype[capitalize(key)] = ObsClient.prototype[key];
	}
}

for(let key in ObsClient.prototype){
	if ({}.hasOwnProperty.call(ObsClient.prototype, key)) {
		let index = key.indexOf('Configuration');
		if (index > 0 && index + 'Configuration'.length === key.length) {
			ObsClient.prototype[key.slice(0, index)] = ObsClient.prototype[key];
		}
	}
}

module.exports = ObsClient;



/***/ }),

/***/ 8567:
/***/ ((module) => {

/**
 * Copyright 2019 Huawei Technologies Co.,Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 */

const owner = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'Owner',
	'parameters' : {
		'ID' : {
			'sentAs' : 'ID',
		}
	}
};

const initiator = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'Initiator',
	'parameters' : {
		'ID' : {
			'sentAs' : 'ID',
		},
	},
};
const commonPrefixes = {
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'CommonPrefixes',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Prefix' : {
				'decode' : true,
				'sentAs' : 'Prefix',
			},
			'MTime': {
				'sentAs': 'MTime',
			},
			'InodeNo': {
				'sentAs': 'InodeNo',
			}
		}
	}
};

const grants = {
	'type' : 'array',
	'location' : 'xml',
	'wrapper' : 'AccessControlList',
	'sentAs' : 'Grant',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Grantee' : {
				'type' : 'object',
				'sentAs' : 'Grantee',
				'parameters' : {
					'Type' : {
						'type' : 'ignore',
					},
					'ID' : {
						'sentAs' : 'ID',
						'notAllowEmpty' : true,
					},
					'URI' : {
						'sentAs' :  'Canned',
						'type' : 'adapter',
						'notAllowEmpty' : true,
					}
				},
			},
			'Permission' : {
				'sentAs' : 'Permission',
			},
			'Delivered' :{
				'sentAs' : 'Delivered',
			}
		},
	},
};

const grantsV2 = {
	'type' : 'array',
	'location' : 'xml',
	'wrapper' : 'AccessControlList',
	'sentAs' : 'Grant',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Grantee' : {
				'data' : {
					'xsiNamespace' : 'http://www.w3.org/2001/XMLSchema-instance',
					'xsiType' : 'Type',
				},
				'type' : 'object',
				'sentAs' : 'Grantee',
				'parameters' : {
					'Type' : {
						'type' : 'ignore',
					},
					'ID' : {
						'sentAs' : 'ID',
						'notAllowEmpty' : true,
					},
					'Name' : {
						'sentAs' : 'DisplayName',
						'notAllowEmpty' : true,
					},
					'URI' : {
						'sentAs' :  'URI',
						'type' : 'adapter',
						'notAllowEmpty' : true,
					}
				},
			},
			'Permission' : {
				'sentAs' : 'Permission',
			},
		},
	},
};

const loggingEnabled = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'LoggingEnabled',
	'parameters' : {
		'TargetBucket' : {
			'sentAs' : 'TargetBucket',
		},
		'TargetPrefix' : {
			'sentAs' : 'TargetPrefix',
		},
		'TargetGrants' : {
			'type' : 'array',
			'wrapper' : 'TargetGrants',
			'sentAs' : 'Grant',
			'items' : {
				'type' : 'object',
				'parameters' : {
					'Grantee' : {
						'type' : 'object',
						'sentAs' : 'Grantee',
						'parameters' : {
							'Type' : {
								'type' : 'ignore',
							},
							'ID' : {
								'sentAs' : 'ID',
							},
							'URI' : {
								'sentAs' :  'Canned',
								'type' : 'adapter'
							}
						},
					},
					'Permission' : {
						'sentAs' : 'Permission',
					},
				},
			},
		},
	},
};

const rules = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'Rule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'ID' : {
				'sentAs' : 'ID',
			},
			'Prefix' : {
				'sentAs' : 'Prefix',
			},
			'Status' : {
				'sentAs' : 'Status',
			},
			'Transitions' : {
				'type' : 'array',
				'sentAs' : 'Transition',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'StorageClass' :{
							'sentAs' : 'StorageClass',
							'type' : 'adapter'
						},
						'Date' : {
							'sentAs' : 'Date',
						},
						'Days' : {
							'type' : 'number',
							'sentAs' : 'Days'
						}
					}
				}
			},
			'Expiration' : {
				'type' : 'object',
				'sentAs' : 'Expiration',
				'parameters' : {
					'Date' : {
						'sentAs' : 'Date',
					},
					'Days' : {
						'type' : 'number',
						'sentAs' : 'Days'
					},
				},
			},
			'NoncurrentVersionTransitions' :{
				'type' : 'array',
				'sentAs' : 'NoncurrentVersionTransition',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'StorageClass' :{
							'sentAs' : 'StorageClass',
							'type' : 'adapter'
						},
						'NoncurrentDays' : {
							'type' : 'number',
							'sentAs' : 'NoncurrentDays'
						}
					}
				}
			},
			'NoncurrentVersionExpiration' : {
				'type' : 'object',
				'sentAs' : 'NoncurrentVersionExpiration',
				'parameters' : {
					'NoncurrentDays' : {
						'type' : 'number',
						'sentAs' : 'NoncurrentDays',
					},
				},
			}
		},
	},
};

const redirectAllRequestsTo = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'RedirectAllRequestsTo',
	'parameters' : {
		'HostName' : {
			'sentAs' : 'HostName',
		},
		'Protocol' : {
			'sentAs' : 'Protocol',
		},
	}
};

const routingRules = {
	'type' : 'array',
	'wrapper' : 'RoutingRules',
	'location' : 'xml',
	'sentAs' : 'RoutingRule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Condition' : {
				'type' : 'object',
				'sentAs' : 'Condition',
				'parameters' : {
					'HttpErrorCodeReturnedEquals' : {
						'sentAs' : 'HttpErrorCodeReturnedEquals',
					},
					'KeyPrefixEquals' : {
						'sentAs' : 'KeyPrefixEquals',
					},
				},
			},
			'Redirect' : {
				'type' : 'object',
				'sentAs' : 'Redirect',
				'parameters' : {
					'HostName' : {
						'sentAs' : 'HostName',
					},
					'HttpRedirectCode' : {
						'sentAs' : 'HttpRedirectCode',
					},
					'Protocol' : {
						'sentAs' : 'Protocol',
					},
					'ReplaceKeyPrefixWith' : {
						'sentAs' : 'ReplaceKeyPrefixWith',
					},
					'ReplaceKeyWith' : {
						'sentAs' : 'ReplaceKeyWith',
					}
				}
			},
		},
	},
};

const indexDocument = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'IndexDocument',
	'parameters' : {
		'Suffix' : {
			'sentAs' : 'Suffix',
		},
	}
};

const errorDocument = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'ErrorDocument',
	'parameters' : {
		'Key' : {
			'sentAs' : 'Key',
		},
	}
};

const corsRule = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'CORSRule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'ID' : {
				'sentAs' : 'ID',
			},
			'AllowedMethod' : {
				'type' : 'array',
				'sentAs' : 'AllowedMethod',
				'items' : {
					'type' : 'string',
				},
			},
			'AllowedOrigin' : {
				'type' : 'array',
				'sentAs' : 'AllowedOrigin',
				'items' : {
					'type' : 'string',
				},
			},
			'AllowedHeader' : {
				'type' : 'array',
				'sentAs' : 'AllowedHeader',
				'items' : {
					'type' : 'string',
				},
			},
			'MaxAgeSeconds' : {
				'type' : 'number',
				'sentAs' : 'MaxAgeSeconds',
			},
			'ExposeHeader' : {
				'type' : 'array',
				'sentAs' : 'ExposeHeader',
				'items' : {
					'type' : 'string',
				},
			},
		},
	},
};

const functionGraphConfiguration = {
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'FunctionGraphConfiguration',
	'items' : {
		'type' : 'object',
		'location' : 'xml',
		'parameters' : {
			'ID' : {
				'sentAs' : 'Id'
			},
			'Filter' : {
				'type' : 'object',
				'parameters' : {
					'FilterRules' : {
						'wrapper' : 'Object',
						'type' : 'array',
						'sentAs' : 'FilterRule',
						'items' : {
							'type' : 'object',
							'parameters' : {
								'Name' : {},
								'Value' : {}
							}
						}
					}
				}
			},
			'FunctionGraph' : {},

			'Event' : {
				'type' : 'array',
				'items' : {
					'type' : 'adapter',
				}
			}
		}
	}
};

const topicConfiguration = {
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'TopicConfiguration',
	'items' : {
		'type' : 'object',
		'location' : 'xml',
		'parameters' : {
			'ID' : {
				'sentAs' : 'Id'
			},
			'Filter' : {
				'type' : 'object',
				'parameters' : {
					'FilterRules' : {
						'wrapper' : 'Object',
						'type' : 'array',
						'sentAs' : 'FilterRule',
						'items' : {
							'type' : 'object',
							'parameters' : {
								'Name' : {},
								'Value' : {}
							}
						}
					}
				}
			},
			'Topic' : {},

			'Event' : {
				'type' : 'array',
				'items' : {
					'type' : 'adapter',
				}
			}
		}
	}
};

const tagSet = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'wrapper' : 'TagSet',
	'sentAs' : 'Tag',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Key' : {
				'sentAs' : 'Key',
			},
			'Value' : {
				'sentAs' : 'Value',
			}
		}
	}
};

const replicationRules = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'Rule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'ID' : {
				'sentAs' : 'ID',
			},
			'Prefix' : {
				'sentAs' : 'Prefix',
			},
			'Status' : {
				'sentAs' : 'Status',
			},
			'Destination' :{
				'type' : 'object',
				'sentAs' : 'Destination',
				'parameters' :{
					'Bucket' : {
						'sentAs' : 'Bucket',
						'type' : 'adapter'
					},
					'StorageClass' :{
						'sentAs' : 'StorageClass',
						'type' : 'adapter'
					}
				}
			}
		},
	}
};

const bucketEncryptionRule = {
	'type': 'object',
	'location': 'xml',
	'sentAs': 'Rule',
	'parameters': {
		'ApplyServerSideEncryptionByDefault': {
			'type': 'object',
			'sentAs': 'ApplyServerSideEncryptionByDefault',
			'parameters': {
				'SSEAlgorithm': {
					'sentAs': 'SSEAlgorithm'
				},
				'KMSMasterKeyID': {
					'sentAs': 'KMSMasterKeyID'
				}
			}
		}
	}
};

const PublicAccessBlockBody = {
    'BlockPublicAcls' : {
        'location' : 'xml',
        'sentAs' : 'BlockPublicAcls',
    },
    'IgnorePublicAcls' : {
        'location' : 'xml',
        'sentAs' : 'IgnorePublicAcls',
    },
    'BlockPublicPolicy' : {
        'location' : 'xml',
        'sentAs' : 'BlockPublicPolicy',
    },
    'RestrictPublicBuckets' : {
        'location' : 'xml',
        'sentAs' : 'RestrictPublicBuckets',
    }
};

const CustomDomainCertificateConfig = {
	'type': 'object',
	'location': 'xml',
	'required': false,
	'sentAs': 'CustomDomainConfiguration',
	'parameters': {
		'Name': {
			'type': 'string',
			'required': true
		},
		'CertificateId': {
			'type':'string',
		},
		'Certificate': {
			'type': 'string',
			'required': true,
		},
		'CertificateChain': {
			'type': 'string',
		},
		'PrivateKey': {
			'type': 'string',
			'required': true,
		}

	}
}

const inventoryConfiguration = {
	'Id' : {
		'location' : 'xml',
		'sentAs' : 'Id'
	},
	'IsEnabled' : {
		'location' : 'xml',
		'sentAs' : 'IsEnabled'
	},
	'Filter' : {
		'type' : 'object',
		'location' : 'xml',
		'sentAs' : 'Filter',
		'parameters' : {
			'Prefix' : {
				'sentAs' : 'Prefix'
			}
		}
	},
	'Destination' : {
		'type' : 'object',
		'location' : 'xml',
		'sentAs' : 'Destination',
		'parameters' : {
			'Format' : {
				'sentAs' : 'Format'
			},
			'Bucket' : {
				'sentAs' : 'Bucket',
				'type' : 'adapter'
			},
			'Prefix' : {
				'sentAs' : 'Prefix'
			}
		}
	},
	'Schedule' : {
		'type' : 'object',
		'location' : 'xml',
		'sentAs' : 'Schedule',
		'parameters' : {
			'Frequency' : {
				'sentAs' : 'Frequency'
			}
		}
	},
	'IncludedObjectVersions' : {
		'location' : 'xml',
		'sentAs' : 'IncludedObjectVersions'
	},
	'OptionalFields' : {
		'type' : 'object',
		'location' : 'xml',
		'sentAs' : 'OptionalFields',
		'parameters' : {
			'Field' : {
				'type' : 'array',
				'sentAs' : 'Field',
				'items' : {
					'type' : 'string'
				}
			}
		}
	}
}

const operations = {
	'CreateBucket' : {
		'httpMethod' : 'PUT',
		'data' : {
			'xmlRoot' : 'CreateBucketConfiguration',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'Location' : {
				'location' : 'xml',
				'sentAs' : 'Location'
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},

			'GrantWrite' : {
				'location' : 'header',
				'sentAs' : 'grant-write',
				'withPrefix' : true,
			},

			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},

			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},

			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},

			'GrantReadDelivered' : {
				'location' : 'header',
				'sentAs' : 'grant-read-delivered',
				'withPrefix' : true,
			},

			'GrantFullControlDelivered' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control-delivered',
				'withPrefix' : true,
			},

			'AzRedundancy': {
				'location': 'header',
				'sentAs': 'x-obs-az-redundancy'
			},
			'MultiEnterprise': {
				'location': 'header',
				'sentAs': 'epid',
				'withPrefix': true
			},
			'FileInterface':{
				'location' : 'header',
				'sentAs' : 'fs-file-interface',
				'withPrefix': true
			},
		}
	},

    'ListBuckets' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'BucketType': {
				'location': 'header',
				'sentAs': 'bucket-type',
				'withPrefix': true
			},
			'Marker' : {
				'location' : 'urlPath',
				'sentAs' : 'marker',
			},
			'MaxKeys' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-keys',
			},
		}
	},

	'ListBucketsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListAllMyBucketsResult',
		},
		'parameters' : {
			'Owner' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Owner',
				'parameters' : {
					'ID' : {
						'sentAs' : 'ID',
					},
					'Name' : {
						'sentAs' : 'DisplayName',
					},
				},
			},
			'Marker' : {
				'location' : 'xml',
				'sentAs' : 'Marker',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'NextMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextMarker',
			},
			'MaxKeys' : {
				'location' : 'xml',
				'sentAs' : 'MaxKeys',
			},
			'Buckets' : {
				'type' : 'array',
				'location' : 'xml',
				'wrapper' : 'Buckets',
				'sentAs' : 'Bucket',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'BucketName' : {
							'sentAs' : 'Name',
						},
						'CreationDate' : {
							'sentAs' : 'CreationDate'
						},
						'Location' : {
							'sentAs' : 'Location'
						},
						'BucketType' : {
							'sentAs' : 'BucketType'
						}
					},
				},
			},
		},
	},

	'HeadBucket' : {
		'httpMethod' : 'HEAD',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'HeadApiVersion' : {
		'httpMethod' : 'HEAD',
		'urlPath' : 'apiversion',
		'parameters' : {
			'Bucket' : {
				'location' : 'uri',
			},
		},
	},

	'HeadApiVersionOutput' : {
		'parameters' : {
			'ApiVersion' : {
				'location' : 'header',
				'sentAs' : 'x-obs-api'
			},
		}
	},


	'GetBucketMetadata' : {
		'httpMethod' : 'HEAD',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},

			'Origin' : {
				'location' : 'header',
				'sentAs' : 'Origin'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'RequestHeader' : {
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers'
			}
		},
	},

	'GetBucketMetadataOutput' : {
		'parameters' : {
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true
			},
			'StorageClassObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
			},
			'StorageClassV2' : {
				'location' : 'header',
				'sentAs' : 'x-default-storage-class',
			},
			'ObsVersion' : {
				'location' : 'header',
				'sentAs' : 'version',
				'withPrefix' : true
			},
			'ObsVersionObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version',
			},
			'ObsVersionV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version',
			},
			'FsInterface': {
				'location': 'header',
				'sentAs': 'fs-file-interface',
				'withPrefix': true
			},
			'FsInterfaceObs': {
				'location': 'header',
				'sentAs': 'x-obs-fs-file-interface',
			},
			'FsInterfaceV2': {
				'location': 'header',
				'sentAs': 'x-amz-fs-file-interface',
			},
			'Location' : {
				'location' : 'header',
				'sentAs' : 'bucket-location',
				'withPrefix' : true
			},
			'LocationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-bucket-location',
			},
			'LocationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-bucket-region',
			},
			'AzRedundancy': {
				'location': 'header',
				'sentAs': 'x-obs-az-redundancy'
			},
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin'
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age'
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers'
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods'
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers'
			},
			'MultiEnterprise': {
				'location': 'header',
				'sentAs': 'epid',
				'withPrefix' : true
			},
			'MultiEnterpriseObs': {
				'location': 'header',
				'sentAs': 'x-obs-epid',
			},
			'MultiEnterpriseV2': {
				'location': 'header',
				'sentAs': 'x-amz-epid',
			},
			'ErrorCode': {
				'location': 'header',
				'sentAs': 'x-obs-error-code'
			},
			'ErrorMessage': {
				'location': 'header',
				'sentAs': 'x-obs-error-message'
			}
		}
	},

	'DeleteBucket' : {
		'httpMethod' : 'DELETE',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'ListObjects' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Prefix' : {
				'location' : 'urlPath',
				'sentAs' : 'prefix',
			},
			'Marker' : {
				'location' : 'urlPath',
				'sentAs' : 'marker',
			},
			'MaxKeys' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-keys',
			},
			'Delimiter' : {
				'location' : 'urlPath',
				'sentAs' : 'delimiter',
			},
			'AccessKeyId': {
				'location': 'urlPath',
				'sentAs': 'AccessKeyId'
			},
			'Signature': {
				'location': 'urlPath',
				'sentAs': 'Signature'
			},
			'Policy': {
				'location': 'urlPath',
				'sentAs': 'Policy'
			},
			'SecurityToken': {
				'location': 'urlPath',
				'sentAs': 'x-obs-security-token'
			},
			'FsClient': {
				'location': 'header',
				'sentAs': 'x-hws-fs-client'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type'
			}
		},
	},

	'ListObjectsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListBucketResult',
		},
		'parameters' : {
			'Location' : {
				'location' : 'header',
				'sentAs' : 'bucket-location',
				'withPrefix' : true
			},
			'LocationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-bucket-location',
			},
			'LocationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-bucket-region',
			},
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Name',
			},
			'Delimiter' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Delimiter',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'Prefix' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Prefix',
			},
			'Marker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Marker',
			},
			'NextMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'NextMarker',
			},
			'MaxKeys' : {
				'location' : 'xml',
				'sentAs' : 'MaxKeys',
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
			'Contents' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Contents',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
						'Size' : {
							'sentAs' : 'Size',
						},
						'Type' :{
							'sentAs' : 'Type'
						},
						'StorageClass' : {
							'sentAs' : 'StorageClass',
						},
						'Owner' : owner
					},
				},

			},
			'CommonPrefixes' : commonPrefixes
		},
	},

	'ListVersions' : {
		'httpMethod' : 'GET',
		'urlPath' : 'versions',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Prefix' : {
				'location' : 'urlPath',
				'sentAs' : 'prefix',
			},
			'KeyMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'key-marker',
			},
			'MaxKeys' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-keys',
			},
			'Delimiter' : {
				'location' : 'urlPath',
				'sentAs' : 'delimiter',
			},
			'VersionIdMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'version-id-marker',
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
		},
	},
	'ListVersionsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListVersionsResult',
		},
		'parameters' : {
			'Location' : {
				'location' : 'header',
				'sentAs' : 'bucket-location',
				'withPrefix' : true
			},
			'LocationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-bucket-location',
			},
			'LocationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-bucket-region',
			},
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Name',
			},
			'Prefix' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Prefix',
			},
			'Delimiter' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Delimiter',
			},
			'KeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'KeyMarker',
			},
			'VersionIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'VersionIdMarker',
			},
			'NextKeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'NextKeyMarker',
			},
			'NextVersionIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextVersionIdMarker',
			},
			'MaxKeys' : {
				'location' : 'xml',
				'sentAs' : 'MaxKeys',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'Versions' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Version',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'IsLatest' : {
							'sentAs' : 'IsLatest',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
						'Size' : {
							'sentAs' : 'Size',
						},
						'Type' :{
							'sentAs' : 'Type'
						},
						'Owner' : owner,
						'StorageClass' : {
							'sentAs' : 'StorageClass',
						}
					}
				},
			},
			'DeleteMarkers' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'DeleteMarker',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'IsLatest' : {
							'sentAs' : 'IsLatest',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'Owner' : owner
					}
				},
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
			'CommonPrefixes' : commonPrefixes
		},
	},

	'GetBucketLocation' : {
		'httpMethod' : 'GET',
		'urlPath' : 'location',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'GetBucketLocationOutput' : {
		'data' : {
			'type' : 'xml'
		},
		'parameters' : {
			'Location' : {
				'location' : 'xml',
				'sentAs' : 'Location'
			},
		},
	},

	'GetBucketStorageInfo' : {
		'httpMethod' : 'GET',
		'urlPath' : 'storageinfo',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketStorageInfoOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'GetBucketStorageInfoResult',
		},
		'parameters' : {
			'Size' : {
				'location' : 'xml',
				'sentAs' : 'Size',
			},
			'ObjectNumber' : {
				'location' : 'xml',
				'sentAs' : 'ObjectNumber',
			},
		},
	},

	'SetBucketQuota' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'quota',
		'data' : {
			'xmlRoot' : 'Quota',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'StorageQuota' : {
				'required' : true,
				'location' : 'xml',
				'sentAs' : 'StorageQuota',
			},
		},
	},

	'GetBucketQuota' : {
		'httpMethod' : 'GET',
		'urlPath' : 'quota',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},

		},
	},
	'GetBucketQuotaOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'Quota',
		},
		'parameters' : {
			'StorageQuota' : {
				'location' : 'xml',
				'sentAs' : 'StorageQuota',
			},
		},
	},

	'SetBucketAcl' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'acl',
		'data' : {
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'Owner' : owner,
			'Grants' : grants
		},
	},

	'GetBucketAcl' : {
		'httpMethod' : 'GET',
		'urlPath' : 'acl',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketAclOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'Owner' : owner,
			'Grants' : grants,
			'GrantsV2': grantsV2,
		}
	},

	'SetBucketLoggingConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'logging',
		'data' : {
			'xmlRoot' : 'BucketLoggingStatus',
			'xmlAllowEmpty' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Agency' :{
				'location' : 'xml',
				'sentAs' : 'Agency',
			},
			'LoggingEnabled' : loggingEnabled,
		},
	},

	'GetBucketLoggingConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'logging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketLoggingConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'BucketLoggingStatus',
		},
		'parameters' : {
			'Agency' :{
				'location' : 'xml',
				'sentAs' : 'Agency'
			},
			'LoggingEnabled' : loggingEnabled,
		},
	},

	'SetBucketPolicy' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'policy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Policy' : {
				'required' : true,
				'location' : 'body',
			},
		},
	},

	'GetBucketPolicy' : {
		'httpMethod' : 'GET',
		'urlPath' : 'policy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketPolicyOutput' : {
		'data' : {
			'type' : 'body',
		},
		'parameters' : {
			'Policy' : {
				'location' : 'body',
			},
		},
	},
	'DeleteBucketPolicy' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'policy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'SetBucketLifecycleConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'lifecycle',
		'data' : {
			'xmlRoot' : 'LifecycleConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Rules' : rules
		},
	},

	'GetBucketLifecycleConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'lifecycle',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketLifecycleConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'LifecycleConfiguration',
		},
		'parameters' : {
			'Rules' : rules
		},
	},

	'DeleteBucketLifecycleConfiguration' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'lifecycle',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'SetBucketWebsiteConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'website',
		'data' : {
			'xmlRoot' : 'WebsiteConfiguration',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RedirectAllRequestsTo' : redirectAllRequestsTo,
			'IndexDocument' : indexDocument,
			'ErrorDocument' : errorDocument,
			'RoutingRules' : routingRules
		},
	},

	'GetBucketWebsiteConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'website',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketWebsiteConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'WebsiteConfiguration',
		},
		'parameters' : {
			'RedirectAllRequestsTo' : redirectAllRequestsTo,
			'IndexDocument' : indexDocument,
			'ErrorDocument' : errorDocument,
			'RoutingRules' : routingRules,
		},
	},
	'DeleteBucketWebsiteConfiguration' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'website',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'SetBucketVersioningConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'versioning',
		'data' : {
			'xmlRoot' : 'VersioningConfiguration',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionStatus' : {
				'required' : true,
				'location' : 'xml',
				'sentAs' : 'Status',
			},
		},
	},

	'GetBucketVersioningConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'versioning',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketVersioningConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'VersioningConfiguration',
		},
		'parameters' : {
			'VersionStatus' : {
				'location' : 'xml',
				'sentAs' : 'Status',
			},
		},
	},

	'SetBucketCors' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'cors',
		'data' : {
			'xmlRoot' : 'CORSConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'CorsRules' : corsRule
		},
	},
	'GetBucketCors' : {
		'httpMethod' : 'GET',
		'urlPath' : 'cors',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},
	'GetBucketCorsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CORSConfiguration',
		},
		'parameters' : {
			'CorsRules' : corsRule
		},
	},
	'DeleteBucketCors' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'cors',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'SetBucketNotification' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'notification',
		'data' : {
			'xmlRoot' : 'NotificationConfiguration',
			'xmlAllowEmpty' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'TopicConfigurations' : topicConfiguration,
			'FunctionGraphConfigurations' : functionGraphConfiguration,
		}
	},


	'GetBucketNotification' : {
		'httpMethod' : 'GET',
		'urlPath' : 'notification',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		}
	},

	'GetBucketNotificationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'NotificationConfiguration',
		},
		'parameters' : {
			'TopicConfigurations' : topicConfiguration,
			'FunctionGraphConfigurations' : functionGraphConfiguration,
		},
	},

	'OptionsBucket' : {
		'httpMethod' : 'OPTIONS',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Origin' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'Origin',
			},
			'AccessControlRequestMethods' : {
				'required' : true,
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Method',
				'items' : {
					'type' : 'string',
				},
			},
			'AccessControlRequestHeaders' : {
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers',
				'items' : {
					'type' : 'string',
				},
			},
		},
	},
	'OptionsBucketOutput' : {
		'parameters' : {
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin',
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers',
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods',
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers',
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age',
			},
		},
	},

	'SetBucketTagging' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'tagging',
		'data' : {
			'xmlRoot' : 'Tagging',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Tags' : tagSet
		}
	},

	'GetBucketTagging' : {
		'httpMethod' : 'GET',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		}
	},

	'GetBucketTaggingOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'Tagging',
		},
		'parameters' : {
			'Tags' : tagSet
		}
	},

	'DeleteBucketTagging' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		}
	},

	'SetBucketStoragePolicy' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'storageClass',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'StorageClass' :{
				'required' : true,
				'location' : 'xml',
				'type' : 'adapter',
				'sentAs' : 'StorageClass'
			}
		}
	},

	'GetBucketStoragePolicy' :{
		'httpMethod' : 'GET',
		'urlPath' : 'storageClass',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		}
	},

	'GetBucketStoragePolicyOutput' :{
		'data' : {
			'type' : 'xml',
		},
		'parameters' : {
			'StorageClass' : {
				'location' : 'xml',
				'type' : 'string',
				'sentAs' : 'StorageClass'
			}
		}
	},

	'SetBucketReplication' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'replication',
		'data' : {
			'xmlRoot' : 'ReplicationConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Agency' :{
				'location' : 'xml',
				'sentAs' : 'Agency'
			},
			'Rules' : replicationRules
		}
	},

	'GetBucketReplication' : {
		'httpMethod' : 'GET',
		'urlPath' : 'replication',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		}
	},

	'GetBucketReplicationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ReplicationConfiguration',
		},
		'parameters' : {
			'Agency' :{
				'location' : 'xml',
				'sentAs' : 'Agency'
			},
			'Rules' : replicationRules
		}
	},

	'DeleteBucketReplication' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'replication',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		}
	},

	'GetBucketRequesterPayment': {
		'httpMethod': 'GET',
		'urlPath': 'requestPayment',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			}
		}
	},
	'GetBucketRequesterPaymentOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'RequestPaymentConfiguration'
		},
		'parameters' : {
			'Payer' : {
				'location': 'xml',
				'sentAs': 'Payer',
			}
		}
	},
	'SetBucketRequesterPayment': {
		'httpMethod' : 'PUT',
		'urlPath': 'requestPayment',
		'data' : {
			'xmlRoot' : 'RequestPaymentConfiguration'
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Payer' : {
				'location': 'xml',
				'sentAs': 'Payer'
			}
		}
	},
	'SetBucketRequesterPaymentOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'RequestPaymentConfiguration'
		},
		'parameters' : {
			'Payer' : {
				'location': 'xml',
				'sentAs': 'Payer',
			}
		}
	},

	'PutObject' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'ContentSHA256' : {
				'location' : 'header',
				'sentAs' : 'content-sha256',
				'withPrefix' : true,
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'Offset' : {
				'type' : 'plain'
			},

			'ProgressCallback' :{
				'type' : 'plain'
			},

			'ContentLength' :{
				'location' : 'header',
				'sentAs' : 'Content-Length',
				'type' : 'plain'
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true,
			},
			'CacheControl': {
				'location': 'header',
				'sentAs': 'Cache-Control'
			},
			'ContentDisposition': {
				'location': 'header',
				'sentAs': 'Content-Disposition',
				'encodingSafe': ' ;/?:@&=+$,"'
			},
			'ContentLanguage': {
				'location': 'header',
				'sentAs': 'Content-Language'
			},
			'ContentEncoding': {
				'location': 'header',
				'sentAs': 'Content-Encoding'
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true,
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'expires',
				'type' : 'number',
				'withPrefix' : true,
			},
			'SuccessActionRedirect':{
				'location' : 'header',
				'sentAs' : 'success-action-redirect'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'PutObjectOutput' : {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true,
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'StorageClass' :{
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
			},
			'StorageClassObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
			},
			'StorageClassV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-storage-class',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption',
			},
			'SseKmsV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption',
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseKmsKeyObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-kms-key-id',
			},
			'SseKmsKeyV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-kms-key-id',
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-algorithm',
			},
			'SseCV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-algorithm',
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true,
			},
			'SseCKeyMd5Obs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-key-MD5',
			},
			'SseCKeyMd5V2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-key-MD5',
			}
		},
	},

	'RenameObject': {
		'httpMethod': 'POST',
		'urlPath': 'rename',
		'parameters': {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Name': {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'name',
			}
		}
	},

	'ModifyObject': {
		'httpMethod': 'PUT',
		'urlPath': 'modify',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Position' : {
				'location' : 'urlPath',
				'sentAs' : 'position',
				'type' : 'number'
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'Offset' : {
				'type' : 'plain'
			},

			'ProgressCallback' :{
				'type' : 'plain'
			},

			'ContentLength' :{
				'location' : 'header',
				'sentAs' : 'Content-Length',
				'type' : 'plain'
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true,
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'expires',
				'type' : 'number',
				'withPrefix' : true,
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'ModifyObjectOutput': {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true,
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'StorageClass' :{
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
			},
			'StorageClassObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
			},
			'StorageClassV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-storage-class',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption',
			},
			'SseKmsV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption',
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseKmsKeyObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-kms-key-id',
			},
			'SseKmsKeyV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-kms-key-id',
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-algorithm',
			},
			'SseCV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-algorithm',
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true,
			},
			'SseCKeyMd5Obs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-key-MD5',
			},
			'SseCKeyMd5V2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-key-MD5',
			}
		},
	},

	'AppendObject' : {
		'httpMethod' : 'POST',
		'urlPath' : 'append',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Position' : {
				'location' : 'urlPath',
				'sentAs' : 'position',
				'type' : 'number'
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'Offset' : {
				'type' : 'plain'
			},

			'ProgressCallback' :{
				'type' : 'plain'
			},

			'ContentLength' :{
				'location' : 'header',
				'sentAs' : 'Content-Length',
				'type' : 'plain'
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true,
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true,
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'expires',
				'type' : 'number',
				'withPrefix' : true,
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'AppendObjectOutput' : {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'NextPosition' : {
				'location' : 'header',
				'sentAs' : 'next-append-position',
				'withPrefix' : true,
			},
			'NextPositionObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-next-append-position',
			},
			'NextPositionV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-next-append-position',
			},
			'StorageClass' :{
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
			},
			'StorageClassObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
				'type' : 'adapter',
			},
			'StorageClassV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-storage-class',
				'type' : 'adapter',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseKmsKeyObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-kms-key-id',
			},
			'SseKmsKeyV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-kms-key-id',
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-algorithm',
			},
			'SseCV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-algorithm',
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true,
			},
			'SseCKeyMd5Obs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-key-MD5',
			},
			'SseCKeyMd5V2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-key-MD5',
			}
		},
	},

	'GetObject' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'AccessKeyId': {
				'location': 'urlPath',
			},
			'Signature': {
				'location': 'urlPath'
			},
			'Policy': {
				'location': 'urlPath'
			},
			'SecurityToken': {
				'location': 'urlPath',
				'sentAs': 'x-obs-security-token'
			},
			'ResponseCacheControl' : {
				'location' : 'urlPath',
				'sentAs' : 'response-cache-control',
			},
			'ResponseContentDisposition' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-disposition',
			},
			'ResponseContentEncoding' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-encoding',
			},
			'ResponseContentLanguage' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-language',
			},
			'ResponseContentType' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-type',
			},
			'ResponseExpires' : {
				'location' : 'urlPath',
				'sentAs' : 'response-expires',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'ImageProcess' : {
				'location' : 'urlPath',
				'sentAs' : 'x-image-process',
			},
			'IfMatch' : {
				'location' : 'header',
				'sentAs' : 'If-Match',
			},
			'IfModifiedSince' : {
				'location' : 'header',
				'sentAs' : 'If-Modified-Since',
			},
			'IfNoneMatch' : {
				'location' : 'header',
				'sentAs' : 'If-None-Match',
			},
			'IfUnmodifiedSince' : {
				'location' : 'header',
				'sentAs' : 'If-Unmodified-Since',
			},
			'Range' : {
				'location' : 'header',
				'sentAs' : 'Range',
			},
			'Origin' :{
				'location' : 'header',
				'sentAs' : 'Origin'
			},
			'RequestHeader' : {
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers'
			},
			'SaveAsFile' : {
				'type' : 'dstFile',
			},
			'SaveAsStream' : {
				'type' : 'plain'
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'ProgressCallback' :{
				'type' : 'plain'
			}
		}
	},
	'GetObjectOutput' : {
		'data' : {
			'type' : 'body'
		},
		'parameters' : {
			'Content' : {
				'location' : 'body',
			},
			'Expiration' : {
				'location' : 'header',
				'sentAs' : 'expiration',
				'withPrefix' : true
			},
			'ExpirationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-expiration',
			},
			'ExpirationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-expiration',
			},
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'CacheControl' : {
				'location' : 'header',
				'sentAs' : 'Cache-Control',
			},
			'ContentDisposition' : {
				'location' : 'header',
				'sentAs' : 'Content-Disposition',
			},
			'ContentEncoding' : {
				'location' : 'header',
				'sentAs' : 'Content-Encoding',
			},
			'ContentLanguage' : {
				'location' : 'header',
				'sentAs' : 'Content-Language',
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type',
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'Expires',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'ContentLength' : {
				'location' : 'header',
				'sentAs' : 'Content-Length',
			},
			'DeleteMarker' : {
				'location' : 'header',
				'sentAs' : 'delete-marker',
				'withPrefix' : true
			},
			'DeleteMarkerObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-delete-marker',
			},
			'DeleteMarkerV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-delete-marker',
			},
			'LastModified' : {
				'location' : 'header',
				'sentAs' : 'Last-Modified',
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true
			},
			'WebsiteRedirectLocationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-website-redirect-location',
			},
			'WebsiteRedirectLocationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-website-redirect-location',
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true
			},
			'StorageClassObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
			},
			'StorageClassV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-storage-class',
			},
			'Restore' : {
				'location' : 'header',
				'sentAs' : 'restore',
				'withPrefix' : true
			},
			'RestoreObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-restore',
			},
			'RestoreV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-restore',
			},
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin'
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age'
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers'
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods'
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseKmsKeyObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-kms-key-id',
			},
			'SseKmsKeyV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-kms-key-id',
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-algorithm',
			},
			'SseCV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-algorithm',
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'SseCKeyMd5Obs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-key-MD5',
			},
			'SseCKeyMd5V2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-key-MD5',
			},
			'Metadata' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'meta-',
				'withPrefix' : true
			},
			'MetadataObs' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'x-obs-meta-',
			},
			'MetadataV2' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'x-amz-meta-',
			}
		},
	},
	'CopyObject' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'CopySource' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'copy-source',
				'withPrefix' : true,
				'skipEncoding' : true
			},
			'CopySourceIfMatch' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-match',
				'withPrefix' : true
			},
			'CopySourceIfModifiedSince' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-modified-since',
				'withPrefix' : true
			},
			'CopySourceIfNoneMatch' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-none-match',
				'withPrefix' : true
			},
			'CopySourceIfUnmodifiedSince' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-unmodified-since',
				'withPrefix' : true
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'ContentEncoding' : {
				'location' : 'header',
				'sentAs' : 'content-encoding'
			},
			'ContentLanguage' : {
				'location' : 'header',
				'sentAs' : 'content-language'
			},
			'ContentDisposition' : {
				'location' : 'header',
				'sentAs' : 'content-disposition'
			},
			'CacheControl' : {
				'location' : 'header',
				'sentAs' : 'cache-control'
			},
			'TagDirective' : {
				'location' : 'header',
				'sentAs' : 'tagging-directive',
				'withPrefix' : true,
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'expires'
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true
			},
			'MetadataDirective' : {
				'location' : 'header',
				'sentAs' : 'metadata-directive',
				'withPrefix' : true
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true
			},
			'SuccessActionRedirect':{
				'location' : 'header',
				'sentAs' : 'success-action-redirect'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'CopySourceSseC' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'CopySourceSseCKey' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'CopyObjectOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CopyObjectResult',
		},
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'CopySourceVersionId' : {
				'location' : 'header',
				'sentAs' : 'copy-source-version-id',
				'withPrefix' : true
			},
			'CopySourceVersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-copy-source-version-id',
			},
			'CopySourceVersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-copy-source-version-id',
			},
			'ETag' : {
				'location' : 'xml',
				'sentAs' : 'ETag',
			},
			'LastModified' : {
				'location' : 'xml',
				'sentAs' : 'LastModified',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseKmsKeyObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-kms-key-id',
			},
			'SseKmsKeyV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-kms-key-id',
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-algorithm',
			},
			'SseCV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-algorithm',
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'SseCKeyMd5Obs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-key-MD5',
			},
			'SseCKeyMd5V2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-key-MD5',
			}
		},
	},

	'RestoreObject' : {
		'httpMethod' : 'POST',
		'urlPath' : 'restore',
		'data' : {
			'xmlRoot' : 'RestoreRequest',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'Days' : {
				'location' : 'xml',
				'sentAs' : 'Days'
			},
			'Tier' : {
				'wrapper' : 'RestoreJob',
				'location' : 'xml',
				'sentAs' : 'Tier',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetObjectMetadata' : {
		'httpMethod' : 'HEAD',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'Origin' : {
				'location' : 'header',
				'sentAs' : 'Origin'
			},
			'RequestHeader' : {
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers'
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetObjectMetadataOutput' : {
		'parameters' : {
			'Expiration' : {
				'location' : 'header',
				'sentAs' : 'expiration',
				'withPrefix' : true
			},
			'ExpirationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-expiration',
			},
			'ExpirationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-expiration',
			},
			'LastModified' : {
				'location' : 'header',
				'sentAs' : 'Last-Modified',
			},
			'ContentLength' : {
				'location' : 'header',
				'sentAs' : 'Content-Length',
			},
			'ContentType' :{
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'CacheControl': {
				'location': 'header',
				'sentAs': 'Cache-Control'
			},
			'ContentDisposition': {
				'location': 'header',
				'sentAs': 'Content-Disposition'
			},
			'ContentLanguage': {
				'location': 'header',
				'sentAs': 'Content-Language'
			},
			'ContentEncoding': {
				'location': 'header',
				'sentAs': 'Content-Encoding'
			},
			'TaggingCount' : {
				'location' : 'header',
				'sentAs' : 'tagging-count',
				'withPrefix': true
			},
			'Expires': {
				'location': 'header',
				'sentAs': 'Expires'
			},
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true
			},
			'WebsiteRedirectLocationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-website-redirect-location',
			},
			'WebsiteRedirectLocationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-website-redirect-location',
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true
			},
			'StorageClassObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
			},
			'StorageClassV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-storage-class',
			},
			'Restore' : {
				'location' : 'header',
				'sentAs' : 'restore',
				'withPrefix' : true
			},
			'RestoreObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-restore',
			},
			'RestoreV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-restore',
			},
			'ObjectType' :{
				'location' : 'header',
				'sentAs' : 'object-type',
				'withPrefix' : true
			},
			'ObjectTypeObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-object-type',
			},
			'ObjectTypeV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-object-type',
			},
			'NextPosition' :{
				'location' : 'header',
				'sentAs' : 'next-append-position',
				'withPrefix' : true
			},
			'NextPositionObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-next-append-position',
			},
			'NextPositionV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-next-append-position',
			},
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin'
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age'
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers'
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods'
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption',
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-algorithm',
			},
			'SseCV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-algorithm',
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'SseCKeyMd5Obs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-key-MD5',
			},
			'SseCKeyMd5V2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-key-MD5',
			},
			'Metadata' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'meta-',
				'withPrefix' : true
			},
			'MetadataObs' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'x-obs-meta-',
			},
			'MetadataV2' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'x-amz-meta-',
			},
			'ObjectLockMode' : {
				'location' : 'header',
				'sentAs' : 'object-lock-mode',
				'withPrefix' : true
			},
			'ObjectLockModeObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-object-lock-mode',
			},
			'ObjectLockModeV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-object-lock-mode',
			},
			'ObjectLockRetainUntilDate' : {
				'location' : 'header',
				'sentAs' : 'object-lock-retain-until-date',
				'withPrefix' : true
			},
			'ObjectLockRetainUntilDateObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-object-lock-retain-until-date',
			},
			'ObjectLockRetainUntilDateV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-object-lock-retain-until-date',
			},
			'ObjectLockLegalHold' : {
				'location' : 'header',
				'sentAs' : 'object-lock-legal-hold',
				'withPrefix' : true
			},
			'ObjectLockLegalHoldObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-object-lock-legal-hold',
			},
			'ObjectLockLegalHoldV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-object-lock-legal-hold',
			}
		},
	},

    'SetObjectMetadata': {
        'httpMethod': 'PUT',
        'urlPath': 'metadata',
        'parameters': {
            'Bucket': {
                'required': true,
                'location': 'uri'
            },
            'Key': {
                'required': true,
                'location': 'uri'
            },
            'VersionId': {
                'location': 'urlPath',
                'sentAs': 'versionId'
            },
            'Origin': {
                'location': 'header',
                'sentAs': 'Origin'
            },
            'RequestHeader': {
                'location': 'header',
                'sentAs': 'Access-Control-Request-Headers'
            },
            'CacheControl': {
                'location': 'header',
                'sentAs': 'Cache-Control'
            },
            'ContentDisposition': {
                'location': 'header',
                'sentAs': 'Content-Disposition',
				'encodingSafe': ' ;/?:@&=+$,"'
            },
            'ContentLanguage': {
                'location': 'header',
                'sentAs': 'Content-Language'
            },
            'ContentEncoding': {
            	'location': 'header',
            	'sentAs': 'Content-Encoding'
            },
            'ContentType': {
                'location': 'header',
                'sentAs': 'Content-Type'
            },
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix': true
			},
            'Expires': {
                'location': 'header',
                'sentAs': 'Expires'
            },
            'Metadata': {
            	'type' : 'object',
            	'location': 'header',
            	'sentAs': 'meta-',
                'withPrefix': true
            },
            'MetadataDirective' : {
				'location' : 'header',
				'sentAs' : 'metadata-directive',
				'withPrefix' : true
			},
            'StorageClass': {
                'location': 'header',
                'sentAs': 'storage-class',
                'withPrefix': true,
                'type' : 'adapter',
            },
            'WebsiteRedirectLocation': {
                'location': 'header',
                'sentAs': 'website-redirect-location',
                'withPrefix': true
            },
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
        }
    },
    'SetObjectMetadataOutput': {
        'parameters': {
            'Expires': {
                'location': 'header',
                'sentAs': 'Expires'
            },
			'ContentEncoding': {
				'location': 'header',
				'sentAs': 'Content-Encoding'
			},
            'ContentType': {
                'location': 'header',
                'sentAs': 'Content-Type'
            },
            'ContentLanguage': {
                'location': 'header',
                'sentAs': 'Content-Language'
            },
            'CacheControl': {
                'location': 'header',
                'sentAs': 'Cache-Control'
            },
            'ContentDisposition': {
                'location': 'header',
                'sentAs': 'Content-Disposition'
            },
            'WebsiteRedirectLocation': {
                'location': 'header',
                'sentAs': 'website-redirect-location',
                'withPrefix': true
            },
			'WebsiteRedirectLocationObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-website-redirect-location',
			},
			'WebsiteRedirectLocationV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-website-redirect-location',
			},
            'StorageClass': {
                'location': 'header',
                'sentAs': 'storage-class',
                'withPrefix': true
            },
			'StorageClassObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
			},
			'StorageClassV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-storage-class',
			},
            'Metadata': {
                'location': 'header',
                'type': 'object',
                'sentAs': 'meta-',
                'withPrefix': true
            },
			'MetadataObs' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'x-obs-meta-',
			},
			'MetadataV2' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'x-amz-meta-',
			},
			'MetadataDirective': {
				'location' : 'header',
				'sentAs' : 'metadata-directive',
				'withPrefix' : true
			}
        }
    },

	'SetObjectAcl' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'acl',
		'data' : {
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'Delivered' :{
				'location' : 'xml',
				'sentAs' : 'Delivered'
			},
			'Owner' : owner,
			'Grants' : grants,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'SetObjectAclOutput' : {
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
		},
	},
	'GetObjectAcl' : {
		'httpMethod' : 'GET',
		'urlPath' : 'acl',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetObjectAclOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'Delivered' :{
				'location' : 'xml',
				'sentAs' : 'Delivered'
			},
			'Owner' : owner,
			'Grants' : grants
		},
	},

	'SetObjectTagging' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'tagging',
		'data' : {
			'xmlRoot' : 'Tagging',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'Tags' : tagSet
		}
	},

	'GetObjectTagging' : {
		'httpMethod' : 'GET',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
		}
	},

	'GetObjectTaggingOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'Tagging',
		},
		'parameters' : {
			'Tags' : tagSet
		}
	},

	'DeleteObjectTagging' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
		}
	},

	'DeleteObject' : {
		'httpMethod' : 'DELETE',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'DeleteObjectOutput' : {
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'DeleteMarker' : {
				'location' : 'header',
				'sentAs' : 'delete-marker',
				'withPrefix' : true
			},
			'DeleteMarkerObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-delete-marker',
			},
			'DeleteMarkerV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-delete-marker',
			},
		},
	},
	'DeleteObjects' : {
		'httpMethod' : 'POST',
		'urlPath' : 'delete',
		'data' : {
			'xmlRoot' : 'Delete',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Quiet' : {
				'location' : 'xml',
				'sentAs' : 'Quiet',
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
			'Objects' : {
				'required' : true,
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Object',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
					},
				},
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'DeleteObjectsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'DeleteResult',
		},
		'parameters' : {
			'Deleteds' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Deleted',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'DeleteMarker' : {
							'sentAs' : 'DeleteMarker',
						},
						'DeleteMarkerVersionId' : {
							'sentAs' : 'DeleteMarkerVersionId',
						},
					}
				},
			},
			'Errors' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Error',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'Code' : {
							'sentAs' : 'Code',
						},
						'Message' : {
							'sentAs' : 'Message',
						},
					}
				},
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
		},
	},

	'InitiateMultipartUpload' : {
		'httpMethod' : 'POST',
		'urlPath' : 'uploads',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true
			},
			'CacheControl': {
				'location': 'header',
				'sentAs': 'Cache-Control'
			},
			'ContentDisposition': {
				'location': 'header',
				'sentAs': 'Content-Disposition',
				'encodingSafe': ' ;/?:@&=+$,"'
			},
			'ContentLanguage': {
				'location': 'header',
				'sentAs': 'Content-Language'
			},
			'ContentEncoding': {
				'location': 'header',
				'sentAs': 'Content-Encoding'
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix': true
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'expires',
				'type' : 'number',
				'withPrefix' : true
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
		},
	},
	'InitiateMultipartUploadOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'InitiateMultipartUploadResult',
		},
		'parameters' : {
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'Key' : {
				'location' : 'xml',
				'sentAs' : 'Key',
			},
			'UploadId' : {
				'location' : 'xml',
				'sentAs' : 'UploadId',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
		},
	},
	'ListMultipartUploads' : {
		'httpMethod' : 'GET',
		'urlPath' : 'uploads',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Delimiter' : {
				'location' : 'urlPath',
				'sentAs' : 'delimiter',
			},
			'KeyMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'key-marker',
			},
			'MaxUploads' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-uploads',
			},
			'Prefix' : {
				'location' : 'urlPath',
				'sentAs' : 'prefix',
			},
			'UploadIdMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'upload-id-marker',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
		},
	},
	'ListMultipartUploadsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListMultipartUploadsResult',
		},
		'parameters' : {
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'KeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'KeyMarker',
			},
			'UploadIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'UploadIdMarker',
			},
			'NextKeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'NextKeyMarker',
			},
			'Prefix' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Prefix',
			},
			'Delimiter' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Delimiter',
			},
			'NextUploadIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextUploadIdMarker',
			},
			'MaxUploads' : {
				'location' : 'xml',
				'sentAs' : 'MaxUploads',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType'
			},
			'Uploads' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Upload',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'UploadId' : {
							'sentAs' : 'UploadId',
						},
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'Initiated' : {
							'sentAs' : 'Initiated',
						},
						'StorageClass' : {
							'sentAs' : 'StorageClass',
						},
						'Owner' : owner,
						'Initiator' : initiator
					},
				},
			},
			'CommonPrefixes' : commonPrefixes
		},
	},
	'UploadPart' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'PartNumber' : {
				'required' : true,
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'partNumber',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'ContentSHA256' : {
				'location' : 'header',
				'sentAs' : 'content-sha256',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'Offset' : {
				'type' : 'plain'
			},
			'PartSize' : {
				'type' : 'plain'
			},
			'ProgressCallback' :{
				'type' : 'plain'
			},

			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'UploadPartOutput' : {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			}
		},
	},
	'ListParts' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'MaxParts' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-parts',
			},
			'PartNumberMarker' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'part-number-marker',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
		},
	},
	'ListPartsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListPartsResult',
		},
		'parameters' : {
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'Key' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Key',
			},
			'UploadId' : {
				'location' : 'xml',
				'sentAs' : 'UploadId',
			},
			'PartNumberMarker' : {
				'location' : 'xml',
				'sentAs' : 'PartNumberMarker',
			},
			'NextPartNumberMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextPartNumberMarker',
			},
			'MaxParts' : {
				'location' : 'xml',
				'sentAs' : 'MaxParts',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'StorageClass' : {
				'location' : 'xml',
				'sentAs' : 'StorageClass',
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'EncodingType',
			},
			'Initiator':initiator,
			'Owner' : owner,
			'Parts' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Part',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'PartNumber' : {
							'sentAs' : 'PartNumber',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
						'Size' : {
							'sentAs' : 'Size',
						},
					},
				},
			}
		},
	},
	'CopyPart' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'PartNumber' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'partNumber',
				'type' : 'number',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'CopySource' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'copy-source',
				'skipEncoding' : true,
				'withPrefix' : true
			},
			'CopySourceRange' : {
				'location' : 'header',
				'sentAs' : 'copy-source-range',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'CopySourceSseC' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'CopySourceSseCKey' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'CopyPartOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CopyPartResult',
		},
		'parameters' : {
			'LastModified' : {
				'location' : 'xml',
				'sentAs' : 'LastModified',
			},
			'ETag' : {
				'location' : 'xml',
				'sentAs' : 'ETag',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			}
		},
	},
	'AbortMultipartUpload' : {
		'httpMethod' : 'DELETE',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'CompleteMultipartUpload' : {
		'httpMethod' : 'POST',
		'data' : {
			'xmlRoot' : 'CompleteMultipartUpload',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
			'Parts' : {
				'required' : true,
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Part',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'PartNumber' : {
							'sentAs' : 'PartNumber',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
					},
				},
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'CompleteMultipartUploadOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CompleteMultipartUploadResult',
		},
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'Location' : {
				'location' : 'xml',
				'sentAs' : 'Location',
			},
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'Key' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Key',
			},
			'ETag' : {
				'location' : 'xml',
				'sentAs' : 'ETag',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
		},
	},

	'OptionsObject' : {
		'httpMethod' : 'OPTIONS',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Origin' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'Origin',
			},
			'AccessControlRequestMethods' : {
				'required' : true,
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Method',
				'items' : {
					'type' : 'string',
				},
			},
			'AccessControlRequestHeaders' : {
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers',
				'items' : {
					'type' : 'string',
				},
			},
		},
	},
	'OptionsObjectOutput' : {
		'parameters' : {
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin',
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers',
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods',
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers',
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age',
			},
		},
	},

	'GetBucketDirectColdAccess': {
		'httpMethod': 'GET',
		'urlPath': 'directcoldaccess',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			}
		}
	},

	'GetBucketDirectColdAccessOutput': {
		'data': {
			'type': 'xml',
			'xmlRoot': 'DirectColdAccessConfiguration'
		},
		'parameters': {
			'Status': {
				'location': 'xml',
				'sentAs': 'Status'
			}
		}
	},

	'SetBucketDirectColdAccess': {
		'httpMethod': 'PUT',
		'urlPath': 'directcoldaccess',
		'data': {
			'xmlRoot': 'DirectColdAccessConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Status': {
				'required': true,
				'location': 'xml',
				'sentAs': 'Status'
			}
		}
	},

	'SetBucketDirectColdAccessOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'DirectColdAccessConfiguration'
		},
		'parameters' : {
			'Status': {
				'location': 'xml',
				'sentAs': 'Status'
			}
		}
	},

	'DeleteBucketDirectColdAccess': {
		'httpMethod': 'DELETE',
		'urlPath': 'directcoldaccess',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			}
		}
	},

	'DeleteBucketDirectColdAccessOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'DirectColdAccessConfiguration'
		},
		'parameters' : {
			'Status': {
				'location': 'xml',
				'sentAs': 'Status'
			}
		}
	},

	'GetBucketEncryption' : {
		'httpMethod' : 'GET',
		'urlPath' : 'encryption',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'GetBucketEncryptionOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Rule' : {
				'type': 'object',
				'location': 'xml',
				'sentAs': 'Rule',

				'parameters': {
					'ApplyServerSideEncryptionByDefault': {
						'type': 'object',
						'sentAs': 'ApplyServerSideEncryptionByDefault',
						'parameters': {
							'SSEAlgorithm': {
								'sentAs': 'SSEAlgorithm'
							},
							'KMSMasterKeyID': {
								'sentAs': 'KMSMasterKeyID'
							}
						}
					}
				}
			}
		}
	},
	'SetBucketEncryption': {
		'httpMethod' : 'PUT',
		'urlPath' : 'encryption',
		'data' : {
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Rule' : bucketEncryptionRule
		}
	},
	'SetBucketEncryptionOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Rule' : bucketEncryptionRule
		}
	},
	'DeleteBucketEncryption': {
		'httpMethod': 'DELETE',
		'urlPath': 'encryption',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			}
		}
	},
	'DeleteBucketEncryptionOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Rule' : bucketEncryptionRule
		}
	},
	'PutBucketPublicAccessBlock' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'publicAccessBlock',
		'data' : {
			'xmlRoot' : 'PublicAccessBlockConfiguration'
		},
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
			...PublicAccessBlockBody
		}
	},
	'GetBucketPublicAccessBlock' : {
		'httpMethod' : 'GET',
		'urlPath' : 'publicAccessBlock',
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
		}
	},
	'GetBucketPublicAccessBlockOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'PublicAccessBlockConfiguration'
		},
		"parameters": {
			...PublicAccessBlockBody
		}
	},
	'DeleteBucketPublicAccessBlock' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'publicAccessBlock',
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
		}
	},
	'GetBucketPolicyPublicStatus' : {
		'httpMethod' : 'GET',
		'urlPath' : 'policyStatus',
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
		}
	},
	'GetBucketPolicyPublicStatusOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'PolicyStatus'
		},
		"parameters": {
			'IsPublic' : {
				'location' : 'xml',
				'sentAs' : 'IsPublic',
			},
		}
	},
	'GetBucketPublicStatus' : {
		'httpMethod' : 'GET',
		'urlPath' : 'bucketStatus',
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
		}
	},
	'GetBucketPublicStatusOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'BucketStatus'
		},
		"parameters": {
			'IsPublic' : {
				'location' : 'xml',
				'sentAs' : 'IsPublic',
			},
		}
	},
	'SetBucketCustomDomain' : {
		'httpMethod' : 'PUT',
		// 'urlPath' : 'customdomain',
		'data' : {
			'md5' : true
		},
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location': 'uri',
			},
			'DomainName' : {
				'required': true,
				'location': 'urlPath',
				'sentAs':'customdomain'
			},
			'DomainBody':CustomDomainCertificateConfig
		}
	},
	'GetBucketCustomDomain' : {
		'httpMethod' : 'GET',
		'urlPath' : 'customdomain',
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location': 'uri',
				'type': 'string'
			},
		}
	},
	'GetBucketCustomDomainOutput': {
		'data': {
			'type': 'xml',
			'xmlRoot': 'ListBucketCustomDomainsResult'
		},
		'parameters': {
			'Domains': {
				'location': 'xml',
				'sentAs': 'Domains',
				'type': 'array',
				'items': {
					'type': 'object',
					'parameters': {
						'DomainName': {
							'sentAs': 'DomainName',
						},
						'Value': {
							'sentAs': 'CreateTime',
						},
						'CertificateId': {
							'sentAs': 'CertificateId',
						}
					},
				}
			}
		}
	},
	'DeleteBucketCustomDomain' : {
		'httpMethod' : 'DELETE',
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'DomainName': {
				'required': true,
				'location': 'urlPath',
				'sentAs':'customdomain'
			}
		}
	},
	'SetBucketInventory' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'inventory',
		'data' : {
			'xmlRoot' : 'InventoryConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'InventoryId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'id'
			},
			'Id' : {
				'location' : 'xml',
				'sentAs' : 'Id'
			},
			'IsEnabled' : {
				'location' : 'xml',
				'sentAs' : 'IsEnabled'
			},
			'Filter' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Filter',
				'parameters' : {
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Destination' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Destination',
				'parameters' : {
					'Format' : {
						'sentAs' : 'Format'
					},
					'Bucket' : {
						'sentAs' : 'Bucket',
						'type' : 'adapter'
					},
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Schedule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Schedule',
				'parameters' : {
					'Frequency' : {
						'sentAs' : 'Frequency'
					}
				}
			},
			'IncludedObjectVersions' : {
				'location' : 'xml',
				'sentAs' : 'IncludedObjectVersions'
			},
			'OptionalFields' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'OptionalFields',
				'parameters' : {
					'Field' : {
						'type' : 'array',
						'sentAs' : 'Field',
						'items' : {
							'type' : 'string'
						}
					}
				}
			}
		}
	},
	'GetBucketInventory' : {
		'httpMethod' : 'GET',
		'urlPath' : 'inventory',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'InventoryId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'id'
			}
		}
	},
	'GetBucketInventoryOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'InventoryConfiguration'
		},
		'parameters' : {
			'Id' : {
				'location' : 'xml',
				'sentAs' : 'Id'
			},
			'IsEnabled' : {
				'location' : 'xml',
				'sentAs' : 'IsEnabled'
			},
			'Filter' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Filter',
				'parameters' : {
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Destination' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Destination',
				'parameters' : {
					'Format' : {
						'sentAs' : 'Format'
					},
					'Bucket' : {
						'sentAs' : 'Bucket',
						'type' : 'adapter'
					},
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Schedule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Schedule',
				'parameters' : {
					'Frequency' : {
						'sentAs' : 'Frequency'
					}
				}
			},
			'IncludedObjectVersions' : {
				'location' : 'xml',
				'sentAs' : 'IncludedObjectVersions'
			},
			'OptionalFields' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'OptionalFields',
				'parameters' : {
					'Field' : {
						'type' : 'array',
						'sentAs' : 'Field',
						'items' : {
							'type' : 'string'
						}
					}
				}
			}
		}
	},
	'ListBucketInventory' : {
		'httpMethod' : 'GET',
		'urlPath' : 'inventory',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'ListBucketInventoryOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListInventoryConfiguration'
		},
		'parameters' : {
			'InventoryConfiguration' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'InventoryConfiguration',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Id' : {
							'location' : 'xml',
							'sentAs' : 'Id'
						},
						'IsEnabled' : {
							'location' : 'xml',
							'sentAs' : 'IsEnabled'
						},
						'Filter' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'Filter',
							'parameters' : {
								'Prefix' : {
									'sentAs' : 'Prefix'
								}
							}
						},
						'Destination' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'Destination',
							'parameters' : {
								'Format' : {
									'sentAs' : 'Format'
								},
								'Bucket' : {
									'sentAs' : 'Bucket',
									'type' : 'adapter'
								},
								'Prefix' : {
									'sentAs' : 'Prefix'
								}
							}
						},
						'Schedule' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'Schedule',
							'parameters' : {
								'Frequency' : {
									'sentAs' : 'Frequency'
								}
							}
						},
						'IncludedObjectVersions' : {
							'location' : 'xml',
							'sentAs' : 'IncludedObjectVersions'
						},
						'OptionalFields' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'OptionalFields',
							'parameters' : {
								'Field' : {
									'type' : 'array',
									'sentAs' : 'Field',
									'items' : {
										'type' : 'string'
									}
								}
							}
						}
					}
				}
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated'
			},
			'ContinuationToken' : {
				'location' : 'xml',
				'sentAs' : 'ContinuationToken'
			},
			'NextContinuationToken' : {
				'location' : 'xml',
				'sentAs' : 'NextContinuationToken'
			}
		}
	},
	'DeleteBucketInventory' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'inventory',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'InventoryId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'id'
			}
		}
	},
	'SetObjectLockConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'object-lock',
		'data' : {
			'xmlRoot' : 'ObjectLockConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'ObjectLockEnabled' : {
				'location' : 'xml',
				'sentAs' : 'ObjectLockEnabled'
			},
			'Rule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Rule',
				'parameters' : {
					'DefaultRetention' : {
						'type' : 'object',
						'sentAs' : 'DefaultRetention',
						'parameters' : {
							'Mode' : {
								'sentAs' : 'Mode'
							},
							'Days' : {
								'type' : 'number',
								'sentAs' : 'Days'
							},
							'Years' : {
								'type' : 'number',
								'sentAs' : 'Years'
							}
						}
					}
				}
			}
		}
	},
	'GetObjectLockConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'object-lock',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'GetObjectLockConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ObjectLockConfiguration'
		},
		'parameters' : {
			'ObjectLockEnabled' : {
				'location' : 'xml',
				'sentAs' : 'ObjectLockEnabled'
			},
			'Rule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Rule',
				'parameters' : {
					'DefaultRetention' : {
						'type' : 'object',
						'sentAs' : 'DefaultRetention',
						'parameters' : {
							'Mode' : {
								'sentAs' : 'Mode'
							},
							'Days' : {
								'type' : 'number',
								'sentAs' : 'Days'
							},
							'Years' : {
								'type' : 'number',
								'sentAs' : 'Years'
							}
						}
					}
				}
			}
		}
	},
	'SetObjectRetention' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'retention',
		'data' : {
			'xmlRoot' : 'Retention',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Key' : {
				'required' : true,
				'location' : 'uri'
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId'
			},
			'Mode' : {
				'location' : 'xml',
				'sentAs' : 'Mode'
			},
			'RetainUntilDate' : {
				'location' : 'xml',
				'sentAs' : 'RetainUntilDate'
			}
		}
	},
	'SetBucketMirrorBackToSource' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'mirrorBackToSource',
		'data' : {
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'GetBucketMirrorBackToSource' : {
		'httpMethod' : 'GET',
		'urlPath' : 'mirrorBackToSource',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'GetBucketMirrorBackToSourceOutput' : {
		'data' : {
			'type' : 'body'
		},
		'parameters' : {
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'DeleteBucketMirrorBackToSource' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'mirrorBackToSource',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'SetBucketCompressPolicy' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'obscompresspolicy',
		'data' : {
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'GetBucketCompressPolicy' : {
		'httpMethod' : 'GET',
		'urlPath' : 'obscompresspolicy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'GetBucketCompressPolicyOutput' : {
		'data' : {
			'type' : 'body'
		},
		'parameters' : {
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'DeleteBucketCompressPolicy' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'obscompresspolicy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'TruncateObject' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'truncate',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Key' : {
				'required' : true,
				'location' : 'uri'
			},
			'Length' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'length',
				'type' : 'number'
			}
		}
	}
};


module.exports = operations;

/***/ }),

/***/ 395:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/**
 * Copyright 2019 Huawei Technologies Co.,Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 */

const crypto = __nccwpck_require__(6982);
const fs = __nccwpck_require__(9896);
const events = __nccwpck_require__(4434);
const httpLib = __nccwpck_require__(8611);
const httpsLib = __nccwpck_require__(5692);
const { XMLParser } = __nccwpck_require__(591)
const urlLib = __nccwpck_require__(7016);
const pathLib = __nccwpck_require__(6928);
const streamLib = __nccwpck_require__(2203);
const obsModel = __nccwpck_require__(8567);
const v2Model = __nccwpck_require__(5755);
const enums = __nccwpck_require__(8208);
const options = {
	ignoreAttributes: true,
	parseTagValue: false,
	trimValues: false
};
const {
	IAM_DOMAIN_PATH_EXTENSION
} = enums;
const parser = new XMLParser(options);
const DEFAULT_SHADOW_EXPIRES = 15 * 60;
const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';
const OBS_SDK_VERSION = '3.26.8';

const mimeTypes = {
    '7z' : 'application/x-7z-compressed',
    'aac' : 'audio/x-aac',
    'ai' : 'application/postscript',
    'aif' : 'audio/x-aiff',
    'asc' : 'text/plain',
    'asf' : 'video/x-ms-asf',
    'atom' : 'application/atom+xml',
    'avi' : 'video/x-msvideo',
    'bmp' : 'image/bmp',
    'bz2' : 'application/x-bzip2',
    'cer' : 'application/pkix-cert',
    'crl' : 'application/pkix-crl',
    'crt' : 'application/x-x509-ca-cert',
    'css' : 'text/css',
    'csv' : 'text/csv',
    'cu' : 'application/cu-seeme',
    'deb' : 'application/x-debian-package',
    'doc' : 'application/msword',
    'docx' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'dvi' : 'application/x-dvi',
    'eot' : 'application/vnd.ms-fontobject',
    'eps' : 'application/postscript',
    'epub' : 'application/epub+zip',
    'etx' : 'text/x-setext',
    'flac' : 'audio/flac',
    'flv' : 'video/x-flv',
    'gif' : 'image/gif',
    'gz' : 'application/gzip',
    'htm' : 'text/html',
    'html' : 'text/html',
    'ico' : 'image/x-icon',
    'ics' : 'text/calendar',
    'ini' : 'text/plain',
    'iso' : 'application/x-iso9660-image',
    'jar' : 'application/java-archive',
    'jpe' : 'image/jpeg',
    'jpeg' : 'image/jpeg',
    'jpg' : 'image/jpeg',
    'js' : 'text/javascript',
    'mjs' : 'text/javascript',
    'json' : 'application/json',
    'latex' : 'application/x-latex',
    'log' : 'text/plain',
    'm4a' : 'audio/mp4',
    'm4v' : 'video/mp4',
    'mid' : 'audio/midi',
    'midi' : 'audio/midi',
    'mov' : 'video/quicktime',
    'mp3' : 'audio/mpeg',
    'mp4' : 'video/mp4',
    'mp4a' : 'audio/mp4',
    'mp4v' : 'video/mp4',
    'mpe' : 'video/mpeg',
    'mpeg' : 'video/mpeg',
    'mpg' : 'video/mpeg',
    'mpg4' : 'video/mp4',
    'oga' : 'audio/ogg',
    'ogg' : 'audio/ogg',
    'ogv' : 'video/ogg',
    'ogx' : 'application/ogg',
    'pbm' : 'image/x-portable-bitmap',
    'pdf' : 'application/pdf',
    'pgm' : 'image/x-portable-graymap',
    'png' : 'image/png',
    'pnm' : 'image/x-portable-anymap',
    'ppm' : 'image/x-portable-pixmap',
    'ppt' : 'application/vnd.ms-powerpoint',
    'pptx' : 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'ps' : 'application/postscript',
    'qt' : 'video/quicktime',
    'rar' : 'application/x-rar-compressed',
    'ras' : 'image/x-cmu-raster',
    'rss' : 'application/rss+xml',
    'rtf' : 'application/rtf',
    'sgm' : 'text/sgml',
    'sgml' : 'text/sgml',
    'svg' : 'image/svg+xml',
    'swf' : 'application/x-shockwave-flash',
    'tar' : 'application/x-tar',
    'tif' : 'image/tiff',
    'tiff' : 'image/tiff',
    'torrent' : 'application/x-bittorrent',
    'ttf' : 'application/x-font-ttf',
    'txt' : 'text/plain',
    'wav' : 'audio/x-wav',
    'webm' : 'video/webm',
    'wma' : 'audio/x-ms-wma',
    'wmv' : 'video/x-ms-wmv',
    'woff' : 'application/x-font-woff',
    'wsdl' : 'application/wsdl+xml',
    'xbm' : 'image/x-xbitmap',
    'xls' : 'application/vnd.ms-excel',
    'xlsx' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'xml' : 'application/xml',
    'xpm' : 'image/x-xpixmap',
    'xwd' : 'image/x-xwindowdump',
    'yaml' : 'text/yaml',
    'yml' : 'text/yaml',
    'zip' : 'application/zip',
	'wasm' : 'application/wasm',
};


const allowedResourceParameterNames = [
	'acl',
	'backtosource',
    'policy',
    'torrent',
    'logging',
    'location',
    'storageinfo',
    'quota',
    'storageclass',
    'storagepolicy',
    'requestpayment',
    'versions',
    'versioning',
    'versionid',
    'uploads',
    'uploadid',
    'partnumber',
    'website',
    'notification',
    'replication',
    'lifecycle',
    'deletebucket',
    'delete',
    'cors',
    'restore',
    'tagging',
    'append',
    'position',
    'response-content-type',
    'response-content-language',
    'response-expires',
    'response-cache-control',
    'response-content-disposition',
    'response-content-encoding',
    'x-image-process',
    'x-oss-process',
    'x-image-save-object',
    'x-image-save-bucket',
	'encryption',
	'directcoldaccess',
	'rename',
	'name',
	'requestPayment',
	'metadata',
	'modify',
	'attname',
	'truncate',
	'x-obs-security-token',

	// workflow api
	'x-workflow-prefix',
	'x-workflow-start',
	'x-workflow-limit',
	'x-workflow-template-name',
	'x-workflow-graph-name',
	'x-workflow-execution-state',
	'x-workflow-execution-type',
	'x-workflow-next-marker',
	'obsworkflowtriggerpolicy',

	// virtual bucket api
	'obsbucketalias',
	'obsalias',
	'publicaccessblock',
	'bucketstatus',
	'policystatus',

	'customdomain',

	// inventory / worm / mirrorback / decompress sub-resources
	'inventory',
	'object-lock',
	'retention',
	'mirrorbacktosource',
	'obscompresspolicy',
	// truncate / modify sub-resources
	'length',
	'position',
];


const allowedResponseHttpHeaderMetadataNames = [
    'content-type',
    'content-md5',
    'content-length',
    'content-language',
    'expires',
    'origin',
    'cache-control',
    'content-disposition',
    'content-encoding',
    'x-default-storage-class',
    'location',
    'date',
    'etag',
    'host',
    'last-modified',
    'content-range',
    'x-reserved',
    'access-control-allow-origin',
    'access-control-allow-headers',
    'access-control-max-age',
    'access-control-allow-methods',
    'access-control-expose-headers',
    'connection'
];

const commonHeaders = {
	'content-length' : 'ContentLength',
	'date' : 'Date',
	'x-reserved' : 'Reserved'
};

const obsAllowedStorageClass = ['STANDARD', 'WARM', 'COLD', 'DEEP_ARCHIVE', 'INTELLIGENT_TIERING', 'HIGH_PERFORMANCE'];

// 服务端暂不支持S3协议的INTELLIGENT_TIERING、HIGH_PERFORMANCE
const v2AllowedStorageClass = ['STANDARD', 'STANDARD_IA', 'GLACIER', 'DEEP_ARCHIVE', 'INTELLIGENT_TIERING', 'HIGH_PERFORMANCE'];

const obsAllowedAcl = ['private', 'public-read', 'public-read-write', 'public-read-delivered', 'public-read-write-delivered','bucket-owner-full-control'];

const v2AllowedAcl = ['private', 'public-read', 'public-read-write', 'authenticated-read', 'bucket-owner-read', 'bucket-owner-full-control', 'log-delivery-write'];

const obsAllowedUri = ['Everyone', 'Logdelivery'];

const v2AllowedUri = ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers', 'http://acs.amazonaws.com/groups/s3/LogDelivery'];

const obsAllowedEvent = ['ObjectCreated:*', 'ObjectCreated:Put', 'ObjectCreated:Post', 'ObjectCreated:Copy',
    'ObjectCreated:CompleteMultipartUpload', 'ObjectRemoved:*', 'ObjectRemoved:Delete', 'ObjectRemoved:DeleteMarkerCreated'];
const v2AllowedEvent = ['s3:ObjectCreated:*', 's3:ObjectCreated:Put', 's3:ObjectCreated:Post', 's3:ObjectCreated:Copy',
    's3:ObjectCreated:CompleteMultipartUpload', 's3:ObjectRemoved:*', 's3:ObjectRemoved:Delete', 's3:ObjectRemoved:DeleteMarkerCreated'];

const negotiateMethod = 'HeadApiVersion';

const customDomainCertificateMethod = 'SetBucketCustomDomain'

const obsSignatureContext = {
	signature :	'obs',
	headerPrefix : 'x-obs-',
	headerMetaPrefix : 'x-obs-meta-',
	authPrefix : 'OBS',
	stsToken: 'x-obs-security-token',
};

const v2SignatureContext = {
	signature :	'v2',
	headerPrefix : 'x-amz-',
	headerMetaPrefix : 'x-amz-meta-',
	authPrefix : 'AWS',
	stsToken: 'x-amz-security-token',
};

class TimedOutError extends Error {
    constructor(host) {
        super('connect ETIMEDOUT ' + host);
        this.errno = 'ETIMEDOUT';
        this.code = 'ETIMEDOUT';
        Error.captureStackTrace(this, TimedOutError);
    }
}

function encodeURIWithSafe(str, safe, skipEncoding){
	str = String(str);
	if (str.length === 0) {
		return '';
	}
	if (skipEncoding) {
		return str;
	}
	let ret;
	if (safe) {
		ret = [];
		for (const element of str) {
			ret.push(safe.indexOf(element) >= 0 ? element : encodeURIComponent(element));
		}
		ret = ret.join('');
	} else {
		ret = encodeURIComponent(str);
	}
	return ret.replace(/!/g, '%21')
		.replace(/\*/g, '%2A')
		.replace(/'/g, '%27')
		.replace(/\(/g, '%28')
		.replace(/\)/g, '%29');
}

function headerTostring(obj){
	return JSON ? JSON.stringify(obj) : '';
}

function parseObjectFromHeaders(sentAs, headers){
	let metadata = {};
	for(let key in headers){
		if ({}.hasOwnProperty.call(headers, key)) {
			let k = String(key).toLowerCase();
			if (k.indexOf(sentAs) === 0) {
				metadata[k.slice(sentAs.length)] = headers[key];
			}
		}
	}
	return metadata;
}

function mkdirsSync(dirname) {
	if (fs.existsSync(dirname)) {
		return true;
	}
	if (mkdirsSync(pathLib.dirname(dirname))) {
		fs.mkdirSync(dirname);
		return true;
	}
	return false;
}

function isArray(obj) {
	return Object.prototype.toString.call(obj) === '[object Array]';
}

function isObject(obj) {
	return Object.prototype.toString.call(obj) === '[object Object]';
}


function makeObjFromXml(xml, methodName, log, bc){

	try {
		const result = parser.parse(xml, options);
		if(result === null || result === undefined){
			if(log.isLevelEnabled('error')){
				log.runLog('error', methodName, 'xml [' + xml + '] is not well-format');
			}
			return bc(new Error('xml is not well format'), null);
		}

		bc(null, result);
	} catch (err) {
		return bc(err, null);
	}
}

function getExpireDate(utcDateStr){
	let date = new Date(Date.parse(utcDateStr));
	let hour = date.getUTCHours();
	let min = date.getUTCMinutes();
	let sec = date.getUTCSeconds();
	let day = date.getUTCDate();
	let moth = date.getUTCMonth() + 1;
	let year = date.getUTCFullYear();
	let expireDate = '';
	expireDate += year + '-';

	if(moth < 10){
		expireDate += '0';
	}
	expireDate += moth + '-';

	if(day < 10){
		expireDate += '0';
	}
	expireDate += day + 'T';

	if(hour < 10){
		expireDate += '0';
	}
	expireDate += hour + ':';

	if(min < 10){
		expireDate += '0';
	}
	expireDate += min + ':';

	if(sec < 10){
		expireDate += '0';
	}
	expireDate += sec + 'Z';
	return expireDate;
}

function getDates(utcDateStr){
	let date = new Date(Date.parse(utcDateStr));
	let hour = date.getUTCHours();
	let min = date.getUTCMinutes();
	let sec = date.getUTCSeconds();
	let day = date.getUTCDate();
	let moth = date.getUTCMonth() + 1;
	let year = date.getUTCFullYear();
	let shortDate = '';
	let longDate = '';
	shortDate += year;

	if(moth < 10){
		shortDate += '0';
	}
	shortDate += moth;

	if(day < 10){
		shortDate += '0';
	}
	shortDate += day;

	longDate += shortDate + 'T';
	if(hour < 10){
		longDate += '0';
	}
	longDate +=  hour;

	if(min < 10){
		longDate += '0';
	}
	longDate +=  min;

	if(sec < 10){
		longDate += '0';
	}
	longDate +=  sec + 'Z';
	return [shortDate, longDate];
}

function getSignedAndCanonicalHeaders(header){
	let arrheadKey = [];
	let arrhead = {};
	for(let key in header){
		if ({}.hasOwnProperty.call(header, key)){
			arrheadKey.push(key.toLowerCase());
			arrhead[key.toLowerCase()] = header[key];
		}
	}
	arrheadKey = arrheadKey.sort();
	let signedHeaders = '';
	let canonicalHeaders = '';
	for(let i = 0; i < arrheadKey.length; i++){
		if(i !== 0){
			signedHeaders += ';';
		}
		signedHeaders += arrheadKey[i];
		canonicalHeaders +=  arrheadKey[i] + ':' + arrhead[arrheadKey[i]] + '\n';
	}
	return [signedHeaders, canonicalHeaders];
}

function createV4Signature(shortDate, sk, region, stringToSign){
	let dateKey = crypto.createHmac('sha256', 'AWS4' + sk).update(shortDate).digest();
	let dateRegionKey = crypto.createHmac('sha256', dateKey).update(region).digest();
	let dateRegionServiceKey = crypto.createHmac('sha256', dateRegionKey).update('s3').digest();
	let signingKey = crypto.createHmac('sha256',dateRegionServiceKey).update('aws4_request').digest();
	return crypto.createHmac('sha256',signingKey).update(stringToSign).digest('hex');
}

function getV4Signature(shortDate, longDate, sk, region, canonicalRequest){
	let scope = shortDate + '/' + region + '/s3/aws4_request';
	let stringToSign = 'AWS4-HMAC-SHA256\n';
	stringToSign += longDate + '\n';
	stringToSign += scope + '\n';
	stringToSign += crypto.createHash('sha256').update(canonicalRequest).digest('hex');
	return createV4Signature(shortDate, sk, region, stringToSign);
}



function getXSdkDateIAMCloud() { // To get the x-sdk-date for Iamcloud
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const day = String(now.getUTCDate()).padStart(2, '0');
  const hours = String(now.getUTCHours()).padStart(2, '0');
  const minutes = String(now.getUTCMinutes()).padStart(2, '0');
  const seconds = String(now.getUTCSeconds()).padStart(2, '0');

  return `${year}${month}${day}T${hours}${minutes}${seconds}Z`;
}

function Utils(logger) {
	this.log = logger;
	this.ak = null;
	this.sk = null;
	this.permanentAk = null;
	this.permanentSk = null;
	this.securityToken = null;
	this.isSecure = true;
	this.server = null;
	this.pathStyle = false;
	this.signatureContext = null;
	this.isSignatureNegotiation = true;
	this.bucketSignatureCache = {};
	this.region = '';
	this.port = null;
	this.maxRetryCount = 3;
	this.timeout = 60;
	this.sslVerify = false;
	this.httpAgent = false;
	this.httpsAgent = false;
	this.noProxyList = [];
	this.obsSdkVersion = OBS_SDK_VERSION;
	this.isCname = false;
	this.bucketEventEmitters = {};
	this.maxConnections = 1000;
	this.userAgent = 'obs-sdk-js/' + this.obsSdkVersion;
	this.iam_domain = null;
	this.shadow_expires = DEFAULT_SHADOW_EXPIRES;
	this.is_shadow_client = false;
	this.shadow_expires_at = null
	this.shadow_expires_at_milliseconds = null
	this.is_shadow_client_ready = false
}

Utils.prototype.encodeURIWithSafe = encodeURIWithSafe;

Utils.prototype.mimeTypes = mimeTypes;

Utils.prototype.close = function(){
	if(this.httpAgent){
		this.httpAgent = null;
	}
	if(this.httpsAgent){
		this.httpsAgent = null;
	}
	if (this.thirdHttpLib) {
		this.thirdHttpLib = null;
	}
};

Utils.prototype.refresh = async function (ak, sk, securityToken, is_shadow_client) {
	this.ak = ak ? String(ak).trim() : null;
	this.sk = sk ? String(sk).trim(): null;
	this.securityToken = securityToken ? String(securityToken).trim() : null;

	if (is_shadow_client) {
		await this.getTemporaryKeysFromCloudAlliance(this.ak, this.sk,this.iam_domain, this.shadow_expires)
	}
};

Utils.prototype.initFactory = async function (ak, sk, isSecure,
	server, pathStyle, signature, region, port, maxRetryCount, timeout, sslVerify, longConnection, securityToken,
	isSignatureNegotiation, isCname, maxConnections, httpAgent, httpsAgent, userAgent, thirdHttpLib, noProxyList, is_shadow_client, iam_domain, shadow_expires, verifyHostName) {

	this.is_shadow_client = is_shadow_client
	this.iam_domain = iam_domain

	shadow_expires = Number(shadow_expires)

	if (shadow_expires && (shadow_expires < (15 * 60) || shadow_expires > (60 * 60 * 24))) {
		throw new Error('Expire time is not valid!');
	}

	if (shadow_expires) {
		this.shadow_expires = shadow_expires
	}

	if (httpAgent !== undefined) {
		this.httpAgent = httpAgent;
	}

	if (httpsAgent !== undefined) {
		this.httpsAgent = httpsAgent;
	}

	await this.refresh(ak, sk, securityToken, is_shadow_client);

	if (!server) {
		throw new Error('Server is not set');
	}

	if (is_shadow_client === true && !iam_domain) {
		throw new Error('iam_domain is not set');
	}

	server = String(server).trim();

	if (server.indexOf('https://') === 0) {
		server = server.slice('https://'.length);
		isSecure = true;
	} else if (server.indexOf('http://') === 0) {
		server = server.slice('http://'.length);
		isSecure = false;
	}

	let index = server.lastIndexOf('/');
	while (index >= 0) {
		server = server.slice(0, index);
		index = server.lastIndexOf('/');
	}

	index = server.indexOf(':');
	if (index >= 0) {
		port = server.slice(index + 1);
		server = server.slice(0, index);
	}
	this.server = server;

	if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(this.server)) {
		pathStyle = true;
	}

	if (isSecure !== undefined) {
		this.isSecure = isSecure;
	}
	if (pathStyle !== undefined) {
		this.pathStyle = pathStyle;
	}

	if (signature !== undefined) {
		signature = String(signature).trim().toLowerCase();
	} else {
		signature = 'obs';
	}

	if (isSignatureNegotiation !== undefined) {
		this.isSignatureNegotiation = isSignatureNegotiation;
	}

	this.isCname = isCname;

	if (this.pathStyle || this.isCname) {
		this.isSignatureNegotiation = false;
		if (signature === 'obs') {
			signature = 'v2';
		}
	}

	this.signatureContext = signature === 'obs' ? obsSignatureContext : v2SignatureContext;

	if (region !== undefined) {
		this.region = String(region).trim();
	}

	this.port = port ? parseInt(port, 10) : (this.isSecure ? 443 : 80);

	if (maxRetryCount !== undefined) {
		this.maxRetryCount = parseInt(maxRetryCount, 10);
	}

	if (timeout !== undefined) {
		this.timeout = parseInt(timeout, 10);
	}

	if (sslVerify !== undefined) {
		this.sslVerify = sslVerify;
	}

	if (verifyHostName !== undefined) {
		this.verifyHostName = verifyHostName;
	}

	if (maxConnections !== undefined) {
		this.maxConnections = parseInt(maxConnections, 10);
	}

	if (userAgent) {
		this.userAgent = userAgent;
	}

	if (noProxyList) {
		if (typeof noProxyList === 'string') {
			this.noProxyList = noProxyList.split(',');
		}
		if (Array.isArray(noProxyList)) {
			this.noProxyList = noProxyList;
		}
	}

	if (thirdHttpLib) {
		this.thirdHttpLib = thirdHttpLib;
	}

	if (longConnection !== undefined && Number(longConnection) >= 0) {
		if (!this.httpAgent) {
			this.httpAgent = new httpLib.Agent({ keepAlive: true, keepAliveMsecs: Number(longConnection) * 1000, maxSockets: this.maxConnections, maxFreeSockets: this.maxConnections });
		}
		if (!this.httpsAgent) {
			this.httpsAgent = new httpsLib.Agent({ keepAlive: true, keepAliveMsecs: Number(longConnection) * 1000, maxSockets: this.maxConnections, maxFreeSockets: this.maxConnections });
		}
	}


}

function generateSignatureCloudAlliance(request, ak, sk) {
	let access = ak;
	let secret = sk;
	let rawHost = request.host;
	let rawUri = request.path;
	let rawBody = request.body || "";
	let rawQueryString = request.queryString || "";


	const XSdkDate = getXSdkDateIAMCloud()
	const HTTPRequestMethod = request.method;
	if (rawUri.charAt(rawUri.length - 1) !== '/') {
		rawUri += '/';
	}
	const CanonicalURI = rawUri;
	const CanonicalQueryString = rawQueryString;
	const CanonicalHeaders = `content-type:application/json\nhost:${rawHost}\nx-sdk-date:${XSdkDate}\n`;
	const SignedHeaders = "content-type;host;x-sdk-date";

	const HashedRequestPayload = crypto.createHash('sha256').update(rawBody).digest('hex');
	const CanonicalRequest = `${HTTPRequestMethod}\n${CanonicalURI}\n${CanonicalQueryString}\n${CanonicalHeaders}\n${SignedHeaders}\n${HashedRequestPayload}`;
	const HashedCanonicalRequest = crypto.createHash('sha256').update(CanonicalRequest).digest('hex');

	const Algorithm = "SDK-HMAC-SHA256";
	const StringToSign = `${Algorithm}\n${XSdkDate}\n${HashedCanonicalRequest}`;
	const Signature = crypto.createHmac('sha256', secret).update(StringToSign).digest('hex');

	return {
			Host: rawHost,
			XSdkDate,
			Authorization: `${Algorithm} Access=${access}, SignedHeaders=${SignedHeaders}, Signature=${Signature}`
	};
}

function parseExpirationTime(expiresAtStr) {
    return new Date(expiresAtStr).getTime(); // Convert to milliseconds
}

Utils.prototype.waitForCloudAllianceGetsReady = async function() {
	const startTime = Date.now();
	const timeout = 60 * 1000; // 60 seconds

	while (!this.is_shadow_client_ready) {
		if (Date.now() - startTime > timeout) {
    	throw new Error("Timeout: Shadow client not ready");
		}
		await new Promise(resolve => setTimeout(resolve, 1000));
	}
}

Utils.prototype.refreshShadowClient = async function () {
	await this.waitForCloudAllianceGetsReady();

	if (!this.permanentAk || !this.permanentSk) {
		throw new Error("Initialization: Shadow client not ready");
	}
	this.is_shadow_client_ready = false
	await this.getTemporaryKeysFromCloudAlliance(this.permanentAk,this.permanentSk,this.iam_domain, this.shadow_expires)
}

Utils.prototype.checkKeysExpiredAndRefresh = async function() {
	const now = Date.now();
	const timeLeft = this.shadow_expires_at_milliseconds - now
	let log = this.log

	if (timeLeft <= 5 * 60 * 1000) { // checks if 5 min left to expire or not
		this.is_shadow_client_ready = false
		log.runLog('warn', 'CloudAllianceTempKeys', 'Temp keys will expire soon, refreshing');
		await this.getTemporaryKeysFromCloudAlliance(this.permanentAk,this.permanentSk,this.iam_domain, this.shadow_expires)
	}
}


Utils.prototype.getTemporaryKeysFromCloudAlliance = async function(ak,sk,iam_domain,shadow_expires) {
	//If is_shadow_client true, call iam-domain and get temp ak-sk
	const request = {
		method: 'POST',
		host: iam_domain,
		path: IAM_DOMAIN_PATH_EXTENSION,
		body: JSON.stringify({
			auth: {
				identity: {
					methods: ["token"],
					token: {
						duration_seconds: String(shadow_expires)
					}
				}
			}
		})
	};


	const validAk = this.permanentAk ? this.permanentAk : ak
	const validSk = this.permanentSk ? this.permanentSk : sk

	const { Host, XSdkDate, Authorization } = generateSignatureCloudAlliance(request, validAk, validSk);

	const options = {
		hostname: Host,
		path: request.path + (request.queryString ? `?${request.queryString}` : ''),
		method: request.method,
		headers: {
			'Content-Type': 'application/json',
			'Host': Host,
			'X-Sdk-Date': XSdkDate,
			'Authorization': Authorization
		}
	};

	if (this.httpsAgent) {
		options.agent = this.httpsAgent
	}
	let log = this.log
	let self = this

	return new Promise((resolve, reject) => {
		const req = httpsLib.request(options, (res) => {

		let responseData = '';
		res.on('data', (chunk) => {
			responseData += chunk;
		});

		res.on('end', () => {
			let parsed;
			try {
				parsed = JSON.parse(responseData);
			} catch (e) {
				reject(new Error('Failed to parse IAM response: ' + responseData));
				return;
			}
			const response = parsed;
			if (res.statusCode >= 200 && res.statusCode < 300) {
				const validResponse = response.credential
				self.permanentAk = validAk
				self.permanentSk = validSk
				self.ak = validResponse.access
				self.sk = validResponse.secret
				self.securityToken = validResponse.securitytoken
				self.shadow_expires_at = validResponse.expires_at
				self.shadow_expires_at_milliseconds = parseExpirationTime(validResponse.expires_at);
				self.refresh(validResponse.access, validResponse.secret, self.securityToken, false).then(() => {
					self.is_shadow_client_ready = true
					log.runLog('info', 'CloudAllianceTempKeys', 'response statusCode:' + res.statusCode );
					resolve();
				}).catch((err) => {
					reject(err);
				});
			} else {
				req.removeAllListeners('abort');
				req.abort();
				if(log.isLevelEnabled('error')){
					log.runLog('error', '', 'get temporary keys from cloud alliance error [' + headerTostring(response.error) + ']');
				}

				reject(new Error(response.error.message));
			}
		})
	});

	req.on('error', (err => {
		req.removeAllListeners('abort');
		req.abort();
		if(log.isLevelEnabled('error')){
			log.runLog('error', '', 'get temporary keys from cloud alliance error [' + headerTostring(err) + ']');
		}
		if(log.isLevelEnabled('warn')){
				log.runLog('warn', '', err);
		}

		reject(new Error(err));
	}));

		req.write(request.body);
		req.end();
	});

}
Utils.prototype.SseKmsAdapter = function(value, signatureContext){
	value = value || '';
	value = String(value);
	let index = value.indexOf('aws:');
	if(signatureContext.signature === 'obs'){
		return index === 0 ? value.slice(4) : value;
	}
	return index === 0 ? value : 'aws:' + value;
};

Utils.prototype.BucketAdapter = function(value, signatureContext){
	value = value || '';
	value = String(value);
	let index = value.indexOf('arn:aws:s3:::');
	if(signatureContext.signature === 'obs'){
		return index === 0 ? value.slice('arn:aws:s3:::'.length) : value;
	}
	return index === 0 ? value : 'arn:aws:s3:::' + value;
};


Utils.prototype.EventAdapter = function(value, signatureContext){
	value = value || '';
	value = String(value);
	if(signatureContext.signature === 'obs'){
		if(obsAllowedEvent.indexOf(value) >= 0){
			return value;
		}
		if(v2AllowedEvent.indexOf(value) >= 0){
			return value.substring(3);
		}
		return '';
	}
	if(v2AllowedEvent.indexOf(value) >= 0){
		return value;
	}
	if(obsAllowedEvent.indexOf(value) >= 0){
		return 's3:' + value;
	}
	return '';
};

Utils.prototype.URIAdapter = function(value, signatureContext){
	value = value || '';
	value = String(value);
	if(signatureContext.signature === 'obs'){
		if(obsAllowedUri.indexOf(value) >= 0){
			return value;
		}
		if(value === 'AllUsers' || value === 'http://acs.amazonaws.com/groups/global/AllUsers'){
			return 'Everyone';
		}
		if (value === 'LogDelivery' || value === 'http://acs.amazonaws.com/groups/s3/LogDelivery') {
			return 'LogDelivery'
		}
		return '';

	}
	if(v2AllowedUri.indexOf(value) >= 0){
		return value;
	}
	if(value === 'Everyone' || value === 'AllUsers'){
		return 'http://acs.amazonaws.com/groups/global/AllUsers';
	}
	if(value === 'AuthenticatedUsers'){
		return 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';
	}
	if(value === 'LogDelivery'){
		return 'http://acs.amazonaws.com/groups/s3/LogDelivery';
	}
	return '';
};


Utils.prototype.StorageClassAdapter = function(value, signatureContext){
	value = value || '';
	value = String(value).toUpperCase();
	if(signatureContext.signature === 'obs'){
		if(obsAllowedStorageClass.indexOf(value) >= 0){
			return value;
		}
		if(value === 'STANDARD_IA'){
			return 'WARM';
		}
		if(value === 'GLACIER'){
			return 'COLD';
		}
		return '';
	}

	if(v2AllowedStorageClass.indexOf(value) >= 0){
		if(value === 'INTELLIGENT_TIERING'){
			this.log.runLog('warn', 'Intelligent tiering supports only OBS signature');
		}
		return value;
	}
	if(value === 'WARM'){
		return 'STANDARD_IA';
	}
	if(value === 'COLD'){
		return 'GLACIER';
	}
	return '';
};

Utils.prototype.ACLAdapter = function(value, signatureContext){
	value = value || '';
	value = String(value).toLowerCase();
	if(signatureContext.signature === 'obs'){
		if(obsAllowedAcl.indexOf(value) >= 0){
			return value;
		}

		return '';
	}

	if(value === 'public-read-delivered'){
		value = 'public-read';
	}else if(value === 'public-read-write-delivered'){
		value = 'public-read-write';
	}

	if(v2AllowedAcl.indexOf(value) >= 0){
		return value;
	}
	return '';
};

Utils.prototype.doExec = function(funcName, param, callback){
	let opt = this.makeParam(funcName, param);
	if('err' in opt){
		return callback(opt.err, null);
	}
	this.sendRequest(funcName, opt, callback);
};

Utils.prototype.doNegotiation = function(funcName, param, callback, checkBucket, checkCache, setCache){
	let o = null;
	let that = this;
	if(checkCache && param.Bucket){
		let item = that.bucketSignatureCache[param.Bucket];
		if(item && item.signatureContext && item.expireTime > new Date().getTime()){
			param.signatureContext = item.signatureContext;
			let opt = that.makeParam(funcName, param);
			if('err' in opt){
				return callback(opt.err, null);
			}
			opt.signatureContext = item.signatureContext;
			return that.sendRequest(funcName, opt, callback);
		}

		o = this.bucketEventEmitters[param.Bucket];
		if(!o){
			o = {
				s : 0,
			};
			this.bucketEventEmitters[param.Bucket] = o;
		}

		if(o.s){
			o.e.once('done', () => {
				that.doNegotiation(funcName, param, callback, checkBucket, checkCache, setCache);
			});
			return;
		}
		o.e = new events.EventEmitter();
		o.s = 1;
	}
	this.doExec(negotiateMethod, checkBucket ? {Bucket:param.Bucket} : {},  function(err, result){
		if(err){
			callback(err, null);
			if(o){
				o.s = 0;
				o.e.emit('done');
			}
			return;
		}
		if((checkBucket && result.CommonMsg.Status === 404) || result.CommonMsg.Status >= 500){
			callback(err, result);
			if(o){
				o.s = 0;
				o.e.emit('done');
			}
			return;
		}
		let signatureContext = v2SignatureContext;
		if(result.CommonMsg.Status < 300 && result.InterfaceResult && result.InterfaceResult.ApiVersion >= '3.0'){
			signatureContext = obsSignatureContext;
		}

		if(setCache){
			that.bucketSignatureCache[param.Bucket] = {
				signatureContext : signatureContext,
				expireTime : new Date().getTime() + 15 + (Math.ceil(Math.random()*5)) * 60 * 1000
			};
		}
		if(o){
			o.s = 0;
			o.e.emit('done');
		}
		param.signatureContext = signatureContext;
		let opt = that.makeParam(funcName, param);
		if('err' in opt){
			return callback(opt.err, null);
		}
		opt.signatureContext = signatureContext;
		that.sendRequest(funcName, opt, callback);
	});
};

Utils.prototype.exec = function(funcName, param, callback){
	let that = this;
	if(that.isSignatureNegotiation && funcName !== negotiateMethod){
		if(funcName === 'ListBuckets'){
			that.doNegotiation(funcName, param, callback, false, false, false);
		}else if(funcName === 'CreateBucket'){
			let _callback = function(err, result){
				if(!err && result.CommonMsg.Status === 400 &&
						result.CommonMsg.Message === 'Unsupported Authorization Type' &&
						param.signatureContext &&
						param.signatureContext.signature === 'v2'){
					param.signatureContext = v2SignatureContext;
					let opt = that.makeParam(funcName, param);
					if('err' in opt){
						return callback(opt.err, null);
					}
					opt.signatureContext = param.signatureContext;
					that.sendRequest(funcName, opt, callback);
					return;
				}
				callback(err, result);
			};

			that.doNegotiation(funcName, param, _callback, false, true, false);
		}else if(funcName === 'DeleteObjects' && param.EncodingType === 'url'){
			param.Objects.map( e =>{
				e.Key = encodeURIComponent(e.Key)
				return e
			})
			that.doNegotiation(funcName, param, callback, true, true, true);
		 }else{
			that.doNegotiation(funcName, param, callback, true, true, true);
		}
		return;
	}
	that.doExec(funcName, param, callback);
};


Utils.prototype.toXml = function(mXml, xmlMeta, root, sentAs, signatureContext){
	let xml = '';
	if(root !== null){
		xml += this.buildXml(mXml, xmlMeta, root, sentAs, signatureContext);
		return xml;
	}
	for (let key in xmlMeta){
		if(key in mXml){
			let meta = xmlMeta[key];
			xml += this.buildXml(mXml, meta, key, meta.sentAs || key, signatureContext);
		}
	}
	return xml;
};

Utils.prototype.buildXml = function(mXml, xmlMeta, key, sentAs, signatureContext){
	let xml = '';
	let type = xmlMeta.type;
	if(type === 'array'){
		for(let i = 0; i < mXml[key].length; i++){
			if(xmlMeta.items.type === 'object'){
				if (!mXml[key][i]) {
					return xml;
				}
				let result = this.toXml(mXml[key][i], xmlMeta.items.parameters, null, null, signatureContext);
				if(result !== ''){
					xml += '<' + sentAs + '>'+ result + '</' + sentAs + '>';
				}
			}else if(xmlMeta.items.type === 'adapter'){
				xml += '<' + sentAs + '>' + String(this[key + 'Adapter'](mXml[key][i], signatureContext)).replace(/&/g, '&amp;').replace(/'/g, '&apos;').replace(/"/g, '&quot;') + '</' + sentAs + '>';
			}else if(xmlMeta.items.type !== 'array'){
				xml += '<' + sentAs + '>'+ String(mXml[key][i]).replace(/&/g, '&amp;').replace(/'/g, '&apos;').replace(/"/g, '&quot;') + '</' + sentAs +'>';
			}
		}
	}else if(type === 'object'){
		if (!mXml[key]) {
			return xml;
		}
		let result = this.toXml(mXml[key], xmlMeta.parameters, null, null, signatureContext);
		if(result !== ''){
			xml += '<' + sentAs;
			if('data' in xmlMeta){
				if('xsiNamespace' in xmlMeta.data){
					xml += ' xmlns:xsi="' +  xmlMeta.data.xsiNamespace + '"';
				}
				if('xsiType' in xmlMeta.data){
					xml += ' xsi:type="' + mXml[key][xmlMeta.data.xsiType] + '"';
				}
			}
			xml += '>';
			xml += result + '</' + sentAs + '>';
		}

	}else if(!xmlMeta.notAllowEmpty || String(mXml[key]) !== ''){
		if(type === 'adapter'){
			xml += '<' + sentAs + '>' + String(this[key + 'Adapter'](mXml[key], signatureContext)).replace(/&/g, '&amp;').replace(/'/g, '&apos;').replace(/"/g, '&quot;') + '</' + sentAs + '>';
		}else if(type !== 'ignore'){
			xml += '<' + sentAs + '>' + String(mXml[key]).replace(/&/g, '&amp;').replace(/'/g, '&apos;').replace(/"/g, '&quot;') + '</' + sentAs + '>';
		}
	}
	if(xml && xmlMeta.wrapper){
		let _wrapper = xmlMeta.wrapper;
		xml = '<' + _wrapper + '>' + xml + '</' + _wrapper + '>';
	}
	return xml;
};



Utils.prototype.jsonToObject = function(model, obj, root, ifRootXMlDecode){
	let opt = {};
	if(root !== null){
		this.buildObject(model, obj, root, opt, ifRootXMlDecode);
	}else{
		for(let key in model){
			if ({}.hasOwnProperty.call(model, key)) {
				this.buildObject(model, obj, key, opt, ifRootXMlDecode);
			}
		}
	}
	return opt;
};

Utils.prototype.buildObject = function(model, obj, key, opt, ifRootXMlDecode){

	let setValue = function (value) {
		return value && model[key].decode && ifRootXMlDecode
		? decodeURIComponent(value.replace(/\+/g, '%20'))
		: value;
	}

	if(isObject(obj)){
		let flag = true;
		let wrapper = model[key].wrapper;
		if(wrapper && wrapper in obj){
			obj = obj[wrapper];
			flag = isObject(obj);
		}
		if(flag){
			let sentAs = model[key].sentAs || key;
			if(sentAs in obj){
				if(model[key].type === 'object'){
					opt[key] = this.jsonToObject(model[key].parameters, obj[sentAs], null, ifRootXMlDecode);
				}else if(model[key].type === 'array'){
					let arr = [];
					if(!isArray(obj[sentAs])){
						arr[0] = model[key].items.type === 'object' ? this.jsonToObject(model[key].items.parameters, obj[sentAs], null, ifRootXMlDecode) : setValue(obj[sentAs] || '');
					}else{
						for (let i = 0; i < obj[sentAs].length; i++ ){
							arr[i] = model[key].items.type === 'object' ? this.jsonToObject(model[key].items.parameters, obj[sentAs][i], null, ifRootXMlDecode) : setValue(obj[sentAs][i]);
						}
					}
					opt[key] = arr;
				}else{
					opt[key] = setValue(obj[sentAs]);
				}
			}
		}
	}

	if(opt[key] === undefined){
		if(model[key].type === 'object'){
			opt[key] = model[key].parameters ? this.jsonToObject(model[key].parameters, null, null, ifRootXMlDecode) : {};
		}else if(model[key].type === 'array'){
			opt[key] = [];
		}else{
			opt[key] = '';
		}
	}
};

Utils.prototype.makeParam = function (methodName, param) {


	let signatureContext = param.signatureContext || this.signatureContext;
	let model = signatureContext.signature === 'obs' ? obsModel[methodName] : v2Model[methodName];
	let method = model.httpMethod;
	let uri = '/';
	let urlPath = '';
	let xml = '';
	let exheaders = {};
	let opt = {};
	opt.$requestHook = param.RequestHook;
	opt.$pipeHook = param.PipeHook;
	opt.$responseHook = param.ResponseHook;
	opt.$highWaterMark = param.HighWaterMark;

	//If the method is setBucketCustomDomain, check the certificate params
	if (methodName === customDomainCertificateMethod&&param.DomainBody) {
		checkCustomDomainCertificateParams(param.DomainBody,this.log,methodName,opt)
	}

	if ('urlPath' in model){
		urlPath += '?';
		urlPath += model.urlPath;
	}
	for (let key in model.parameters){
		if ({}.hasOwnProperty.call(model.parameters, key)) {
			let meta = model.parameters[key];
			if(key === 'Bucket' && this.isCname){
				continue;
			}

			let _value = param[key];
			if (meta.required && (_value === null || _value === undefined || (Object.prototype.toString.call(_value) === '[object String]' && _value === ''))){
				opt.err = key + ' is a required element!';
				if(this.log.isLevelEnabled('warn')){
					this.log.runLog('warn', methodName, opt.err);
				}
				return opt;
			}

			if(_value !== null && _value !== undefined){
				if(meta.type === 'srcFile' || meta.type === 'dstFile'){
					opt[meta.type] = _value;
					continue;
				}

				if(meta.type === 'plain'){
					opt[key] = _value;
				}

				let sentAs = meta.sentAs || key;

				if(meta.withPrefix){
					sentAs = signatureContext.headerPrefix + sentAs;
				}

				if(meta.location === 'uri'){
					if(uri !== '/'){
						uri += '/';
					}
					uri += _value;
				}else if(meta.location === 'header'){
					let safe = meta.encodingSafe || ' ;/?:@&=+$,';
					if(meta.type === 'object'){
						if(signatureContext.headerMetaPrefix === sentAs){
							for(let item in _value){
								if ({}.hasOwnProperty.call(_value, item)) {
									let value = _value[item];
									item = String(item).trim().toLowerCase();
									exheaders[item.indexOf(sentAs) === 0 ? item: sentAs + item] = encodeURIWithSafe(value, safe);
								}
							}
						}
					}else if(meta.type === 'array'){
						let arr = [];
						for(let i=0;i<_value.length;i++){
							arr.push(encodeURIWithSafe(_value[i], safe));
						}
						exheaders[sentAs] = arr;
					}else if(meta.type === 'password'){
						exheaders[sentAs] = Buffer.from(_value,'utf8').toString('base64');
						let pwdSentAs = sentAs + '-MD5';
						exheaders[pwdSentAs] = this.bufMD5(_value);
					}else if(meta.type === 'number' && !isNaN(Number(_value))){
						exheaders[sentAs] = encodeURIWithSafe(String(_value), safe);
					}else if(meta.type === 'boolean'){
						exheaders[sentAs] = encodeURIWithSafe(_value ? 'true' : 'false', safe);
					}else if(meta.type === 'adapter'){
						let val = this[key + 'Adapter'](_value, signatureContext);
						if(val){
							exheaders[sentAs] = encodeURIWithSafe(String(val), safe);
						}
					}else {
						exheaders[sentAs] = encodeURIWithSafe(String(_value), safe, meta.skipEncoding);
					}
				}else if(meta.location === 'urlPath'){
					let sep = urlPath === '' ? '?' : '&';
					let value = _value;
					if(meta.type !== 'number' || (meta.type === 'number' && Number(value) >= 0)){
						urlPath += sep + encodeURIWithSafe(sentAs, '/') + '=' + encodeURIWithSafe(String(value), '/');
					}
				}else if(meta.location === 'xml'){
					let mxml = this.toXml(param, meta, key, sentAs, signatureContext);
					if(mxml){
						xml += mxml;
					}
				}else if(meta.location === 'body'){
					xml = _value;
					exheaders['Content-Type'] = 'application/json';
				}
			}
		}
	}

	if('data' in model && 'xmlRoot' in model.data){
		if(xml || model.data.xmlAllowEmpty){
			let xmlRoot = model.data.xmlRoot;
			xml = '<' + xmlRoot + '>' + xml + '</' + xmlRoot + '>';
		}
	}

	exheaders.Host = this.server;
	if(!this.pathStyle && !this.isCname){
		let uriList = uri.split('/');
		if(uriList.length >= 2 && uriList[1]){
			exheaders.Host = uriList[1] + '.' + exheaders.Host;
			let requestUri = uri.replace(uriList[1], '');
			if(requestUri.indexOf('//') === 0){
				requestUri = requestUri.slice(1);
			}

			if(signatureContext.signature === 'v4'){
				uri = requestUri;
			}else if(requestUri === '/'){
				uri += '/';
			}
			opt.requestUri = encodeURIWithSafe(requestUri, '/');
		}
	}

	opt.method = method;
	opt.uri = encodeURIWithSafe(uri, '/');
	opt.urlPath = urlPath;
	if(xml){
		if(!(xml instanceof streamLib.Readable)){
			let body = Buffer.from(String(xml), 'utf8');
			if(model.data && model.data.md5){
				exheaders['Content-MD5'] = this.bufMD5(body);
			}
			exheaders['Content-Length'] = body.length === 0 ? '0' : String(body.length);
		}
		opt.xml = xml;
		if(this.log.isLevelEnabled('debug')){
			this.log.runLog('debug', methodName, 'request content:' + xml);
		}
	}
	opt.headers = exheaders;

	if('srcFile' in opt){
		if (!fs.existsSync(opt.srcFile)) {
			opt.err = 'the file [' + opt.srcFile + '] is not exist!';
			if(this.log.isLevelEnabled('error')){
				this.log.runLog('error', methodName, opt.err);
			}
			return opt;
		}

		let fileSize = fs.statSync(opt.srcFile).size;
		if ('Content-Length' in opt.headers || 'PartSize' in opt || 'Offset' in opt) {
			let offset = opt.Offset;
			offset = (offset && offset >= 0 && offset < fileSize) ? offset : 0;
			let partSize;
			if('PartSize' in opt){
				partSize = opt.PartSize;
			}else if('Content-Length' in opt.headers){
				partSize = parseInt(opt.headers['Content-Length'], 10);
			}else{
				partSize = fileSize;
			}
			partSize = (partSize && partSize > 0 && partSize <= fileSize - offset) ? partSize : fileSize - offset;
			opt.PartSize = partSize;
			opt.Offset = offset;
			opt.headers['Content-Length'] = String(opt.PartSize);
		}
	}else if('PartSize' in opt){
		opt.headers['Content-Length'] = String(opt.PartSize);
	}

	return opt;
};

Utils.prototype.sendRequest = function(funcName, opt, bc, retryCount){
	if(retryCount === undefined){
		retryCount = 1;
	}
	let that = this;
	let readable = opt.xml instanceof streamLib.Readable || opt.ProgressCallback;
	that.makeRequest(funcName, opt, retryCount, function(err, msg){
		if(err){
			if(err.message === 'redirect'){
				let uri = urlLib.parse(err.location);
				opt.headers.Host = uri.hostname;
				opt.protocol = uri.protocol;
				opt.port = uri.port || ((opt.protocol && opt.protocol.toLowerCase().indexOf('https') === 0) ? 443 : 80);
				that.sendRequest(funcName, opt, bc, retryCount + 1);
				return;
			}

			if(err.message !== 'pause' && !readable && msg !== 'PREMATURE_END' && msg !== 'SELF_SIGNED_CERT_IN_CHAIN' && msg !== 'DEPTH_ZERO_SELF_SIGNED_CERT' && retryCount <= that.maxRetryCount){
				that.sendRequest(funcName, opt, bc, retryCount + 1);
				return;
			}
		}
		bc(err, msg);
	});
};

Utils.prototype.doAuth = function(opt, methodName, signatureContext) {
	let interestHeader = ['Content-MD5', 'Content-Type', 'Date'];
	let log = this.log;

	let hasSecurityToken = false;
	let securityToken = '';

	let stringToSign = opt.method + '\n';
	for(let i=0;i<interestHeader.length;i++){
		if(interestHeader[i] in opt.headers){
			stringToSign += opt.headers[interestHeader[i]];
		}
		stringToSign += '\n';
	}

	let temp = [];
	for(let originKey of Object.keys(opt.headers)){
		let lowerKey = originKey.toLowerCase();
		if (lowerKey.indexOf(signatureContext.headerPrefix) === 0){
			temp.push({
				key: lowerKey,
				value: opt.headers[originKey]
			});
		}
		// 单独处理SecurityToken
		if (!hasSecurityToken && lowerKey === signatureContext.stsToken) {
			hasSecurityToken = true;
			securityToken = opt.headers[originKey];
		}
	}
	temp = temp.sort(function (obj1, obj2) {
		if (obj1.key < obj2.key) {
			return -1;
		}
		if (obj1.key > obj2.key) {
			return 1;
		}
		return 0;
	});
	for(let i=0;i<temp.length;i++){
		let key = temp[i].key;
		let val = key.indexOf(signatureContext.headerMetaPrefix) === 0  ? temp[i].value.trim() : temp[i].value;
		stringToSign += key + ':' + val + '\n';
	}

	let path = opt.uri;
	if(this.isCname){
		if(path === '/'){
			path += opt.headers.Host + '/';
		}else if(path.indexOf('/') === 0){
			path = '/' + opt.headers.Host + path;
		}
	}
	if(opt.urlPath){
		let _path = opt.urlPath.slice(1);
		let arrPath = _path.split('&').sort();
		let urlPath = '';
		for(let i=0;i<arrPath.length;i++){
			let listvar = arrPath[i].split('=');
			let key = decodeURIComponent(listvar[0]);
			if(allowedResourceParameterNames.indexOf(key.toLowerCase()) >= 0){
				urlPath += urlPath === '' ?  '?' : '&';
				urlPath += key;
				if(listvar.length === 2 && listvar[1]){
					urlPath += '=' + decodeURIComponent(listvar[1]);
				}
			}
		}
		path += urlPath;
	}
	stringToSign += path;

	let logStringToSign = stringToSign;
	if (hasSecurityToken) {
		logStringToSign = logStringToSign.replace(securityToken, '*****');
	}

	if(log.isLevelEnabled('debug')){
		log.runLog('debug',methodName, 'stringToSign:' + logStringToSign);
	}
	opt.headers.Authorization = signatureContext.authPrefix + ' ' + this.ak + ':' + crypto.createHmac('sha1', this.sk).update(stringToSign).digest('base64');
};

Utils.prototype.v4Auth = function(opt, methodName, signatureContext){
	opt.headers[signatureContext.headerPrefix + 'content-sha256'] = UNSIGNED_PAYLOAD;
	let header = opt.headers;
	let log = this.log;
	let shortDate = null;
	let longDate = null;

	if(signatureContext.headerPrefix + 'date' in header){
		longDate = header[signatureContext.headerPrefix + 'date'];
		shortDate = longDate.slice(0, longDate.indexOf('T'));
	}else{
		let dates = getDates(header.Date);
		shortDate = dates[0];
		longDate = dates[1];
	}

	let credential = this.ak + '/' + shortDate + '/' + this.region + '/s3/aws4_request';

	let signedAndCanonicalHeaders = getSignedAndCanonicalHeaders(header);

	let signedHeaders = signedAndCanonicalHeaders[0];
	let canonicalHeaders = signedAndCanonicalHeaders[1];

	let canonicalQueryString = '';
	if(opt.urlPath){
		let path = opt.urlPath.slice(1);
		let arrPath = path.split('&').sort();
		for(let i=0;i<arrPath.length;i++){
			canonicalQueryString += arrPath[i];
			if(arrPath[i].indexOf('=') === -1){
				canonicalQueryString += '=';
			}
			if(i !== arrPath.length -1){
				canonicalQueryString += '&';
			}
		}
	}
	let canonicalRequest = opt.method + '\n';
	canonicalRequest += opt.uri +  '\n';
	canonicalRequest += canonicalQueryString + '\n';
	canonicalRequest +=  canonicalHeaders + '\n';
	canonicalRequest += signedHeaders + '\n';
	canonicalRequest += UNSIGNED_PAYLOAD;

	if(log.isLevelEnabled('debug')){
		log.runLog('debug',methodName, 'canonicalRequest:' + canonicalRequest);
	}
	let signature = getV4Signature(shortDate, longDate, this.sk, this.region, canonicalRequest);

	opt.headers.Authorization = 'AWS4-HMAC-SHA256 Credential=' + credential + ',SignedHeaders=' + signedHeaders + ',Signature=' + signature;
};

Utils.prototype.parseCommonHeaders = function(opt, headers, signatureContext){
	for(let key in commonHeaders){
		if ({}.hasOwnProperty.call(commonHeaders, key)) {
			opt.InterfaceResult[commonHeaders[key]] = headers[key];
		}
	}
	opt.InterfaceResult.RequestId = headers[signatureContext.headerPrefix + 'request-id'];
	opt.InterfaceResult.Id2 = headers[signatureContext.headerPrefix + 'id-2'];
	opt.CommonMsg.RequestId = opt.InterfaceResult.RequestId;
	opt.CommonMsg.Id2 = opt.InterfaceResult.Id2;
};

Utils.prototype.contrustCommonMsg = function(opt, obj, headers, methodName, signatureContext){
	opt.InterfaceResult = {};
	let log = this.log;
	this.parseCommonHeaders(opt, headers, signatureContext);

	if(log.isLevelEnabled('info')){
		log.runLog('info', methodName, 'request finished with request id:' + opt.InterfaceResult.RequestId);
	}
	for (let key in obj){
		if(obj[key].location !== 'header'){
			continue;
		}
		let sentAs = obj[key].sentAs || key;

		if(obj[key].withPrefix){
			sentAs = signatureContext.headerPrefix + sentAs;
		}

		if(obj[key].type === 'object'){
			opt.InterfaceResult[key] = parseObjectFromHeaders(sentAs, headers);
			continue;
		}
		let val = headers[sentAs];


		if(val === undefined){
			val = headers[sentAs.toLowerCase()];
		}
		if(val !== undefined){
			opt.InterfaceResult[key] = val;
		}
	}
};

Utils.prototype.getRequest = function(methodName, serverback, dstFile, saveAsStream, readable, signatureContext, retryCount, doAbort, bc, progressCallback){
	let opt = {};
	let log = this.log;
	let model = signatureContext.signature === 'obs' ? obsModel[methodName + 'Output'] : v2Model[methodName + 'Output'];
	model = model || {};
	let obj = model.parameters || {};
    let headers = serverback.headers;
	opt.CommonMsg = {
		Status : serverback.statusCode,
		Code : headers[signatureContext.headerPrefix + 'error-code'] || '',
		Message : headers[signatureContext.headerPrefix + 'error-message'] || '',
		HostId : '',
		RequestId : '',
		InterfaceResult : null,
		QosDelayTime : headers[signatureContext.headerPrefix + 'qos-delay-time'] || '',
	};
	if (this.thirdHttpLib) {
		for (let key in headers){
		    if ({}.hasOwnProperty.call(headers, key)){
		    	if (isArray(headers[key]) && headers[key].length === 1) {
		    		headers[key] = headers[key][0];
		    	}
		    }
		}
	}
	if(log.isLevelEnabled('info')){
		log.runLog('info', methodName, 'get response start, statusCode:' + serverback.statusCode);
	}
	if(log.isLevelEnabled('debug')){
		log.runLog('debug', methodName, 'response msg :statusCode:' + serverback.statusCode + ', headers:' + headerTostring(headers));
	}

	let doLog = function(){
		if(log.isLevelEnabled('debug')){
			let logMsg = 'Status:' + opt.CommonMsg.Status + ', Code:' + opt.CommonMsg.Code + ', Message:' + opt.CommonMsg.Message;
			log.runLog('debug', methodName, 'exec interface ' + methodName + ' finish, ' + logMsg);
		}
		bc(null,opt);
	};
	let that = this;

	if(serverback.statusCode >= 300 && serverback.statusCode < 400 && serverback.statusCode !== 304 && !readable && retryCount <= that.maxRetryCount){
		let location = headers.location || headers.Location;
		if(location){
			serverback.req.removeAllListeners('abort');
			serverback.req.abort();
			doAbort();
			if(log.isLevelEnabled('warn')){
				let err = 'http code is 3xx, need to redirect to ' + location;
				log.runLog('warn', methodName, err);
			}
			let redirectErr = new Error('redirect');
			redirectErr.location = location;
			return bc(redirectErr);
		}
		if(log.isLevelEnabled('error')){
			log.runLog('error', methodName, 'get redirect code 3xx, but no location in headers');
		}
	}

	if(serverback.statusCode < 300){
		let getCount = 0
		let objectTotalSize = headers['content-length']
		let writeStart = new Date().getTime();
		let progressListener = null
		if(dstFile){
			let fileDir = pathLib.dirname(dstFile);
			if(!mkdirsSync(fileDir)){
				return bc(new Error('failed to create file:' + dstFile), null);
			}
			// 下载进度回调
			if(progressCallback){
				progressListener = function(data){
					getCount += data.length;
					progressCallback(getCount, objectTotalSize, (new Date().getTime()-writeStart)/1000, data);
				};
				serverback.on('data', progressListener)
			}

			let stream = fs.createWriteStream(dstFile);
			stream.once('close', function(){
				if(opt.InterfaceResult && opt.InterfaceResult.ContentLength !== undefined && fs.existsSync(dstFile)){
					let fstat = fs.statSync(dstFile);
					if(fstat.size !== parseInt(opt.InterfaceResult.ContentLength, 10)){
						return bc(new Error('premature end of Content-Length delimiter message body (expected:' + opt.InterfaceResult.ContentLength + '; received:' + fstat.size + ')'), 'PREMATURE_END');
					}
				}
				doLog();
			}).once('error', function(err){
				if(log.isLevelEnabled('error')){
					log.runLog('error', methodName, 'get response stream error [' + headerTostring(err) + ']');
				}
				bc(err, null);
			});

			serverback.once('error', function(err){
				stream.end();
				if(log.isLevelEnabled('error')){
					log.runLog('error', methodName, 'get response stream error [' + headerTostring(err) + ']');
				}
				bc(err, null);
			}).once('end', function(){
				stream.end();
				that.contrustCommonMsg(opt, obj, headers, methodName, signatureContext);
				if(log.isLevelEnabled('debug')){
					log.runLog('debug', methodName, 'exec interface ' + methodName + ' finish, Status:' + opt['CommonMsg']['Status'] + ', Code: ,Message: ');
				}
			}).pipe(stream);
			return;
		}
		if(('data' in model) && saveAsStream){
			// 下载进度回调
			if(progressCallback){
				progressListener = function(data){
					getCount += data.length;
					progressCallback(getCount, objectTotalSize, (new Date().getTime()-writeStart)/1000, data);
				};
				serverback.on('data', progressListener)
			}
			that.contrustCommonMsg(opt, obj, headers, methodName, signatureContext);
			if(log.isLevelEnabled('debug')){
				let respMsg = 'Status: ' + opt.CommonMsg.Status + ', headers: ' +  headerTostring(headers);
				log.runLog('debug', methodName, respMsg);
			}

			for (let key in obj){
				if(obj[key].location !== 'body'){
					continue;
				}
				opt.InterfaceResult[key] = serverback;
				break;
			}
			return doLog();
		}
	}

	let body = [];
	serverback.on('data', function(data) {
		body.push(data);
	}).once('error', function(err){
		if(log.isLevelEnabled('error')){
			log.runLog('error', methodName, 'get response stream error [' + headerTostring(err) + ']');
		}
		bc(err, null);
	}).once('end', function() {
		body = Buffer.concat(body);

		if(serverback.statusCode < 300){
			if(log.isLevelEnabled('debug')){
				let respMsg = 'Status: ' + opt.CommonMsg.Status + ', headers: ' +  headerTostring(headers);
				if(body.length > 0){
					respMsg += 'body length: ' + body.length;
					log.runLog('debug', methodName, 'response body length:' + body.length);
				}
				log.runLog('debug', methodName, respMsg);
			}
			that.contrustCommonMsg(opt, obj, headers, methodName, signatureContext);

			if(body.length > 0 && ('data' in model)){
				if(model.data.type === 'xml'){
					return makeObjFromXml(body, methodName, log, function(err, result){
						if(err){
							if(log.isLevelEnabled('error')){
								log.runLog('error', methodName, 'change xml to json err [' + headerTostring(err) + ']' );
							}
							return bc(err, null);
						}
						let tempResult = result;
						if(model.data.xmlRoot && (model.data.xmlRoot in tempResult)){
							tempResult = result[model.data.xmlRoot];
						}
						let ifRootXMlDecode = tempResult.EncodingType ? true : false;
						if(isObject(tempResult)){
							for (let key in obj){
								if(obj[key].location === 'xml'){
									opt.InterfaceResult[key] = that.jsonToObject(obj, tempResult, key, ifRootXMlDecode)[key];
								}
							}
						}
						doLog();
					});
				}

				if(model.data.type === 'body'){
					for (let key in obj){
						if(obj[key].location === 'body'){
							opt.InterfaceResult[key] = body.toString('utf8');
							break;
						}
					}
				}
			}
			return doLog();
		}

		if(log.isLevelEnabled('debug')){
			let respMsg = 'Status: ' + opt.CommonMsg.Status + ', headers: ' +  headerTostring(headers);
			if(body.length > 0){
				respMsg += 'body: ' + body;
				log.runLog('debug', methodName, 'response body:' + body);
			}
			log.runLog('debug', methodName, respMsg);
		}

		opt.CommonMsg.RequestId = headers[signatureContext.headerPrefix + 'request-id'];
		opt.CommonMsg.Id2 = headers[signatureContext.headerPrefix + 'id2'];
		opt.CommonMsg.Indicator = headers['x-reserved-indicator'];
		if(log.isLevelEnabled('error')){
			log.runLog('error', methodName, 'request error with http status code:' + serverback.statusCode);
		}

		if(log.isLevelEnabled('info')){
			log.runLog('info', methodName, 'request finished with request id:' + opt.CommonMsg.RequestId);
		}

		if(body.length === 0){
			return doLog();
		}

		return makeObjFromXml(body, methodName, log, function(err, re){
			if(err){
				// XML parse failed, try JSON (for APIs like mirrorBackToSource/obscompresspolicy that return JSON errors)
				try {
					let jsonResult = JSON.parse(body.toString('utf8'));
					if(jsonResult) {
						// Support both {"error":{"code":"...","message":"..."}} and {"code":"...","message":"..."} formats
						let errObj = jsonResult.error || jsonResult;
						opt.CommonMsg.Code = errObj.code || errObj.Code || '';
						opt.CommonMsg.Message = errObj.message || errObj.Message || '';
						if(log.isLevelEnabled('error')){
							log.runLog('error', methodName, 'request error with error code:' + opt.CommonMsg.Code + ', error message:' + opt.CommonMsg.Message);
						}
						return doLog();
					}
				} catch(e) {
					// Not JSON either, fall through to original error
				}
				if(log.isLevelEnabled('error')){
					log.runLog('error', methodName, 'change xml to json err [' + headerTostring(err) + ']' );
				}
				opt.CommonMsg.Message = err.message;
			}else if(re && 'Error' in re){
				let errMsg = re.Error;
				opt.CommonMsg.Code = errMsg.Code;
				opt.CommonMsg.Message = errMsg.Message;
				opt.CommonMsg.HostId = errMsg.HostId;
				if(errMsg.RequestId){
					opt.CommonMsg.RequestId = errMsg.RequestId;
				}
				if(log.isLevelEnabled('error')){
					log.runLog('error', methodName, 'request error with error code:' + opt.CommonMsg.Code + ', error message:' + opt.CommonMsg.Message + ', request id:' + opt.CommonMsg.RequestId);
				}
			}
			doLog();
		});
	});

};

function isMatchingPattern(host, pattern) {
	const regex = new RegExp(pattern.replace(/\*/g, '.*'), 'i');
	return regex.test(host);
}

function getValidStringInKb(str) {
	const byte = new TextEncoder().encode(str).length;
	// we convert bytes to KB
	const kb = byte / 1024;
	return kb
}

function checkCustomDomainCertificateParams(params,log,methodName,opt) {
	//Validate Name
	if (!params.Name || typeof params.Name !== 'string') {
		opt.err =  !params.Name ? 'Name should be defined!' : 'Name should be string!';
		if(log.isLevelEnabled('warn')){
			log.runLog('warn', methodName, opt.err);
		}
		return opt;
	}
	if (params.Name.length < 3 || params.Name.length > 63) {
		opt.err =  'The length of the Name should be between 3 and 63!';
		if(log.isLevelEnabled('warn')){
			log.runLog('warn', methodName, opt.err);
		}
		return opt;

	}

	//Validate CertificateId
	if (params.CertificateId !== undefined) {
		if (typeof params.CertificateId !== 'string') {
			opt.err =  'CertificateId should be string!';
			if(log.isLevelEnabled('warn')){
				log.runLog('warn', methodName, opt.err);
			}
			return opt;
		}
		if (params.CertificateId.length !== 16) {
			opt.err =  'The length of the CertificateId should be exactly 16!';
			if(log.isLevelEnabled('warn')){
				log.runLog('warn', methodName, opt.err);
			}
			return opt;
		}
	}

	//Validate Certificate
	if (!params.Certificate || typeof params.Certificate !== 'string') {
		opt.err =  !params.Certificate ? 'Certificate should be defined!' : 'Certificate should be string!';
			if(log.isLevelEnabled('warn')){
				log.runLog('warn', methodName, opt.err);
			}
			return opt;
	}

	//Validate CertificateChain
	if (params.CertificateChain !== undefined) {

		if (typeof params.CertificateChain !== 'string') {
			opt.err =  'CertificateChain should be string!';
			if(log.isLevelEnabled('warn')){
				log.runLog('warn', methodName, opt.err);
			}
			return opt;
		}
	}

	//Validate PrivateKey
	if (!params.PrivateKey || typeof params.PrivateKey !== 'string') {
		opt.err = !params.PrivateKey ? 'PrivateKey should be defined!' : 'PrivateKey should be string!';
			if(log.isLevelEnabled('warn')){
				log.runLog('warn', methodName, opt.err);
			}
			return opt;
	}
}

Utils.prototype.shouldUseProxy = function(requestUrl) {
	if (this.noProxyList.length === 0) {
		return true
	}
	return !this.noProxyList.some(pattern => isMatchingPattern(requestUrl, pattern));
}

Utils.prototype.makeRequest = async function (methodName, opt, retryCount, bc) {
	if (this.is_shadow_client) {
		try {
			await this.waitForCloudAllianceGetsReady();
			await this.checkKeysExpiredAndRefresh()
		} catch (error) {
			return bc(error);
		}
	}

	let log = this.log;
	let body = opt.xml;
	let readable = body instanceof streamLib.Readable;
	let signatureContext = opt.signatureContext || this.signatureContext;
	let nowDate = new Date();
	opt.headers.Date = nowDate.toUTCString();
	delete opt.headers.Authorization;// retry bug fix

	let ex = opt.headers;
	let path = (opt.requestUri ? opt.requestUri : opt.uri) + opt.urlPath;
	let method = opt.method;

	if (methodName === customDomainCertificateMethod && opt.xml !== undefined) {
		if (getValidStringInKb(opt.xml) > 40) {
			const err =  'Total XML body of Certificate should be equal or less than 40KB!';
			if(log.isLevelEnabled('warn')){
				log.runLog('warn', methodName, err);
			}
			return bc(err);
		}
	}
	if(this.ak && this.sk && methodName !== negotiateMethod){
		if(this.securityToken){
			opt.headers[signatureContext.headerPrefix + 'security-token'] = this.securityToken;
		}
	    if(signatureContext.signature === 'v4'){
	    	this.v4Auth(opt, methodName, signatureContext);
	    }else{
	    	this.doAuth(opt, methodName, signatureContext);
	    }
	}

	ex['User-Agent'] = this.userAgent;

	if(log.isLevelEnabled('info')){
		log.runLog('info', methodName, 'prepare request parameters ok, then start to send request to service');
	}
	if(log.isLevelEnabled('debug')){
		let header_msg = {};
		for (let key in ex){
			if ({}.hasOwnProperty.call(ex, key)){
				header_msg[key] = ex[key];
			}
		}
		header_msg.Authorization = '****';

		if (header_msg[signatureContext.stsToken]) {
			header_msg[signatureContext.stsToken] = '****';
		}

		let msg = 'method:' + method + ', path:' + path + 'headers:' + headerTostring(header_msg);
		if (body && !readable) {
			msg += 'body:' + body;
		}
		log.runLog('debug', methodName, 'request msg:' + msg);
	}

	let ca = null;
	if(this.sslVerify && this.sslVerify !== true && fs.existsSync(String(this.sslVerify))){
		ca = fs.readFileSync(String(this.sslVerify));
	}

	let reopt = {
		method : method,
		host : ex.Host,
		port : opt.port || this.port,
		path : path,
		ca : ca,
		rejectUnauthorized : this.sslVerify || false,
		headers : ex,
		highWaterMark : opt.$highWaterMark || null,
	};

	if (this.verifyHostName === false) {
		reopt.checkServerIdentity = function (host, cert) {
		    return undefined; // do not verify hostname
		};
	}

	let requestPath = reopt.host + ':' + reopt.port + reopt.path;

	let start = nowDate.getTime();

	let _isSecure = opt.protocol ? opt.protocol.toLowerCase().indexOf('https') === 0 : this.isSecure;

	reopt.agent = _isSecure ? this.httpsAgent : this.httpAgent;
	if (!this.shouldUseProxy(reopt.host) && reopt.agent.proxyUri) {
		reopt.agent = null;
	}

	let _http = _isSecure ? httpsLib : httpLib;
	if (this.thirdHttpLib) {
		_http = this.thirdHttpLib;
	}
	let req = _http.request(reopt);

	if(opt.$requestHook){
		opt.$requestHook(req);
	}

	let that = this;

	let progressListener;
	let errorListener;
	let doAbort = function(){
		if(body && (body instanceof streamLib.Readable)){
			if(progressListener){
				body.removeListener('data', progressListener);
			}
			if(errorListener){
				body.removeListener('error', errorListener);
			}
			body.destroy();
		}
	};

	if (!this.thirdHttpLib) {
		req.setNoDelay(true);
		req.setTimeout(this.timeout * 1000, function () {
			doAbort();
			bc(new TimedOutError(ex.Host));
		});
	}

	req.once('response', function(serverback) {
		if(log.isLevelEnabled('info')){
			log.runLog('info', methodName, 'get http response for ' + requestPath +  ' cost ' +  (new Date().getTime() - start) + ' ms');
		}

		if(opt.$responseHook){
			opt.$responseHook(serverback);
		}
		that.getRequest(methodName, serverback, opt.dstFile, opt.SaveAsStream, readable, signatureContext, retryCount, doAbort, bc, opt.ProgressCallback);
	}).once('error', function(err){
		if(log.isLevelEnabled('error')){
			log.runLog('error', methodName, 'Send request to service error [' + headerTostring(err) + ']');
		}
		if(log.isLevelEnabled('info')){
			log.runLog('info', methodName, 'get http response for ' + requestPath + ' cost ' +  (new Date().getTime() - start) + ' ms');
		}
		if(!req.aborted){
			bc(err);
		}
	}).once('abort', function(){
		doAbort();
		bc(new Error('pause'));
	});

	if(log.isLevelEnabled('info')){
		req.once('socket', function(socket){
			if(log.isLevelEnabled('debug')){
				socket.once('connect', function(){
					log.runLog('debug', methodName, 'do http connect for ' + requestPath + ' cost ' +  (new Date().getTime() - start) + ' ms');
				}).once('lookup', function(){
					log.runLog('debug', methodName, 'dns resolve for ' + requestPath + ' cost ' +  (new Date().getTime() - start) + ' ms');
				});
			}
			log.runLog('info', methodName, 'get tcp socket for ' + requestPath + ' cost ' +  (new Date().getTime() - start) + ' ms');
		});
	}

	if(['GET', 'HEAD', 'OPTIONS'].includes(method)){
		return req.end();
	}

	let progressCallback = opt.ProgressCallback;
	let writeCount = 0;
	let writeStart = new Date().getTime();

	if(body){
		if(!readable){
			let data = String(body);
			return req.end(data, function(){
				if(progressCallback){
					progressCallback(data.length, data.length, (new Date().getTime()-writeStart)/1000, data);
				}
			});
		}

		errorListener = function(err){
			req.removeAllListeners('abort');
			req.abort();
			doAbort();
			if(log.isLevelEnabled('error')){
				log.runLog('error', methodName, 'get temporary keys from cloud alliance error [' + headerTostring(err) + ']');
			}
			bc(err);
		};

		body.once('error', errorListener);

		let contentLength = ('ContentLength' in opt) ? parseInt(opt.ContentLength, 10) : -1;

		if(contentLength > 0 && body.end === Infinity){
			body.end =  (body.start ? body.start : 0) + contentLength - 1;
		}

		if(progressCallback){
			progressListener = function(data){
				writeCount += data.length;
				progressCallback(writeCount, contentLength, (new Date().getTime()-writeStart)/1000, data);
			};
			body.on('data', progressListener);
		}

		if(opt.$pipeHook){
			return opt.$pipeHook(body, req);
		}
		return body.pipe(req);
	}

	if(!('srcFile' in opt)){
		return req.end();
	}

	let stream = null;
	let offset = opt.Offset >= 0 ? opt.Offset : 0;
	if('PartSize' in opt){
		stream = fs.createReadStream(opt.srcFile, {start:offset, end:offset + Math.max(parseInt(opt.PartSize, 10)-1, 0)});
	}else if('ContentLength' in opt){
		stream = fs.createReadStream(opt.srcFile, {start:offset, end:offset+Math.max(parseInt(opt.ContentLength, 10)-1, 0)});
	}

	if(!stream){
		stream = fs.createReadStream(opt.srcFile);
	}
	body = stream;
	if(progressCallback){
		let fileSize = fs.statSync(opt.srcFile).size;
		progressListener = function(data){
			writeCount += data.length;
			progressCallback(writeCount, fileSize, (new Date().getTime()-writeStart)/1000);
		};
		stream.on('data', progressListener);
	}
	errorListener = function(err){
		req.removeAllListeners('abort');
		req.abort();
		doAbort();
		if(log.isLevelEnabled('error')){
			log.runLog('error', methodName, 'get temporary keys from cloud alliance error [' + headerTostring(err) + ']');
		}
		bc(err);
	};

	stream.once('error', errorListener);

	if(opt.$pipeHook){
		return opt.$pipeHook(stream, req);
	}
	stream.pipe(req);
};

Utils.prototype.bufMD5 = function(buf) {
	return crypto.createHash('md5').update(buf).digest('base64');
};

Utils.prototype.fileMD5 = function (filePath, bc){
	let stream = fs.createReadStream(filePath);
	let sha = crypto.createHash('md5');
	sha.on('finish', ()=>{
		bc(null, sha.digest('base64'));
	});

	stream.on('error',function(err){
		sha.destroy();
		bc(err);
	}).on('data', function(data){
		sha.update(data);
	});
};


Utils.prototype.createSignedUrlSync = function(param){
	return this.signatureContext.signature === 'v4' ? this.createV4SignedUrlSync(param) : this.createV2SignedUrlSync(param);
};

Utils.prototype.createV2SignedUrlSync = function(param){
	param = param || {};

	let method = param.Method ? String(param.Method) : 'GET';
	let bucketName = param.Bucket ? String(param.Bucket) : null;
	let objectKey = param.Key ? String(param.Key) : null;
	let specialParam = param.SpecialParam ? String(param.SpecialParam) : null;

	if(this.signatureContext.signature === 'obs' && specialParam === 'storagePolicy'){
		specialParam = 'storageClass';
	}else if(this.signatureContext.signature === 'v2' && specialParam === 'storageClass'){
		specialParam = 'storagePolicy';
	}

	let policy = param.Policy ?  Buffer.from(String(param.Policy),'utf8').toString('base64') : null;
	let prefix = param.Prefix ? String(param.Prefix) : null;
	let expires = param.Expires ? parseInt(param.Expires, 10) : 300;
	let headers = {};
	if(param.Headers && (param.Headers instanceof Object) && !(param.Headers instanceof Array)){
		for(let key in param.Headers){
			if ({}.hasOwnProperty.call(param.Headers, key)) {
				headers[key] = param.Headers[key];
			}
		}
	}

	let queryParams = {};
	if(param.QueryParams && (param.QueryParams instanceof Object) && !(param.QueryParams instanceof Array)){
		for(let key in param.QueryParams){
			if ({}.hasOwnProperty.call(param.QueryParams, key)) {
				queryParams[key] = param.QueryParams[key];
			}
		}
	}

	if(this.securityToken && !queryParams[this.signatureContext.headerPrefix + 'security-token']){
		queryParams[this.signatureContext.headerPrefix + 'security-token'] = this.securityToken;
	}

	let isShareFolder = policy && prefix;
	let result = '';
	let resource = '';
	let host = this.server;
	if(this.isCname){
		resource += '/' + host + '/';
	}else if(bucketName){
		resource += '/' + bucketName;
		if(this.pathStyle){
			result += '/' + bucketName;
		}else{
			host = bucketName + '.' + host;
			resource += '/';
		}
	}

	headers.Host = host;

	if(objectKey){
		objectKey = encodeURIWithSafe(objectKey, '/');
		result += '/' + objectKey;
		if(resource.lastIndexOf('/') !== resource.length - 1){
			resource += '/';
		}
		resource += objectKey;
	}

	if(resource === ''){
		resource = '/';
	}

	result += '?';

	if(specialParam){
		queryParams[specialParam] = '';
	}

	if(this.signatureContext.signature === 'v2'){
		queryParams.AWSAccessKeyId = this.ak;
	}else{
		queryParams.AccessKeyId = this.ak;
	}

	if(expires < 0){
		expires = 300;
	}
	expires = parseInt(new Date().getTime() / 1000, 10) + expires;

	if (isShareFolder) {
		queryParams.Policy = policy;
		queryParams.prefix = prefix;
	} else {
		queryParams.Expires = String(expires);
	}

	let interestHeaders = {};
	for(let name in headers){
		if ({}.hasOwnProperty.call(headers, name)) {
			let key = String(name).toLowerCase();
			if(key === 'content-type' || key === 'content-md5' || key.length > this.signatureContext.headerPrefix.length && key.slice(0,this.signatureContext.headerPrefix.length) === this.signatureContext.headerPrefix){
				interestHeaders[key] = headers[name];
			}
		}
	}

	let queryParamsKeys = [];
	for(let key in queryParams){
		if ({}.hasOwnProperty.call(queryParams, key)) {
			queryParamsKeys.push(key);
		}
	}
	queryParamsKeys.sort();
	let flag = false;
	let _resource = [];
	let safeKey = isShareFolder ? '': '/';
	for(let i=0;i<queryParamsKeys.length;i++){
		let key = queryParamsKeys[i];
		let val = queryParams[key];
		key = encodeURIWithSafe(key, safeKey);
		val = encodeURIWithSafe(val, safeKey);
		result += key;
		if(val){
			result += '=' + val;
		}
		result += '&';
		if (isShareFolder && key.toLocaleLowerCase() === 'policy') {
			continue;
		}
		if(allowedResourceParameterNames.indexOf(key.toLowerCase())>=0 || key.toLowerCase().indexOf(this.signatureContext.headerPrefix) === 0){
			flag = true;
			let _val = val ? key + '=' + decodeURIComponent(val) : key;
			_resource.push(_val);
		}
	}
	_resource = _resource.join('&');
	if(flag){
		_resource = '?' + _resource;
	}
	resource += _resource;

	let stringToSign = [method];
	stringToSign.push('\n');

	if('content-md5' in interestHeaders){
		stringToSign.push(interestHeaders['content-md5']);
	}
	stringToSign.push('\n');

	if('content-type' in interestHeaders){
		stringToSign.push(interestHeaders['content-type']);
	}

	stringToSign.push('\n');
	if (isShareFolder) {
		stringToSign.push(policy);
	} else {
		stringToSign.push(String(expires));
	}

	stringToSign.push('\n');

	let temp = [];
	let i = 0;
	for(let key in interestHeaders){
		if ({}.hasOwnProperty.call(interestHeaders, key)){
			if (key.length > this.signatureContext.headerPrefix.length && key.slice(0, this.signatureContext.headerPrefix.length) === this.signatureContext.headerPrefix){
				temp[i++] = key;
			}
		}
	}
	temp = temp.sort();
	for(let j=0;j<temp.length;j++){
		stringToSign.push(temp[j]);
		stringToSign.push(':');
		stringToSign.push(interestHeaders[temp[j]]);
		stringToSign.push('\n');
	}

	if (!isShareFolder) {
		stringToSign.push(resource);
	} else {
		stringToSign.push(_resource);
	}

	let hmac = crypto.createHmac('sha1', this.sk);
	hmac.update(stringToSign.join(''));
	if (policy && prefix) {
		result += 'Signature=' + encodeURIWithSafe(hmac.digest('base64'));
	} else {
		result += 'Signature=' + encodeURIWithSafe(hmac.digest('base64'), '/');
	}

	return {
		ActualSignedRequestHeaders : headers,
		SignedUrl : (this.isSecure ? 'https' : 'http') + '://' + host + ':' + this.port + result
	};
};

Utils.prototype.createV4SignedUrlSync = function(param){
	param = param || {};

	let method = param.Method ? String(param.Method) : 'GET';
	let bucketName = param.Bucket ? String(param.Bucket) : null;
	let objectKey = param.Key ? String(param.Key) : null;
	let specialParam = param.SpecialParam ? String(param.SpecialParam) : null;

	if(specialParam === 'storageClass'){
		specialParam = 'storagePolicy';
	}

	let expires = param.Expires ? parseInt(param.Expires, 10) : 300;
	let headers = {};
	if(param.Headers && (param.Headers instanceof Object) && !(param.Headers instanceof Array)){
		for(let key in param.Headers){
			if ({}.hasOwnProperty.call(param.Headers, key)) {
				headers[key] = param.Headers[key];
			}
		}
	}

	let queryParams = {};
	if(param.QueryParams && (param.QueryParams instanceof Object) && !(param.QueryParams instanceof Array)){
		for(let key in param.QueryParams){
			if ({}.hasOwnProperty.call(param.QueryParams, key)) {
				queryParams[key] = param.QueryParams[key];
			}
		}
	}

	if(this.securityToken && !queryParams[this.signatureContext.headerPrefix + 'security-token']){
		queryParams[this.signatureContext.headerPrefix + 'security-token'] = this.securityToken;
	}

	let result = '';
	let resource = '';
	let host = this.server;
	if(bucketName){
		if(this.pathStyle){
			result += '/' + bucketName;
			resource += '/' + bucketName;
		}else{
			host = bucketName + '.' + host;
		}
	}

	if(objectKey){
		objectKey = encodeURIWithSafe(objectKey, '/');
		result += '/' + objectKey;
		resource += '/' + objectKey;
	}

	if(resource === ''){
		resource = '/';
	}

	result += '?';

	if(specialParam){
		queryParams[specialParam] = '';
	}

	if(expires < 0){
		expires = 300;
	}

	let utcDateStr = headers.date || headers.Date || new Date().toUTCString();

	let dates = getDates(utcDateStr);
	let shortDate = dates[0];
	let longDate = dates[1];

	headers.Host = host + ((this.port === 80 || this.port === 443) ? '' : ':' + this.port);


	queryParams['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
	queryParams['X-Amz-Credential'] = this.ak + '/' + shortDate + '/' + this.region + '/s3/aws4_request';
	queryParams['X-Amz-Date'] = longDate;
	queryParams['X-Amz-Expires'] = String(expires);

    let signedAndCanonicalHeaders = getSignedAndCanonicalHeaders(headers);

	queryParams['X-Amz-SignedHeaders'] = signedAndCanonicalHeaders[0];

	let _queryParams = {};
	let queryParamsKeys = [];
	for(let key in queryParams){
		if ({}.hasOwnProperty.call(queryParams, key)){
			let val = queryParams[key];
			key = encodeURIWithSafe(key, '/');
			val = encodeURIWithSafe(val);
			_queryParams[key] = val;
			queryParamsKeys.push(key);
			result += key;
			if(val){
				result += '=' + val;
			}
			result += '&';
		}
	}

	let canonicalQueryString = '';

	queryParamsKeys.sort();

	for(let i=0;i<queryParamsKeys.length;){
		canonicalQueryString += queryParamsKeys[i] + '=' + _queryParams[queryParamsKeys[i]];
		if(++i !== queryParamsKeys.length){
			canonicalQueryString += '&';
		}
	}

	let canonicalRequest = method + '\n';
	canonicalRequest += resource +  '\n';
	canonicalRequest += canonicalQueryString + '\n';
	canonicalRequest += signedAndCanonicalHeaders[1] + '\n';
	canonicalRequest += signedAndCanonicalHeaders[0] + '\n';
	canonicalRequest += UNSIGNED_PAYLOAD;

	let signature = getV4Signature(shortDate, longDate, this.sk, this.region, canonicalRequest);

	result += 'X-Amz-Signature=' + encodeURIWithSafe(signature);

	return {
		ActualSignedRequestHeaders : headers,
		SignedUrl : (this.isSecure ? 'https' : 'http') + '://' + host + ':' + this.port + result
	};

};


Utils.prototype.createPostSignatureSync = function(param){

	if(this.signatureContext.signature === 'v4'){
		return this.createV4PostSignatureSync(param);
	}

	param = param || {};
	let bucketName = param.Bucket ? String(param.Bucket) : null;
	let objectKey = param.Key ? String(param.Key) : null;
	let expires = param.Expires ? parseInt(param.Expires, 10) : 300;
	let formParams = {};

	if(param.FormParams && (param.FormParams instanceof Object) && !(param.FormParams instanceof Array)){
		for(let key in param.FormParams){
			if ({}.hasOwnProperty.call(param.FormParams, key)){
				formParams[key] = param.FormParams[key];
			}
		}
	}

	if(this.securityToken && !formParams[this.signatureContext.headerPrefix + 'security-token']){
		formParams[this.signatureContext.headerPrefix + 'security-token'] = this.securityToken;
	}

	let expireDate = new Date();
	expireDate.setTime(parseInt(new Date().getTime(), 10) + expires * 1000);
	expireDate = getExpireDate(expireDate.toUTCString());

	if(bucketName){
		formParams.bucket = bucketName;
	}

	if(objectKey){
		formParams.key = objectKey;
	}

	let policy = [];
	policy.push('{"expiration":"');
	policy.push(expireDate);
	policy.push('", "conditions":[');

	let matchAnyBucket = true;
	let matchAnyKey = true;

	let conditionAllowKeys = ['acl', 'bucket', 'key', 'success_action_redirect', 'redirect', 'success_action_status'];

	for(let key in formParams){
		if ({}.hasOwnProperty.call(formParams, key)){
			if(!key){
				continue;
			}
			let val = formParams[key];
			key = String(key).toLowerCase();

			if(key === 'bucket'){
				matchAnyBucket = false;
			}else if(key === 'key'){
				matchAnyKey = false;
			}

			if(allowedResponseHttpHeaderMetadataNames.indexOf(key) < 0 && conditionAllowKeys.indexOf(key) < 0 && key.indexOf(this.signatureContext.headerPrefix) !== 0){
				continue;
			}

			policy.push('{"');
			policy.push(key);
			policy.push('":"');
			policy.push(val !== null ? String(val) : '');
			policy.push('"},');
		}
	}


	if(matchAnyBucket){
		policy.push('["starts-with", "$bucket", ""],');
	}

	if(matchAnyKey){
		policy.push('["starts-with", "$key", ""],');
	}

	// 去除末尾的逗号
	let originPolicy = policy.join('').replace(/,$/, '') + ']}';

	policy = Buffer.from(originPolicy,'utf8').toString('base64');

	let signature = crypto.createHmac('sha1', this.sk).update(policy).digest('base64');

	return {
		OriginPolicy : originPolicy,
		Policy : policy,
		Signature : signature,
		Token : this.ak + ':' + signature + ':' + policy
	};
};


Utils.prototype.createV4PostSignatureSync = function(param){
	param = param || {};

	let bucketName = param.Bucket ? String(param.Bucket) : null;
	let objectKey = param.Key ? String(param.Key) : null;
	let expires = param.Expires ? parseInt(param.Expires, 10) : 300;
	let formParams = {};

	if(param.FormParams && (param.FormParams instanceof Object) && !(param.FormParams instanceof Array)){
		for(let key in param.FormParams){
			if ({}.hasOwnProperty.call(param.FormParams, key)) {
				formParams[key] = param.FormParams[key];
			}
		}
	}

	if(this.securityToken && !formParams[this.signatureContext.headerPrefix + 'security-token']){
		formParams[this.signatureContext.headerPrefix + 'security-token'] = this.securityToken;
	}

	let utcDateStr = new Date().toUTCString();
	let dates = getDates(utcDateStr);
	let shortDate = dates[0];
	let longDate = dates[1];

	let credential = this.ak + '/' + shortDate + '/' + this.region + '/s3/aws4_request';

	let expireDate = new Date();
	expireDate.setTime(parseInt(new Date().getTime(), 10) + expires * 1000);

	expireDate = getExpireDate(expireDate.toUTCString());

	formParams['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
	formParams['X-Amz-Date'] = longDate;
	formParams['X-Amz-Credential'] = credential;

	if(bucketName){
		formParams.bucket = bucketName;
	}

	if(objectKey){
		formParams.key = objectKey;
	}

	let policy = [];
	policy.push('{"expiration":"');
	policy.push(expireDate);
	policy.push('", "conditions":[');

	let matchAnyBucket = true;
	let matchAnyKey = true;

	let conditionAllowKeys = ['acl', 'bucket', 'key', 'success_action_redirect', 'redirect', 'success_action_status'];

	for(let key in formParams){
		if(!{}.hasOwnProperty.call(formParams, key)){
			continue;
		}
		if(!key){
			continue;
		}
		let val = formParams[key];
		key = String(key).toLowerCase();

		if(key === 'bucket'){
			matchAnyBucket = false;
		}else if(key === 'key'){
			matchAnyKey = false;
		}

		if(allowedResponseHttpHeaderMetadataNames.indexOf(key) < 0 && conditionAllowKeys.indexOf(key) < 0 && key.indexOf(this.signatureContext.headerPrefix) !== 0){
			continue;
		}

		policy.push('{"');
		policy.push(key);
		policy.push('":"');
		policy.push(val !== null ? String(val) : '');
		policy.push('"},');
	}

	if(matchAnyBucket){
		policy.push('["starts-with", "$bucket", ""],');
	}

	if(matchAnyKey){
		policy.push('["starts-with", "$key", ""],');
	}

	policy.push(']}');

	let originPolicy = policy.join('');

	policy = Buffer.from(originPolicy,'utf8').toString('base64');

	let signature = createV4Signature(shortDate, this.sk, this.region, policy);

	return {
		OriginPolicy : originPolicy,
		Policy : policy,
		Algorithm : formParams['X-Amz-Algorithm'],
		Credential : formParams['X-Amz-Credential'],
		Date : formParams['X-Amz-Date'],
		Signature : signature
	};
};

module.exports = Utils;


/***/ }),

/***/ 5755:
/***/ ((module) => {

/**
 * Copyright 2019 Huawei Technologies Co.,Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License.  You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 */

const owner = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'Owner',
	'parameters' : {
		'ID' : {
			'sentAs' : 'ID',
		},
		'Name' : {
			'sentAs' : 'DisplayName'
		}
	}
};

const initiator = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'Initiator',
	'parameters' : {
		'ID' : {
			'sentAs' : 'ID',
		},
		'Name' : {
			'sentAs' : 'DisplayName',
		},
	},
};
const commonPrefixes = {
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'CommonPrefixes',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Prefix' : {
				'decode' : true,
				'sentAs' : 'Prefix',
			},
		}
	}
};

const grants = {
	'type' : 'array',
	'location' : 'xml',
	'wrapper' : 'AccessControlList',
	'sentAs' : 'Grant',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Grantee' : {
				'data' : {
					'xsiNamespace' : 'http://www.w3.org/2001/XMLSchema-instance',
					'xsiType' : 'Type',
				},
				'type' : 'object',
				'sentAs' : 'Grantee',
				'parameters' : {
					'Type' : {
						'type' : 'ignore',
					},
					'ID' : {
						'sentAs' : 'ID',
						'notAllowEmpty' : true,
					},
					'Name' : {
						'sentAs' : 'DisplayName',
						'notAllowEmpty' : true,
					},
					'URI' : {
						'sentAs' :  'URI',
						'type' : 'adapter',
						'notAllowEmpty' : true,
					}
				},
			},
			'Permission' : {
				'sentAs' : 'Permission',
			},
		},
	},
};

const loggingEnabled = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'LoggingEnabled',
	'parameters' : {
		'TargetBucket' : {
			'sentAs' : 'TargetBucket',
		},
		'TargetPrefix' : {
			'sentAs' : 'TargetPrefix',
		},
		'TargetGrants' : {
			'type' : 'array',
			'wrapper' : 'TargetGrants',
			'sentAs' : 'Grant',
			'items' : {
				'type' : 'object',
				'parameters' : {
					'Grantee' : {
						'data' : {
							'xsiNamespace' : 'http://www.w3.org/2001/XMLSchema-instance',
							'xsiType' : 'Type',
						},
						'type' : 'object',
						'sentAs' : 'Grantee',
						'parameters' : {
							'Type' : {
								'type' : 'ignore',
							},
							'ID' : {
								'sentAs' : 'ID',
							},
							'Name' : {
								'sentAs' : 'DisplayName',
							},
							'URI' : {
								'sentAs' :  'URI',
								'type' : 'adapter'
							}
						},
					},
					'Permission' : {
						'sentAs' : 'Permission',
					},
				},
			},
		},
	},
};

const rules = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'Rule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'ID' : {
				'sentAs' : 'ID',
			},
			'Prefix' : {
				'sentAs' : 'Prefix',
			},
			'Status' : {
				'sentAs' : 'Status',
			},
			'Transitions' : {
				'type' : 'array',
				'sentAs' : 'Transition',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'StorageClass' :{
							'sentAs' : 'StorageClass',
							'type' : 'adapter'
						},
						'Date' : {
							'sentAs' : 'Date',
						},
						'Days' : {
							'type' : 'number',
							'sentAs' : 'Days'
						}
					}
				}
			},
			'Expiration' : {
				'type' : 'object',
				'sentAs' : 'Expiration',
				'parameters' : {
					'Date' : {
						'sentAs' : 'Date',
					},
					'Days' : {
						'type' : 'number',
						'sentAs' : 'Days'
					},
				},
			},
			'NoncurrentVersionTransitions' :{
				'type' : 'array',
				'sentAs' : 'NoncurrentVersionTransition',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'StorageClass' :{
							'sentAs' : 'StorageClass',
							'type' : 'adapter'
						},
						'NoncurrentDays' : {
							'type' : 'number',
							'sentAs' : 'NoncurrentDays'
						}
					}
				}
			},
			'NoncurrentVersionExpiration' : {
				'type' : 'object',
				'sentAs' : 'NoncurrentVersionExpiration',
				'parameters' : {
					'NoncurrentDays' : {
						'type' : 'number',
						'sentAs' : 'NoncurrentDays',
					},
				},
			}
		},
	},
};

const redirectAllRequestsTo = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'RedirectAllRequestsTo',
	'parameters' : {
		'HostName' : {
			'sentAs' : 'HostName',
		},
		'Protocol' : {
			'sentAs' : 'Protocol',
		},
	}
};

const routingRules = {
	'type' : 'array',
	'wrapper' : 'RoutingRules',
	'location' : 'xml',
	'sentAs' : 'RoutingRule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Condition' : {
				'type' : 'object',
				'sentAs' : 'Condition',
				'parameters' : {
					'HttpErrorCodeReturnedEquals' : {
						'sentAs' : 'HttpErrorCodeReturnedEquals',
					},
					'KeyPrefixEquals' : {
						'sentAs' : 'KeyPrefixEquals',
					},
				},
			},
			'Redirect' : {
				'type' : 'object',
				'sentAs' : 'Redirect',
				'parameters' : {
					'HostName' : {
						'sentAs' : 'HostName',
					},
					'HttpRedirectCode' : {
						'sentAs' : 'HttpRedirectCode',
					},
					'Protocol' : {
						'sentAs' : 'Protocol',
					},
					'ReplaceKeyPrefixWith' : {
						'sentAs' : 'ReplaceKeyPrefixWith',
					},
					'ReplaceKeyWith' : {
						'sentAs' : 'ReplaceKeyWith',
					}
				}
			},
		},
	},
};

const indexDocument = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'IndexDocument',
	'parameters' : {
		'Suffix' : {
			'sentAs' : 'Suffix',
		},
	}
};

const errorDocument = {
	'type' : 'object',
	'location' : 'xml',
	'sentAs' : 'ErrorDocument',
	'parameters' : {
		'Key' : {
			'sentAs' : 'Key',
		},
	}
};

const corsRule = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'CORSRule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'ID' : {
				'sentAs' : 'ID',
			},
			'AllowedMethod' : {
				'type' : 'array',
				'sentAs' : 'AllowedMethod',
				'items' : {
					'type' : 'string',
				},
			},
			'AllowedOrigin' : {
				'type' : 'array',
				'sentAs' : 'AllowedOrigin',
				'items' : {
					'type' : 'string',
				},
			},
			'AllowedHeader' : {
				'type' : 'array',
				'sentAs' : 'AllowedHeader',
				'items' : {
					'type' : 'string',
				},
			},
			'MaxAgeSeconds' : {
				'type' : 'number',
				'sentAs' : 'MaxAgeSeconds',
			},
			'ExposeHeader' : {
				'type' : 'array',
				'sentAs' : 'ExposeHeader',
				'items' : {
					'type' : 'string',
				},
			},
		},
	},
};

const functionGraphConfiguration = {
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'FunctionGraphConfiguration',
	'items' : {
		'type' : 'object',
		'location' : 'xml',
		'parameters' : {
			'ID' : {
				'sentAs' : 'Id'
			},
			'Filter' : {
				'type' : 'object',
				'parameters' : {
					'FilterRules' : {
						'wrapper' : 'S3Key',
						'type' : 'array',
						'sentAs' : 'FilterRule',
						'items' : {
							'type' : 'object',
							'parameters' : {
								'Name' : {},
								'Value' : {}
							}
						}
					}
				}
			},
			'FunctionGraph' : {},

			'Event' : {
				'type' : 'array',
				'items' : {
					'type' : 'adapter',
				}
			}
		}
	}
};

const topicConfiguration = {
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'TopicConfiguration',
	'items' : {
		'type' : 'object',
		'location' : 'xml',
		'parameters' : {
			'ID' : {
				'sentAs' : 'Id'
			},
			'Filter' : {
				'type' : 'object',
				'parameters' : {
					'FilterRules' : {
						'wrapper' : 'S3Key',
						'type' : 'array',
						'sentAs' : 'FilterRule',
						'items' : {
							'type' : 'object',
							'parameters' : {
								'Name' : {},
								'Value' : {}
							}
						}
					}
				}
			},
			'Topic' : {},

			'Event' : {
				'type' : 'array',
				'items' : {
					'type' : 'adapter',
				}
			}
		}
	}
};

const tagSet = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'wrapper' : 'TagSet',
	'sentAs' : 'Tag',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'Key' : {
				'sentAs' : 'Key',
			},
			'Value' : {
				'sentAs' : 'Value',
			}
		}
	}
};

const replicationRules = {
	'required' : true,
	'type' : 'array',
	'location' : 'xml',
	'sentAs' : 'Rule',
	'items' : {
		'type' : 'object',
		'parameters' : {
			'ID' : {
				'sentAs' : 'ID',
			},
			'Prefix' : {
				'sentAs' : 'Prefix',
			},
			'Status' : {
				'sentAs' : 'Status',
			},
			'Destination' :{
				'type' : 'object',
				'sentAs' : 'Destination',
				'parameters' :{
					'Bucket' : {
						'sentAs' : 'Bucket',
						'type' : 'adapter'
					},
					'StorageClass' :{
						'sentAs' : 'StorageClass',
						'type' : 'adapter'
					}
				}
			}
		},
	}
};

const bucketEncryptionRule = {
	'type': 'object',
	'location': 'xml',
	'sentAs': 'Rule',
	'parameters': {
		'ApplyServerSideEncryptionByDefault': {
			'type': 'object',
			'sentAs': 'ApplyServerSideEncryptionByDefault',
			'parameters': {
				'SSEAlgorithm': {
					'sentAs': 'SSEAlgorithm'
				},
				'KMSMasterKeyID': {
					'sentAs': 'KMSMasterKeyID'
				}
			}
		}
	}
};

const PublicAccessBlockBody = {
    'BlockPublicAcls' : {
        'location' : 'xml',
        'sentAs' : 'BlockPublicAcls',
    },
    'IgnorePublicAcls' : {
        'location' : 'xml',
        'sentAs' : 'IgnorePublicAcls',
    },
    'BlockPublicPolicy' : {
        'location' : 'xml',
        'sentAs' : 'BlockPublicPolicy',
    },
    'RestrictPublicBuckets' : {
        'location' : 'xml',
        'sentAs' : 'RestrictPublicBuckets',
    }
};

const CustomDomainCertificateConfig = {
	'type': 'object',
	'location': 'xml',
	'required': false,

	'sentAs': 'customDomainCertificateConfig',
	'parameters': {

		'Name': {
			'type': 'string',
			'required': true
		},
		'CertificateId': {
			'type':'string',
		},
		'Certificate': {
			'type': 'string',
			'required': true,
		},
		'CertificateChain': {
			'type': 'string',
		},
		'PrivateKey': {
			'type': 'string',
			'required': true,
		}

	}
}

const operations = {
	'CreateBucket' : {
		'httpMethod' : 'PUT',
		'data' : {
			'xmlRoot' : 'CreateBucketConfiguration',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'x-default-storage-class',
				'type' : 'adapter'
			},
			'Location' : {
				'location' : 'xml',
				'sentAs' : 'LocationConstraint'
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},

			'GrantWrite' : {
				'location' : 'header',
				'sentAs' : 'grant-write',
				'withPrefix' : true,
			},

			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},

			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},

			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},

			'AzRedundancy': {
				'location': 'header',
				'sentAs': 'x-obs-az-redundancy',
			},
			'MultiEnterprise': {
				'location': 'header',
				'sentAs': 'x-obs-az-redundancy',
			},
			'FileInterface':{
				'location' : 'header',
				'sentAs' : 'fs-file-interface',
				'withPrefix': true
			},
		}
	},

    'ListBuckets' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'QueryLocation' : {
				'location' : 'header',
				'sentAs' : 'location',
				'type' : 'boolean',
				'withPrefix' : true,
			},
			'BucketType': {
				'location': 'header',
				'sentAs': 'bucket-type',
				'withPrefix': true
			},
			'Marker' : {
				'location' : 'urlPath',
				'sentAs' : 'marker',
			},
			'MaxKeys' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-keys',
			},
		}
	},

	'ListBucketsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListAllMyBucketsResult',
		},
		'parameters' : {
			'Owner' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Owner',
				'parameters' : {
					'ID' : {
						'sentAs' : 'ID',
					},
					'Name' : {
						'sentAs' : 'DisplayName',
					},
				},
			},
			'Marker' : {
				'location' : 'xml',
				'sentAs' : 'Marker',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'NextMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextMarker',
			},
			'MaxKeys' : {
				'location' : 'xml',
				'sentAs' : 'MaxKeys',
			},
			'Buckets' : {
				'type' : 'array',
				'location' : 'xml',
				'wrapper' : 'Buckets',
				'sentAs' : 'Bucket',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'BucketName' : {
							'sentAs' : 'Name',
						},
						'CreationDate' : {
							'sentAs' : 'CreationDate'
						},
						'Location' : {
							'sentAs' : 'Location'
						},
						'BucketType' : {
							'sentAs' : 'BucketType'
						}
					},
				},
			},
		},
	},

	'HeadBucket' : {
		'httpMethod' : 'HEAD',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
		},
	},

	'HeadApiVersion' : {
		'httpMethod' : 'HEAD',
		'urlPath' : 'apiversion',
		'parameters' : {
			'Bucket' : {
				'location' : 'uri',
			},
		},
	},

	'HeadApiVersionOutput' : {
		'parameters' : {
			'ApiVersion' : {
				'location' : 'header',
				'sentAs' : 'x-obs-api'
			},
		}
	},


	'GetBucketMetadata' : {
		'httpMethod' : 'HEAD',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},

			'Origin' : {
				'location' : 'header',
				'sentAs' : 'Origin'
			},

			'RequestHeader' : {
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketMetadataOutput' : {
		'parameters' : {
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'x-default-storage-class'
			},
			'ObsVersion' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version'
			},
			'FsInterface': {
				'location': 'header',
				'sentAs': 'x-obs-fs-file-interface'
			},
			'Location' : {
				'location' : 'header',
				'sentAs' : 'bucket-region',
				'withPrefix' : true
			},
			'AzRedundancy': {
				'location': 'header',
				'sentAs': 'x-obs-az-redundancy',
			},
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin'
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age'
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers'
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods'
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers'
			},
			'MultiEnterprise': {
				'location': 'header',
				'sentAs': 'epid',
				'withPrefix' : true
			},
			'ErrorCode': {
				'location': 'header',
				'sentAs': 'x-amz-error-code'
			},
			'ErrorMessage': {
				'location': 'header',
				'sentAs': 'x-amz-error-message'
			}
		}
	},

	'DeleteBucket' : {
		'httpMethod' : 'DELETE',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'ListObjects' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Prefix' : {
				'location' : 'urlPath',
				'sentAs' : 'prefix',
			},
			'Marker' : {
				'location' : 'urlPath',
				'sentAs' : 'marker',
			},
			'MaxKeys' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-keys',
			},
			'Delimiter' : {
				'location' : 'urlPath',
				'sentAs' : 'delimiter',
			},
			'AccessKeyId': {
				'location': 'urlPath',
				'sentAs': 'AccessKeyId'
			},
			'Signature': {
				'location': 'urlPath',
				'sentAs': 'Signature'
			},
			'Policy': {
				'location': 'urlPath',
				'sentAs': 'Policy'
			},
			'SecurityToken': {
				'location': 'urlPath',
				'sentAs': 'x-amz-security-token'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type'
			},
		},
	},

	'ListObjectsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListBucketResult',
		},
		'parameters' : {
			'Location' : {
				'location' : 'header',
				'sentAs' : 'bucket-region',
				'withPrefix' : true
			},
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Name',
			},
			'Delimiter' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Delimiter',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'Prefix' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Prefix',
			},
			'Marker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Marker',
			},
			'NextMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'NextMarker',
			},
			'MaxKeys' : {
				'location' : 'xml',
				'sentAs' : 'MaxKeys',
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
			'Contents' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Contents',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
						'Size' : {
							'sentAs' : 'Size',
						},
						'StorageClass' : {
							'sentAs' : 'StorageClass',
						},
						'Type' :{
							'sentAs' : 'Type'
						},
						'Owner' : owner
					},
				},

			},
			'CommonPrefixes' : commonPrefixes
		},
	},

	'ListVersions' : {
		'httpMethod' : 'GET',
		'urlPath' : 'versions',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Prefix' : {
				'location' : 'urlPath',
				'sentAs' : 'prefix',
			},
			'KeyMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'key-marker',
			},
			'MaxKeys' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-keys',
			},
			'Delimiter' : {
				'location' : 'urlPath',
				'sentAs' : 'delimiter',
			},
			'VersionIdMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'version-id-marker',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
		},
	},
	'ListVersionsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListVersionsResult',
		},
		'parameters' : {
			'Location' : {
				'location' : 'header',
				'sentAs' : 'bucket-region',
				'withPrefix' : true
			},
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Name',
			},
			'Prefix' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Prefix',
			},
			'Delimiter' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Delimiter',
			},
			'KeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'KeyMarker',
			},
			'VersionIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'VersionIdMarker',
			},
			'NextKeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'NextKeyMarker',
			},
			'NextVersionIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextVersionIdMarker',
			},
			'MaxKeys' : {
				'location' : 'xml',
				'sentAs' : 'MaxKeys',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
			'Versions' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Version',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'IsLatest' : {
							'sentAs' : 'IsLatest',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
						'Size' : {
							'sentAs' : 'Size',
						},
						'Type' :{
							'sentAs' : 'Type'
						},
						'Owner' : owner,
						'StorageClass' : {
							'sentAs' : 'StorageClass',
						}
					}
				},
			},
			'DeleteMarkers' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'DeleteMarker',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'IsLatest' : {
							'sentAs' : 'IsLatest',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'Owner' : owner
					}
				},
			},
			'CommonPrefixes' : commonPrefixes
		},
	},

	'GetBucketLocation' : {
		'httpMethod' : 'GET',
		'urlPath' : 'location',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketLocationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CreateBucketConfiguration',
		},
		'parameters' : {
			'Location' : {
				'location' : 'xml',
				'sentAs' : 'LocationConstraint'
			},
		},
	},

	'GetBucketStorageInfo' : {
		'httpMethod' : 'GET',
		'urlPath' : 'storageinfo',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketStorageInfoOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'GetBucketStorageInfoResult',
		},
		'parameters' : {
			'Size' : {
				'location' : 'xml',
				'sentAs' : 'Size',
			},
			'ObjectNumber' : {
				'location' : 'xml',
				'sentAs' : 'ObjectNumber',
			},
		},
	},

	'SetBucketQuota' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'quota',
		'data' : {
			'xmlRoot' : 'Quota',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'StorageQuota' : {
				'required' : true,
				'location' : 'xml',
				'sentAs' : 'StorageQuota',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketQuota' : {
		'httpMethod' : 'GET',
		'urlPath' : 'quota',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}

		},
	},
	'GetBucketQuotaOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'Quota',
		},
		'parameters' : {
			'StorageQuota' : {
				'location' : 'xml',
				'sentAs' : 'StorageQuota',
			},
		},
	},

	'SetBucketAcl' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'acl',
		'data' : {
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'Owner' : owner,
			'Grants' : grants,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketAcl' : {
		'httpMethod' : 'GET',
		'urlPath' : 'acl',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketAclOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'Owner' : owner,
			'Grants' : grants
		}
	},

	'SetBucketLoggingConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'logging',
		'data' : {
			'xmlRoot' : 'BucketLoggingStatus',
			'xmlAllowEmpty' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'LoggingEnabled' : loggingEnabled,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketLoggingConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'logging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketLoggingConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'BucketLoggingStatus',
		},
		'parameters' : {
			'LoggingEnabled' : loggingEnabled,
		},
	},

	'SetBucketPolicy' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'policy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Policy' : {
				'required' : true,
				'location' : 'body',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketPolicy' : {
		'httpMethod' : 'GET',
		'urlPath' : 'policy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketPolicyOutput' : {
		'data' : {
			'type' : 'body',
		},
		'parameters' : {
			'Policy' : {
				'location' : 'body',
			},
		},
	},
	'DeleteBucketPolicy' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'policy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'SetBucketLifecycleConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'lifecycle',
		'data' : {
			'xmlRoot' : 'LifecycleConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Rules' : rules,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketLifecycleConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'lifecycle',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketLifecycleConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'LifecycleConfiguration',
		},
		'parameters' : {
			'Rules' : rules
		},
	},

	'DeleteBucketLifecycleConfiguration' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'lifecycle',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'SetBucketWebsiteConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'website',
		'data' : {
			'xmlRoot' : 'WebsiteConfiguration',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RedirectAllRequestsTo' : redirectAllRequestsTo,
			'IndexDocument' : indexDocument,
			'ErrorDocument' : errorDocument,
			'RoutingRules' : routingRules,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketWebsiteConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'website',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketWebsiteConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'WebsiteConfiguration',
		},
		'parameters' : {
			'RedirectAllRequestsTo' : redirectAllRequestsTo,
			'IndexDocument' : indexDocument,
			'ErrorDocument' : errorDocument,
			'RoutingRules' : routingRules,
		},
	},
	'DeleteBucketWebsiteConfiguration' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'website',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'SetBucketVersioningConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'versioning',
		'data' : {
			'xmlRoot' : 'VersioningConfiguration',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionStatus' : {
				'required' : true,
				'location' : 'xml',
				'sentAs' : 'Status',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'GetBucketVersioningConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'versioning',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketVersioningConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'VersioningConfiguration',
		},
		'parameters' : {
			'VersionStatus' : {
				'location' : 'xml',
				'sentAs' : 'Status',
			},
		},
	},

	'SetBucketCors' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'cors',
		'data' : {
			'xmlRoot' : 'CORSConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'CorsRules' : corsRule,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketCors' : {
		'httpMethod' : 'GET',
		'urlPath' : 'cors',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetBucketCorsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CORSConfiguration',
		},
		'parameters' : {
			'CorsRules' : corsRule
		},
	},
	'DeleteBucketCors' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'cors',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'SetBucketNotification' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'notification',
		'data' : {
			'xmlRoot' : 'NotificationConfiguration',
			'xmlAllowEmpty' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'TopicConfigurations' : topicConfiguration,
			'FunctionGraphConfigurations' : functionGraphConfiguration,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},


	'GetBucketNotification' : {
		'httpMethod' : 'GET',
		'urlPath' : 'notification',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketNotificationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'NotificationConfiguration',
		},
		'parameters' : {
			'TopicConfigurations' : topicConfiguration,
			'FunctionGraphConfigurations' : functionGraphConfiguration,
		},
	},

	'OptionsBucket' : {
		'httpMethod' : 'OPTIONS',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Origin' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'Origin',
			},
			'AccessControlRequestMethods' : {
				'required' : true,
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Method',
				'items' : {
					'type' : 'string',
				},
			},
			'AccessControlRequestHeaders' : {
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers',
				'items' : {
					'type' : 'string',
				},
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'OptionsBucketOutput' : {
		'parameters' : {
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin',
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers',
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods',
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers',
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age',
			},
		},
	},

	'SetBucketTagging' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'tagging',
		'data' : {
			'xmlRoot' : 'Tagging',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Tags' : tagSet,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketTagging' : {
		'httpMethod' : 'GET',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketTaggingOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'Tagging',
		},
		'parameters' : {
			'Tags' : tagSet
		}
	},

	'DeleteBucketTagging' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'SetBucketStoragePolicy' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'storagePolicy',
		'data' : {
			'xmlRoot' : 'StoragePolicy',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'StorageClass' :{
				'required' : true,
				'location' : 'xml',
				'type' : 'adapter',
				'sentAs' : 'DefaultStorageClass'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketStoragePolicy' :{
		'httpMethod' : 'GET',
		'urlPath' : 'storagePolicy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketStoragePolicyOutput' :{
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'StoragePolicy',
		},
		'parameters' : {
			'StorageClass' : {
				'location' : 'xml',
				'type' : 'string',
				'sentAs' : 'DefaultStorageClass'
			}
		}
	},

	'SetBucketReplication' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'replication',
		'data' : {
			'xmlRoot' : 'ReplicationConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Agency' :{
				'location' : 'xml',
				'sentAs' : 'Agency'
			},
			'Rules' : replicationRules,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketReplication' : {
		'httpMethod' : 'GET',
		'urlPath' : 'replication',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketReplicationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ReplicationConfiguration',
		},
		'parameters' : {
			'Agency' :{
				'location' : 'xml',
				'sentAs' : 'Agency'
			},
			'Rules' : replicationRules
		}
	},

	'DeleteBucketReplication' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'replication',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketRequesterPayment': {
		'httpMethod': 'GET',
		'urlPath': 'requestPayment',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},
	'GetBucketRequesterPaymentOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'RequestPaymentConfiguration'
		},
		'parameters' : {
			'Payer' : {
				'location': 'xml',
				'sentAs': 'Payer',
			}
		}
	},
	'SetBucketRequesterPayment': {
		'httpMethod' : 'PUT',
		'urlPath': 'requestPayment',
		'data' : {
			'xmlRoot' : 'RequestPaymentConfiguration'
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Payer' : {
				'location': 'xml',
				'sentAs': 'Payer'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},
	'SetBucketRequesterPaymentOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'RequestPaymentConfiguration'
		},
		'parameters' : {
			'Payer' : {
				'location': 'xml',
				'sentAs': 'Payer',
			}
		}
	},

	'PutObject' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'ContentSHA256' : {
				'location' : 'header',
				'sentAs' : 'content-sha256',
				'withPrefix' : true,
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'Offset' : {
				'type' : 'plain'
			},
			'ProgressCallback' :{
				'type' : 'plain'
			},
			'ContentLength' :{
				'location' : 'header',
				'sentAs' : 'Content-Length',
				'type' : 'plain'
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true,
			},
			'CacheControl': {
				'location': 'header',
				'sentAs': 'Cache-Control'
			},
			'ContentDisposition': {
				'location': 'header',
				'sentAs': 'Content-Disposition',
				'encodingSafe': ' ;/?:@&=+$,"'
			},
			'ContentLanguage': {
				'location': 'header',
				'sentAs': 'Content-Language'
			},
			'ContentEncoding': {
				'location': 'header',
				'sentAs': 'Content-Encoding'
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true,
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'x-obs-expires',
				'type' : 'number'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'PutObjectOutput' : {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true,
			},
			'StorageClass' :{
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true,
			}
		},
	},

	'RenameObject': {
		'httpMethod': 'POST',
		'urlPath': 'rename',
		'parameters': {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Name': {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'name',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'ModifyObject': {
		'httpMethod': 'PUT',
		'urlPath': 'modify',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Position' : {
				'location' : 'urlPath',
				'sentAs' : 'position',
				'type' : 'number'
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'Offset' : {
				'type' : 'plain'
			},

			'ProgressCallback' :{
				'type' : 'plain'
			},

			'ContentLength' :{
				'location' : 'header',
				'sentAs' : 'Content-Length',
				'type' : 'plain'
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true,
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'expires',
				'type' : 'number',
				'withPrefix' : true,
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'ModifyObjectOutput': {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true,
			},
			'VersionIdObs' : {
				'location' : 'header',
				'sentAs' : 'x-obs-version-id',
			},
			'VersionIdV2' : {
				'location' : 'header',
				'sentAs' : 'x-amz-version-id',
			},
			'StorageClass' :{
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
			},
			'StorageClassObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-storage-class',
			},
			'StorageClassV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-storage-class',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption',
			},
			'SseKmsV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption',
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseKmsKeyObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-kms-key-id',
			},
			'SseKmsKeyV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-kms-key-id',
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCObs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-algorithm',
			},
			'SseCV2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-algorithm',
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true,
			},
			'SseCKeyMd5Obs' :{
				'location' : 'header',
				'sentAs' : 'x-obs-server-side-encryption-customer-key-MD5',
			},
			'SseCKeyMd5V2' :{
				'location' : 'header',
				'sentAs' : 'x-amz-server-side-encryption-customer-key-MD5',
			}
		},
	},

	'AppendObject' : {
		'httpMethod' : 'POST',
		'urlPath' : 'append',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Position' : {
				'location' : 'urlPath',
				'sentAs' : 'position',
				'type' : 'number'
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'Offset' : {
				'type' : 'plain'
			},
			'ProgressCallback' :{
				'type' : 'plain'
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'ContentLength' :{
				'location' : 'header',
				'sentAs' : 'Content-Length',
				'type' : 'plain'
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true,
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true,
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'x-obs-expires',
				'type' : 'number'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'AppendObjectOutput' : {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'NextPosition' : {
				'location' : 'header',
				'sentAs' : 'x-obs-next-append-position',
			},
			'StorageClass' :{
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true,
			}
		},
	},

	'GetObject' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'AccessKeyId': {
				'location': 'urlPath',
			},
			'Signature': {
				'location': 'urlPath'
			},
			'Policy': {
				'location': 'urlPath'
			},
			'SecurityToken': {
				'location': 'urlPath',
				'sentAs': 'x-amz-security-token'
			},
			'ResponseCacheControl' : {
				'location' : 'urlPath',
				'sentAs' : 'response-cache-control',
			},
			'ResponseContentDisposition' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-disposition',
			},
			'ResponseContentEncoding' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-encoding',
			},
			'ResponseContentLanguage' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-language',
			},
			'ResponseContentType' : {
				'location' : 'urlPath',
				'sentAs' : 'response-content-type',
			},
			'ResponseExpires' : {
				'location' : 'urlPath',
				'sentAs' : 'response-expires',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'ImageProcess' : {
				'location' : 'urlPath',
				'sentAs' : 'x-image-process',
			},
			'IfMatch' : {
				'location' : 'header',
				'sentAs' : 'If-Match',
			},
			'IfModifiedSince' : {
				'location' : 'header',
				'sentAs' : 'If-Modified-Since',
			},
			'IfNoneMatch' : {
				'location' : 'header',
				'sentAs' : 'If-None-Match',
			},
			'IfUnmodifiedSince' : {
				'location' : 'header',
				'sentAs' : 'If-Unmodified-Since',
			},
			'Range' : {
				'location' : 'header',
				'sentAs' : 'Range',
			},
			'Origin' :{
				'location' : 'header',
				'sentAs' : 'Origin'
			},
			'RequestHeader' : {
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers'
			},
			'SaveAsFile' : {
				'type' : 'dstFile',
			},
			'SaveAsStream' : {
				'type' : 'plain'
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'ProgressCallback' :{
				'type' : 'plain'
			}
		}
	},
	'GetObjectOutput' : {
		'data' : {
			'type' : 'body'
		},
		'parameters' : {
			'Content' : {
				'location' : 'body',
			},
			'Expiration' : {
				'location' : 'header',
				'sentAs' : 'expiration',
				'withPrefix' : true
			},
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'CacheControl' : {
				'location' : 'header',
				'sentAs' : 'Cache-Control',
			},
			'ContentDisposition' : {
				'location' : 'header',
				'sentAs' : 'Content-Disposition',
			},
			'ContentEncoding' : {
				'location' : 'header',
				'sentAs' : 'Content-Encoding',
			},
			'ContentLanguage' : {
				'location' : 'header',
				'sentAs' : 'Content-Language',
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type',
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'Expires',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'ContentLength' : {
				'location' : 'header',
				'sentAs' : 'Content-Length',
			},
			'DeleteMarker' : {
				'location' : 'header',
				'sentAs' : 'delete-marker',
				'withPrefix' : true
			},
			'LastModified' : {
				'location' : 'header',
				'sentAs' : 'Last-Modified',
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true
			},
			'Restore' : {
				'location' : 'header',
				'sentAs' : 'restore',
				'withPrefix' : true
			},
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin'
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age'
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers'
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods'
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'Metadata' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'meta-',
				'withPrefix' : true
			}
		},
	},
	'CopyObject' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'CopySource' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'copy-source',
				'withPrefix' : true,
				'skipEncoding' : true,
			},
			'CopySourceIfMatch' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-match',
				'withPrefix' : true
			},
			'CopySourceIfModifiedSince' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-modified-since',
				'withPrefix' : true
			},
			'CopySourceIfNoneMatch' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-none-match',
				'withPrefix' : true
			},
			'CopySourceIfUnmodifiedSince' : {
				'location' : 'header',
				'sentAs' : 'copy-source-if-unmodified-since',
				'withPrefix' : true
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'ContentEncoding' : {
				'location' : 'header',
				'sentAs' : 'content-encoding'
			},
			'ContentLanguage' : {
				'location' : 'header',
				'sentAs' : 'content-language'
			},
			'ContentDisposition' : {
				'location' : 'header',
				'sentAs' : 'content-disposition'
			},
			'CacheControl' : {
				'location' : 'header',
				'sentAs' : 'cache-control'
			},
			'TagDirective' : {
				'location' : 'header',
				'sentAs' : 'tagging-directive',
				'withPrefix' : true,
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix' : true,
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'expires'
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true
			},
			'MetadataDirective' : {
				'location' : 'header',
				'sentAs' : 'metadata-directive',
				'withPrefix' : true
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'CopySourceSseC' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'CopySourceSseCKey' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'CopyObjectOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CopyObjectResult',
		},
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'CopySourceVersionId' : {
				'location' : 'header',
				'sentAs' : 'copy-source-version-id',
				'withPrefix' : true
			},
			'ETag' : {
				'location' : 'xml',
				'sentAs' : 'ETag',
			},
			'LastModified' : {
				'location' : 'xml',
				'sentAs' : 'LastModified',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			}
		},
	},

	'RestoreObject' : {
		'httpMethod' : 'POST',
		'urlPath' : 'restore',
		'data' : {
			'xmlRoot' : 'RestoreRequest',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'Days' : {
				'location' : 'xml',
				'sentAs' : 'Days'
			},
			'Tier' : {
				'wrapper' : 'GlacierJobParameters',
				'location' : 'xml',
				'sentAs' : 'Tier',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetObjectMetadata' : {
		'httpMethod' : 'HEAD',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'Origin' : {
				'location' : 'header',
				'sentAs' : 'Origin'
			},
			'RequestHeader' : {
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers'
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetObjectMetadataOutput' : {
		'parameters' : {
			'Expiration' : {
				'location' : 'header',
				'sentAs' : 'expiration',
				'withPrefix' : true
			},
			'LastModified' : {
				'location' : 'header',
				'sentAs' : 'Last-Modified',
			},
			'ContentLength' : {
				'location' : 'header',
				'sentAs' : 'Content-Length',
			},
			'ContentType' :{
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'CacheControl': {
				'location': 'header',
				'sentAs': 'Cache-Control'
			},
			'ContentDisposition': {
				'location': 'header',
				'sentAs': 'Content-Disposition'
			},
			'ContentLanguage': {
				'location': 'header',
				'sentAs': 'Content-Language'
			},
			'ContentEncoding': {
				'location': 'header',
				'sentAs': 'Content-Encoding'
			},
			'TaggingCount' : {
				'location' : 'header',
				'sentAs' : 'tagging-count',
				'withPrefix': true
			},
			'Expires': {
				'location': 'header',
				'sentAs': 'Expires'
			},
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true
			},
			'Restore' : {
				'location' : 'header',
				'sentAs' : 'restore',
				'withPrefix' : true
			},
			'ObjectType' :{
				'location' : 'header',
				'sentAs' : 'x-obs-object-type',
			},
			'NextPosition' :{
				'location' : 'header',
				'sentAs' : 'x-obs-next-append-position',
			},
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin'
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age'
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers'
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods'
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'Metadata' : {
				'location' : 'header',
				'type' : 'object',
				'sentAs' : 'meta-',
				'withPrefix' : true
			}
		},
	},

	 'SetObjectMetadata': {
	        'httpMethod': 'PUT',
	        'urlPath': 'metadata',
	        'parameters': {
	            'Bucket': {
	                'required': true,
	                'location': 'uri'
	            },
	            'Key': {
	                'required': true,
	                'location': 'uri'
	            },
	            'VersionId': {
	                'location': 'urlPath',
	                'sentAs': 'versionId'
	            },
	            'Origin': {
	                'location': 'header',
	                'sentAs': 'Origin'
	            },
	            'RequestHeader': {
	                'location': 'header',
	                'sentAs': 'Access-Control-Request-Headers'
	            },
	            'CacheControl': {
	                'location': 'header',
	                'sentAs': 'Cache-Control'
	            },
	            'ContentDisposition': {
	                'location': 'header',
	                'sentAs': 'Content-Disposition',
					'encodingSafe': ' ;/?:@&=+$,"'
	            },
	            'ContentLanguage': {
	                'location': 'header',
	                'sentAs': 'Content-Language'
	            },
	            'ContentEncoding': {
	            	'location': 'header',
	            	'sentAs': 'Content-Encoding'
	            },
	            'ContentType': {
	                'location': 'header',
	                'sentAs': 'Content-Type'
	            },
				'Tags' : {
					'location' : 'header',
					'sentAs' : 'tagging',
					'withPrefix': true
				},
	            'Expires': {
	                'location': 'header',
	                'sentAs': 'Expires'
	            },
	            'Metadata': {
	            	'type' : 'object',
	            	'location': 'header',
	            	'sentAs': 'meta-',
	                'withPrefix': true
	            },
	            'MetadataDirective' : {
					'location' : 'header',
					'sentAs' : 'metadata-directive',
					'withPrefix' : true
				},
	            'StorageClass': {
	                'location': 'header',
	                'sentAs': 'storage-class',
	                'withPrefix': true,
	                'type' : 'adapter',
	            },
	            'WebsiteRedirectLocation': {
	                'location': 'header',
	                'sentAs': 'website-redirect-location',
	                'withPrefix': true
	            },
				'RequestPayer': {
					'location': 'header',
					'sentAs': 'request-payer',
					'withPrefix': true
				}
	        }
	    },
	    'SetObjectMetadataOutput': {
	        'parameters': {
	            'Expires': {
	                'location': 'header',
	                'sentAs': 'Expires'
	            },
				'ContentEncoding': {
					'location': 'header',
					'sentAs': 'Content-Encoding'
				},
	            'ContentType': {
	                'location': 'header',
	                'sentAs': 'Content-Type'
	            },
	            'ContentLanguage': {
	                'location': 'header',
	                'sentAs': 'Content-Language'
	            },
	            'CacheControl': {
	                'location': 'header',
	                'sentAs': 'Cache-Control'
	            },
	            'ContentDisposition': {
	                'location': 'header',
	                'sentAs': 'Content-Disposition'
	            },
	            'WebsiteRedirectLocation': {
	                'location': 'header',
	                'sentAs': 'website-redirect-location',
	                'withPrefix': true
	            },
	            'StorageClass': {
	                'location': 'header',
	                'sentAs': 'storage-class',
	                'withPrefix': true
	            },
	            'Metadata': {
	                'location': 'header',
	                'type': 'object',
	                'sentAs': 'meta-',
	                'withPrefix': true
	            },
				'MetadataDirective': {
					'location' : 'header',
					'sentAs' : 'metadata-directive',
					'withPrefix' : true
				}
	        }
	    },

	'SetObjectAcl' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'acl',
		'data' : {
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Owner' : owner,
			'Grants' : grants,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'SetObjectAclOutput' : {
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
		},
	},
	'GetObjectAcl' : {
		'httpMethod' : 'GET',
		'urlPath' : 'acl',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'GetObjectAclOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'AccessControlPolicy',
		},
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'Owner' : owner,
			'Grants' : grants
		},
	},

	'SetObjectTagging' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'tagging',
		'data' : {
			'xmlRoot' : 'Tagging',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'Tags' : tagSet
		}
	},

	'GetObjectTagging' : {
		'httpMethod' : 'GET',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
		}
	},

	'GetObjectTaggingOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'Tagging',
		},
		'parameters' : {
			'Tags' : tagSet
		}
	},

	'DeleteObjectTagging' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'tagging',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
		}
	},

	'DeleteObject' : {
		'httpMethod' : 'DELETE',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'DeleteObjectOutput' : {
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'DeleteMarker' : {
				'location' : 'header',
				'sentAs' : 'delete-marker',
				'withPrefix' : true
			},
		},
	},
	'DeleteObjects' : {
		'httpMethod' : 'POST',
		'urlPath' : 'delete',
		'data' : {
			'xmlRoot' : 'Delete',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Quiet' : {
				'location' : 'xml',
				'sentAs' : 'Quiet',
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
			'Objects' : {
				'required' : true,
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Object',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
					},
				},
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'DeleteObjectsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'DeleteResult',
		},
		'parameters' : {
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
			'Deleteds' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Deleted',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'DeleteMarker' : {
							'sentAs' : 'DeleteMarker',
						},
						'DeleteMarkerVersionId' : {
							'sentAs' : 'DeleteMarkerVersionId',
						},
					}
				},
			},
			'Errors' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Error',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'VersionId' : {
							'sentAs' : 'VersionId',
						},
						'Code' : {
							'sentAs' : 'Code',
						},
						'Message' : {
							'sentAs' : 'Message',
						},
					}
				},
			},
		},
	},
	'InitiateMultipartUpload' : {
		'httpMethod' : 'POST',
		'urlPath' : 'uploads',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'ACL' : {
				'location' : 'header',
				'sentAs' : 'acl',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'GrantRead' : {
				'location' : 'header',
				'sentAs' : 'grant-read',
				'withPrefix' : true,
			},
			'GrantReadAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-read-acp',
				'withPrefix' : true,
			},
			'GrantWriteAcp' : {
				'location' : 'header',
				'sentAs' : 'grant-write-acp',
				'withPrefix' : true,
			},
			'GrantFullControl' : {
				'location' : 'header',
				'sentAs' : 'grant-full-control',
				'withPrefix' : true,
			},
			'StorageClass' : {
				'location' : 'header',
				'sentAs' : 'storage-class',
				'withPrefix' : true,
				'type' : 'adapter',
			},
			'Metadata' : {
				'type' : 'object',
				'location' : 'header',
				'sentAs' : 'meta-',
				'withPrefix' : true,
			},
			'CacheControl': {
				'location': 'header',
				'sentAs': 'Cache-Control'
			},
			'ContentDisposition': {
				'location': 'header',
				'sentAs': 'Content-Disposition',
				'encodingSafe': ' ;/?:@&=+$,"'
			},
			'ContentLanguage': {
				'location': 'header',
				'sentAs': 'Content-Language'
			},
			'ContentEncoding': {
				'location': 'header',
				'sentAs': 'Content-Encoding'
			},
			'WebsiteRedirectLocation' : {
				'location' : 'header',
				'sentAs' : 'website-redirect-location',
				'withPrefix' : true,
			},
			'Tags' : {
				'location' : 'header',
				'sentAs' : 'tagging',
				'withPrefix': true
			},
			'Expires' : {
				'location' : 'header',
				'sentAs' : 'x-obs-expires',
				'type' : 'number'
			},
			'ContentType' : {
				'location' : 'header',
				'sentAs' : 'Content-Type'
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
				'type' : 'adapter'
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true,
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
		},
	},
	'InitiateMultipartUploadOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'InitiateMultipartUploadResult',
		},
		'parameters' : {
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'Key' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Key',
			},
			'UploadId' : {
				'location' : 'xml',
				'sentAs' : 'UploadId',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true,
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true,
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true,
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true,
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
		},
	},
	'ListMultipartUploads' : {
		'httpMethod' : 'GET',
		'urlPath' : 'uploads',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Delimiter' : {
				'location' : 'urlPath',
				'sentAs' : 'delimiter',
			},
			'KeyMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'key-marker',
			},
			'MaxUploads' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-uploads',
			},
			'Prefix' : {
				'location' : 'urlPath',
				'sentAs' : 'prefix',
			},
			'UploadIdMarker' : {
				'location' : 'urlPath',
				'sentAs' : 'upload-id-marker',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			}
		},
	},
	'ListMultipartUploadsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListMultipartUploadsResult',
		},
		'parameters' : {
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'KeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'KeyMarker',
			},
			'UploadIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'UploadIdMarker',
			},
			'NextKeyMarker' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'NextKeyMarker',
			},
			'Prefix' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Prefix',
			},
			'Delimiter' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Delimiter',
			},
			'NextUploadIdMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextUploadIdMarker',
			},
			'MaxUploads' : {
				'location' : 'xml',
				'sentAs' : 'MaxUploads',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType'
			},
			'Uploads' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Upload',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'UploadId' : {
							'sentAs' : 'UploadId',
						},
						'Key' : {
							'decode' : true,
							'sentAs' : 'Key',
						},
						'Initiated' : {
							'sentAs' : 'Initiated',
						},
						'StorageClass' : {
							'sentAs' : 'StorageClass',
						},
						'Owner' : owner,
						'Initiator' : initiator
					},
				},
			},
			'CommonPrefixes' : commonPrefixes
		},
	},
	'UploadPart' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'PartNumber' : {
				'required' : true,
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'partNumber',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'ContentMD5' : {
				'location' : 'header',
				'sentAs' : 'Content-MD5',
			},
			'ContentSHA256' : {
				'location' : 'header',
				'sentAs' : 'content-sha256',
				'withPrefix' : true,
			},
			'Body' : {
				'location' : 'body',
			},
			'SourceFile' : {
				'type' : 'srcFile',
			},
			'Offset' : {
				'type' : 'plain'
			},
			'PartSize' : {
				'type' : 'plain'
			},
			'ProgressCallback' :{
				'type' : 'plain'
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'UploadPartOutput' : {
		'parameters' : {
			'ETag' : {
				'location' : 'header',
				'sentAs' : 'etag',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			}
		},
	},
	'ListParts' : {
		'httpMethod' : 'GET',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'MaxParts' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'max-parts',
			},
			'PartNumberMarker' : {
				'type' : 'number',
				'location' : 'urlPath',
				'sentAs' : 'part-number-marker',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
		},
	},
	'ListPartsOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListPartsResult',
		},
		'parameters' : {
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'Key' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Key',
			},
			'UploadId' : {
				'location' : 'xml',
				'sentAs' : 'UploadId',
			},
			'PartNumberMarker' : {
				'location' : 'xml',
				'sentAs' : 'PartNumberMarker',
			},
			'NextPartNumberMarker' : {
				'location' : 'xml',
				'sentAs' : 'NextPartNumberMarker',
			},
			'MaxParts' : {
				'location' : 'xml',
				'sentAs' : 'MaxParts',
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated',
			},
			'StorageClass' : {
				'location' : 'xml',
				'sentAs' : 'StorageClass',
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'EncodingType',
			},
			'Initiator':initiator,
			'Owner' : owner,
			'Parts' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Part',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'PartNumber' : {
							'sentAs' : 'PartNumber',
						},
						'LastModified' : {
							'sentAs' : 'LastModified',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
						'Size' : {
							'sentAs' : 'Size',
						},
					},
				},
			}
		},
	},
	'CopyPart' : {
		'httpMethod' : 'PUT',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'PartNumber' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'partNumber',
				'type' : 'number',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'CopySource' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'copy-source',
				'skipEncoding' : true,
				'withPrefix' : true
			},
			'CopySourceRange' : {
				'location' : 'header',
				'sentAs' : 'copy-source-range',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'CopySourceSseC' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'CopySourceSseCKey' :{
				'location' : 'header',
				'sentAs' : 'copy-source-server-side-encryption-customer-key',
				'type' : 'password',
				'withPrefix' : true
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'CopyPartOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CopyPartResult',
		},
		'parameters' : {
			'LastModified' : {
				'location' : 'xml',
				'sentAs' : 'LastModified',
			},
			'ETag' : {
				'location' : 'xml',
				'sentAs' : 'ETag',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			}
		},
	},
	'AbortMultipartUpload' : {
		'httpMethod' : 'DELETE',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},

	'CompleteMultipartUpload' : {
		'httpMethod' : 'POST',
		'data' : {
			'xmlRoot' : 'CompleteMultipartUpload',
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'UploadId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'uploadId',
			},
			'EncodingType' : {
				'location' : 'urlPath',
				'sentAs' : 'encoding-type',
			},
			'Parts' : {
				'required' : true,
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'Part',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'PartNumber' : {
							'sentAs' : 'PartNumber',
						},
						'ETag' : {
							'sentAs' : 'ETag',
						},
					},
				},
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'CompleteMultipartUploadOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'CompleteMultipartUploadResult',
		},
		'parameters' : {
			'VersionId' : {
				'location' : 'header',
				'sentAs' : 'version-id',
				'withPrefix' : true
			},
			'Location' : {
				'location' : 'xml',
				'sentAs' : 'Location',
			},
			'Bucket' : {
				'location' : 'xml',
				'sentAs' : 'Bucket',
			},
			'Key' : {
				'decode' : true,
				'location' : 'xml',
				'sentAs' : 'Key',
			},
			'ETag' : {
				'location' : 'xml',
				'sentAs' : 'ETag',
			},
			'SseKms' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption',
				'withPrefix' : true
			},
			'SseKmsKey' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-aws-kms-key-id',
				'withPrefix' : true
			},
			'SseKmsProjectId' :{
				'location' : 'header',
				'sentAs' : 'sse-kms-key-project-id',
				'withPrefix' : true
			},
			'SseC' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-algorithm',
				'withPrefix' : true
			},
			'SseCKeyMd5' :{
				'location' : 'header',
				'sentAs' : 'server-side-encryption-customer-key-MD5',
				'withPrefix' : true
			},
			'EncodingType' : {
				'location' : 'xml',
				'sentAs' : 'EncodingType',
			},
		},
	},

	'OptionsObject' : {
		'httpMethod' : 'OPTIONS',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri',
			},
			'Key' : {
				'required' : true,
				'location' : 'uri',
			},
			'Origin' : {
				'required' : true,
				'location' : 'header',
				'sentAs' : 'Origin',
			},
			'AccessControlRequestMethods' : {
				'required' : true,
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Method',
				'items' : {
					'type' : 'string',
				},
			},
			'AccessControlRequestHeaders' : {
				'type' : 'array',
				'location' : 'header',
				'sentAs' : 'Access-Control-Request-Headers',
				'items' : {
					'type' : 'string',
				},
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		},
	},
	'OptionsObjectOutput' : {
		'parameters' : {
			'AllowOrigin' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-origin',
			},
			'AllowHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-headers',
			},
			'AllowMethod' : {
				'location' : 'header',
				'sentAs' : 'access-control-allow-methods',
			},
			'ExposeHeader' : {
				'location' : 'header',
				'sentAs' : 'access-control-expose-headers',
			},
			'MaxAgeSeconds' : {
				'location' : 'header',
				'sentAs' : 'access-control-max-age',
			},
		},
	},

	'GetBucketDirectColdAccess': {
		'httpMethod': 'GET',
		'urlPath': 'directcoldaccess',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'GetBucketDirectColdAccessOutput': {
		'data': {
			'type': 'xml',
			'xmlRoot': 'DirectColdAccessConfiguration'
		},
		'parameters': {
			'Status': {
				'location': 'xml',
				'sentAs': 'Status'
			}
		}
	},

	'SetBucketDirectColdAccess': {
		'httpMethod': 'PUT',
		'urlPath': 'directcoldaccess',
		'data': {
			'xmlRoot': 'DirectColdAccessConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Status': {
				'required': true,
				'location': 'xml',
				'sentAs': 'Status'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'SetBucketDirectColdAccessOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'DirectColdAccessConfiguration'
		},
		'parameters' : {
			'Status': {
				'location': 'xml',
				'sentAs': 'Status'
			}
		}
	},

	'DeleteBucketDirectColdAccess': {
		'httpMethod': 'DELETE',
		'urlPath': 'directcoldaccess',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},

	'DeleteBucketDirectColdAccessOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'DirectColdAccessConfiguration'
		},
		'parameters' : {
			'Status': {
				'location': 'xml',
				'sentAs': 'Status'
			}
		}
	},

	'GetBucketEncryption' : {
		'httpMethod' : 'GET',
		'urlPath' : 'encryption',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},
	'GetBucketEncryptionOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Rule' : {
				'type': 'object',
				'location': 'xml',
				'sentAs': 'Rule',

				'parameters': {
					'ApplyServerSideEncryptionByDefault': {
						'type': 'object',
						'sentAs': 'ApplyServerSideEncryptionByDefault',
						'parameters': {
							'SSEAlgorithm': {
								'sentAs': 'SSEAlgorithm'
							},
							'KMSMasterKeyID': {
								'sentAs': 'KMSMasterKeyID'
							}
						}
					}
				}
			}
		}
	},
	'SetBucketEncryption': {
		'httpMethod' : 'PUT',
		'urlPath' : 'encryption',
		'data' : {
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Rule' : bucketEncryptionRule,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},
	'SetBucketEncryptionOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Rule' : bucketEncryptionRule
		}
	},
	'DeleteBucketEncryption': {
		'httpMethod': 'DELETE',
		'urlPath': 'encryption',
		'parameters': {
			'Bucket': {
				'required': true,
				'location': 'uri'
			},
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},
	'DeleteBucketEncryptionOutput': {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ServerSideEncryptionConfiguration'
		},
		'parameters' : {
			'Rule' : bucketEncryptionRule,
			'RequestPayer': {
				'location': 'header',
				'sentAs': 'request-payer',
				'withPrefix': true
			}
		}
	},
	'PutBucketPublicAccessBlock' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'publicAccessBlock',
		'data' : {
			'xmlRoot' : 'PublicAccessBlockConfiguration'
		},
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
			...PublicAccessBlockBody
		}
	},
	'GetBucketPublicAccessBlock' : {
		'httpMethod' : 'GET',
		'urlPath' : 'publicAccessBlock',
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
		}
	},
	'GetBucketPublicAccessBlockOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'PublicAccessBlockConfiguration'
		},
		"parameters": {
			...PublicAccessBlockBody
		}
	},
	'DeleteBucketPublicAccessBlock' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'publicAccessBlock',
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
		}
	},
	'GetBucketPolicyPublicStatus' : {
		'httpMethod' : 'GET',
		'urlPath' : 'policyStatus',
		"parameters": {
			'Bucket' : {
				'required' : true,
					'location' : 'uri'
			},
		}
	},
	'GetBucketPolicyPublicStatusOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'PolicyStatus'
		},
		"parameters": {
			'IsPublic' : {
				'location' : 'xml',
				'sentAs' : 'IsPublic',
			},
		}
	},
	'GetBucketPublicStatus' : {
		'httpMethod' : 'GET',
		'urlPath' : 'bucketStatus',
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
		}
	},
	'GetBucketPublicStatusOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'BucketStatus'
		},
		"parameters": {
			'IsPublic' : {
				'location' : 'xml',
				'sentAs' : 'IsPublic',
			},
		}
	},
	'SetBucketCustomDomain' : {
		'httpMethod' : 'PUT',
		// 'urlPath' : 'customdomain',
		'data' : {
			'md5' : true
		},
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location': 'uri',
			},
			'DomainName' : {
				'required': true,
				'location': 'urlPath',
				'sentAs':'customdomain'
			},
			'DomainBody':CustomDomainCertificateConfig
		}
	},
	'GetBucketCustomDomain' : {
		'httpMethod' : 'GET',
		'urlPath' : 'customdomain',
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location': 'uri',
				'type': 'string'
			},
		}
	},
	'GetBucketCustomDomainOutput': {
		'data': {
			'type': 'xml',
			'xmlRoot': 'ListBucketCustomDomainsResult'
		},
		'parameters': {
			'Domains': {
				'location': 'xml',
				'sentAs': 'Domains',
				'type': 'array',
				'items': {
					'type': 'object',
					'parameters': {
						'DomainName': {
							'sentAs': 'DomainName',
						},
						'Value': {
							'sentAs': 'CreateTime',
						},
						'CertificateId': {
							'sentAs': 'CertificateId',
						}
					},
				}
			}
		}
	},
	'DeleteBucketCustomDomain' : {
		'httpMethod' : 'DELETE',
		"parameters": {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'DomainName': {
				'required': true,
				'location': 'urlPath',
				'sentAs':'customdomain'
			}
		}
	},
	'SetBucketInventory' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'inventory',
		'data' : {
			'xmlRoot' : 'InventoryConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'InventoryId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'id'
			},
			'Id' : {
				'location' : 'xml',
				'sentAs' : 'Id'
			},
			'IsEnabled' : {
				'location' : 'xml',
				'sentAs' : 'IsEnabled'
			},
			'Filter' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Filter',
				'parameters' : {
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Destination' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Destination',
				'parameters' : {
					'Format' : {
						'sentAs' : 'Format'
					},
					'Bucket' : {
						'sentAs' : 'Bucket',
						'type' : 'adapter'
					},
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Schedule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Schedule',
				'parameters' : {
					'Frequency' : {
						'sentAs' : 'Frequency'
					}
				}
			},
			'IncludedObjectVersions' : {
				'location' : 'xml',
				'sentAs' : 'IncludedObjectVersions'
			},
			'OptionalFields' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'OptionalFields',
				'parameters' : {
					'Field' : {
						'type' : 'array',
						'sentAs' : 'Field',
						'items' : {
							'type' : 'string'
						}
					}
				}
			}
		}
	},
	'GetBucketInventory' : {
		'httpMethod' : 'GET',
		'urlPath' : 'inventory',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'InventoryId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'id'
			}
		}
	},
	'GetBucketInventoryOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'InventoryConfiguration'
		},
		'parameters' : {
			'Id' : {
				'location' : 'xml',
				'sentAs' : 'Id'
			},
			'IsEnabled' : {
				'location' : 'xml',
				'sentAs' : 'IsEnabled'
			},
			'Filter' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Filter',
				'parameters' : {
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Destination' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Destination',
				'parameters' : {
					'Format' : {
						'sentAs' : 'Format'
					},
					'Bucket' : {
						'sentAs' : 'Bucket',
						'type' : 'adapter'
					},
					'Prefix' : {
						'sentAs' : 'Prefix'
					}
				}
			},
			'Schedule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Schedule',
				'parameters' : {
					'Frequency' : {
						'sentAs' : 'Frequency'
					}
				}
			},
			'IncludedObjectVersions' : {
				'location' : 'xml',
				'sentAs' : 'IncludedObjectVersions'
			},
			'OptionalFields' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'OptionalFields',
				'parameters' : {
					'Field' : {
						'type' : 'array',
						'sentAs' : 'Field',
						'items' : {
							'type' : 'string'
						}
					}
				}
			}
		}
	},
	'ListBucketInventory' : {
		'httpMethod' : 'GET',
		'urlPath' : 'inventory',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'ListBucketInventoryOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ListInventoryConfiguration'
		},
		'parameters' : {
			'InventoryConfiguration' : {
				'type' : 'array',
				'location' : 'xml',
				'sentAs' : 'InventoryConfiguration',
				'items' : {
					'type' : 'object',
					'parameters' : {
						'Id' : {
							'location' : 'xml',
							'sentAs' : 'Id'
						},
						'IsEnabled' : {
							'location' : 'xml',
							'sentAs' : 'IsEnabled'
						},
						'Filter' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'Filter',
							'parameters' : {
								'Prefix' : {
									'sentAs' : 'Prefix'
								}
							}
						},
						'Destination' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'Destination',
							'parameters' : {
								'Format' : {
									'sentAs' : 'Format'
								},
								'Bucket' : {
									'sentAs' : 'Bucket',
									'type' : 'adapter'
								},
								'Prefix' : {
									'sentAs' : 'Prefix'
								}
							}
						},
						'Schedule' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'Schedule',
							'parameters' : {
								'Frequency' : {
									'sentAs' : 'Frequency'
								}
							}
						},
						'IncludedObjectVersions' : {
							'location' : 'xml',
							'sentAs' : 'IncludedObjectVersions'
						},
						'OptionalFields' : {
							'type' : 'object',
							'location' : 'xml',
							'sentAs' : 'OptionalFields',
							'parameters' : {
								'Field' : {
									'type' : 'array',
									'sentAs' : 'Field',
									'items' : {
										'type' : 'string'
									}
								}
							}
						}
					}
				}
			},
			'IsTruncated' : {
				'location' : 'xml',
				'sentAs' : 'IsTruncated'
			},
			'ContinuationToken' : {
				'location' : 'xml',
				'sentAs' : 'ContinuationToken'
			},
			'NextContinuationToken' : {
				'location' : 'xml',
				'sentAs' : 'NextContinuationToken'
			}
		}
	},
	'DeleteBucketInventory' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'inventory',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'InventoryId' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'id'
			}
		}
	},
	'SetObjectLockConfiguration' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'object-lock',
		'data' : {
			'xmlRoot' : 'ObjectLockConfiguration',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'ObjectLockEnabled' : {
				'location' : 'xml',
				'sentAs' : 'ObjectLockEnabled'
			},
			'Rule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Rule',
				'parameters' : {
					'DefaultRetention' : {
						'type' : 'object',
						'sentAs' : 'DefaultRetention',
						'parameters' : {
							'Mode' : {
								'sentAs' : 'Mode'
							},
							'Days' : {
								'type' : 'number',
								'sentAs' : 'Days'
							},
							'Years' : {
								'type' : 'number',
								'sentAs' : 'Years'
							}
						}
					}
				}
			}
		}
	},
	'GetObjectLockConfiguration' : {
		'httpMethod' : 'GET',
		'urlPath' : 'object-lock',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'GetObjectLockConfigurationOutput' : {
		'data' : {
			'type' : 'xml',
			'xmlRoot' : 'ObjectLockConfiguration'
		},
		'parameters' : {
			'ObjectLockEnabled' : {
				'location' : 'xml',
				'sentAs' : 'ObjectLockEnabled'
			},
			'Rule' : {
				'type' : 'object',
				'location' : 'xml',
				'sentAs' : 'Rule',
				'parameters' : {
					'DefaultRetention' : {
						'type' : 'object',
						'sentAs' : 'DefaultRetention',
						'parameters' : {
							'Mode' : {
								'sentAs' : 'Mode'
							},
							'Days' : {
								'type' : 'number',
								'sentAs' : 'Days'
							},
							'Years' : {
								'type' : 'number',
								'sentAs' : 'Years'
							}
						}
					}
				}
			}
		}
	},
	'SetObjectRetention' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'retention',
		'data' : {
			'xmlRoot' : 'Retention',
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Key' : {
				'required' : true,
				'location' : 'uri'
			},
			'VersionId' : {
				'location' : 'urlPath',
				'sentAs' : 'versionId'
			},
			'Mode' : {
				'location' : 'xml',
				'sentAs' : 'Mode'
			},
			'RetainUntilDate' : {
				'location' : 'xml',
				'sentAs' : 'RetainUntilDate'
			}
		}
	},
	'SetBucketMirrorBackToSource' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'mirrorBackToSource',
		'data' : {
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'GetBucketMirrorBackToSource' : {
		'httpMethod' : 'GET',
		'urlPath' : 'mirrorBackToSource',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'GetBucketMirrorBackToSourceOutput' : {
		'data' : {
			'type' : 'body'
		},
		'parameters' : {
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'DeleteBucketMirrorBackToSource' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'mirrorBackToSource',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'SetBucketCompressPolicy' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'obscompresspolicy',
		'data' : {
			'md5' : true
		},
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'GetBucketCompressPolicy' : {
		'httpMethod' : 'GET',
		'urlPath' : 'obscompresspolicy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'GetBucketCompressPolicyOutput' : {
		'data' : {
			'type' : 'body'
		},
		'parameters' : {
			'Rules' : {
				'location' : 'body'
			}
		}
	},
	'DeleteBucketCompressPolicy' : {
		'httpMethod' : 'DELETE',
		'urlPath' : 'obscompresspolicy',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			}
		}
	},
	'TruncateObject' : {
		'httpMethod' : 'PUT',
		'urlPath' : 'truncate',
		'parameters' : {
			'Bucket' : {
				'required' : true,
				'location' : 'uri'
			},
			'Key' : {
				'required' : true,
				'location' : 'uri'
			},
			'Length' : {
				'required' : true,
				'location' : 'urlPath',
				'sentAs' : 'length',
				'type' : 'number'
			}
		}
	}
};


module.exports = operations;

/***/ }),

/***/ 3783:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const mkdirpSync = (__nccwpck_require__(1089).mkdirsSync)
const utimesSync = (__nccwpck_require__(6934).utimesMillisSync)
const stat = __nccwpck_require__(887)

function copySync (src, dest, opts) {
  if (typeof opts === 'function') {
    opts = { filter: opts }
  }

  opts = opts || {}
  opts.clobber = 'clobber' in opts ? !!opts.clobber : true // default to true for now
  opts.overwrite = 'overwrite' in opts ? !!opts.overwrite : opts.clobber // overwrite falls back to clobber

  // Warn about using preserveTimestamps on 32-bit node
  if (opts.preserveTimestamps && process.arch === 'ia32') {
    console.warn(`fs-extra: Using the preserveTimestamps option in 32-bit node is not recommended;\n
    see https://github.com/jprichardson/node-fs-extra/issues/269`)
  }

  const { srcStat, destStat } = stat.checkPathsSync(src, dest, 'copy')
  stat.checkParentPathsSync(src, srcStat, dest, 'copy')
  return handleFilterAndCopy(destStat, src, dest, opts)
}

function handleFilterAndCopy (destStat, src, dest, opts) {
  if (opts.filter && !opts.filter(src, dest)) return
  const destParent = path.dirname(dest)
  if (!fs.existsSync(destParent)) mkdirpSync(destParent)
  return startCopy(destStat, src, dest, opts)
}

function startCopy (destStat, src, dest, opts) {
  if (opts.filter && !opts.filter(src, dest)) return
  return getStats(destStat, src, dest, opts)
}

function getStats (destStat, src, dest, opts) {
  const statSync = opts.dereference ? fs.statSync : fs.lstatSync
  const srcStat = statSync(src)

  if (srcStat.isDirectory()) return onDir(srcStat, destStat, src, dest, opts)
  else if (srcStat.isFile() ||
           srcStat.isCharacterDevice() ||
           srcStat.isBlockDevice()) return onFile(srcStat, destStat, src, dest, opts)
  else if (srcStat.isSymbolicLink()) return onLink(destStat, src, dest, opts)
}

function onFile (srcStat, destStat, src, dest, opts) {
  if (!destStat) return copyFile(srcStat, src, dest, opts)
  return mayCopyFile(srcStat, src, dest, opts)
}

function mayCopyFile (srcStat, src, dest, opts) {
  if (opts.overwrite) {
    fs.unlinkSync(dest)
    return copyFile(srcStat, src, dest, opts)
  } else if (opts.errorOnExist) {
    throw new Error(`'${dest}' already exists`)
  }
}

function copyFile (srcStat, src, dest, opts) {
  if (typeof fs.copyFileSync === 'function') {
    fs.copyFileSync(src, dest)
    fs.chmodSync(dest, srcStat.mode)
    if (opts.preserveTimestamps) {
      return utimesSync(dest, srcStat.atime, srcStat.mtime)
    }
    return
  }
  return copyFileFallback(srcStat, src, dest, opts)
}

function copyFileFallback (srcStat, src, dest, opts) {
  const BUF_LENGTH = 64 * 1024
  const _buff = __nccwpck_require__(9635)(BUF_LENGTH)

  const fdr = fs.openSync(src, 'r')
  const fdw = fs.openSync(dest, 'w', srcStat.mode)
  let pos = 0

  while (pos < srcStat.size) {
    const bytesRead = fs.readSync(fdr, _buff, 0, BUF_LENGTH, pos)
    fs.writeSync(fdw, _buff, 0, bytesRead)
    pos += bytesRead
  }

  if (opts.preserveTimestamps) fs.futimesSync(fdw, srcStat.atime, srcStat.mtime)

  fs.closeSync(fdr)
  fs.closeSync(fdw)
}

function onDir (srcStat, destStat, src, dest, opts) {
  if (!destStat) return mkDirAndCopy(srcStat, src, dest, opts)
  if (destStat && !destStat.isDirectory()) {
    throw new Error(`Cannot overwrite non-directory '${dest}' with directory '${src}'.`)
  }
  return copyDir(src, dest, opts)
}

function mkDirAndCopy (srcStat, src, dest, opts) {
  fs.mkdirSync(dest)
  copyDir(src, dest, opts)
  return fs.chmodSync(dest, srcStat.mode)
}

function copyDir (src, dest, opts) {
  fs.readdirSync(src).forEach(item => copyDirItem(item, src, dest, opts))
}

function copyDirItem (item, src, dest, opts) {
  const srcItem = path.join(src, item)
  const destItem = path.join(dest, item)
  const { destStat } = stat.checkPathsSync(srcItem, destItem, 'copy')
  return startCopy(destStat, srcItem, destItem, opts)
}

function onLink (destStat, src, dest, opts) {
  let resolvedSrc = fs.readlinkSync(src)
  if (opts.dereference) {
    resolvedSrc = path.resolve(process.cwd(), resolvedSrc)
  }

  if (!destStat) {
    return fs.symlinkSync(resolvedSrc, dest)
  } else {
    let resolvedDest
    try {
      resolvedDest = fs.readlinkSync(dest)
    } catch (err) {
      // dest exists and is a regular file or directory,
      // Windows may throw UNKNOWN error. If dest already exists,
      // fs throws error anyway, so no need to guard against it here.
      if (err.code === 'EINVAL' || err.code === 'UNKNOWN') return fs.symlinkSync(resolvedSrc, dest)
      throw err
    }
    if (opts.dereference) {
      resolvedDest = path.resolve(process.cwd(), resolvedDest)
    }
    if (stat.isSrcSubdir(resolvedSrc, resolvedDest)) {
      throw new Error(`Cannot copy '${resolvedSrc}' to a subdirectory of itself, '${resolvedDest}'.`)
    }

    // prevent copy if src is a subdir of dest since unlinking
    // dest in this case would result in removing src contents
    // and therefore a broken symlink would be created.
    if (fs.statSync(dest).isDirectory() && stat.isSrcSubdir(resolvedDest, resolvedSrc)) {
      throw new Error(`Cannot overwrite '${resolvedDest}' with '${resolvedSrc}'.`)
    }
    return copyLink(resolvedSrc, dest)
  }
}

function copyLink (resolvedSrc, dest) {
  fs.unlinkSync(dest)
  return fs.symlinkSync(resolvedSrc, dest)
}

module.exports = copySync


/***/ }),

/***/ 1364:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


module.exports = {
  copySync: __nccwpck_require__(3783)
}


/***/ }),

/***/ 1759:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const mkdirp = (__nccwpck_require__(1089).mkdirs)
const pathExists = (__nccwpck_require__(2881).pathExists)
const utimes = (__nccwpck_require__(6934).utimesMillis)
const stat = __nccwpck_require__(887)

function copy (src, dest, opts, cb) {
  if (typeof opts === 'function' && !cb) {
    cb = opts
    opts = {}
  } else if (typeof opts === 'function') {
    opts = { filter: opts }
  }

  cb = cb || function () {}
  opts = opts || {}

  opts.clobber = 'clobber' in opts ? !!opts.clobber : true // default to true for now
  opts.overwrite = 'overwrite' in opts ? !!opts.overwrite : opts.clobber // overwrite falls back to clobber

  // Warn about using preserveTimestamps on 32-bit node
  if (opts.preserveTimestamps && process.arch === 'ia32') {
    console.warn(`fs-extra: Using the preserveTimestamps option in 32-bit node is not recommended;\n
    see https://github.com/jprichardson/node-fs-extra/issues/269`)
  }

  stat.checkPaths(src, dest, 'copy', (err, stats) => {
    if (err) return cb(err)
    const { srcStat, destStat } = stats
    stat.checkParentPaths(src, srcStat, dest, 'copy', err => {
      if (err) return cb(err)
      if (opts.filter) return handleFilter(checkParentDir, destStat, src, dest, opts, cb)
      return checkParentDir(destStat, src, dest, opts, cb)
    })
  })
}

function checkParentDir (destStat, src, dest, opts, cb) {
  const destParent = path.dirname(dest)
  pathExists(destParent, (err, dirExists) => {
    if (err) return cb(err)
    if (dirExists) return startCopy(destStat, src, dest, opts, cb)
    mkdirp(destParent, err => {
      if (err) return cb(err)
      return startCopy(destStat, src, dest, opts, cb)
    })
  })
}

function handleFilter (onInclude, destStat, src, dest, opts, cb) {
  Promise.resolve(opts.filter(src, dest)).then(include => {
    if (include) return onInclude(destStat, src, dest, opts, cb)
    return cb()
  }, error => cb(error))
}

function startCopy (destStat, src, dest, opts, cb) {
  if (opts.filter) return handleFilter(getStats, destStat, src, dest, opts, cb)
  return getStats(destStat, src, dest, opts, cb)
}

function getStats (destStat, src, dest, opts, cb) {
  const stat = opts.dereference ? fs.stat : fs.lstat
  stat(src, (err, srcStat) => {
    if (err) return cb(err)

    if (srcStat.isDirectory()) return onDir(srcStat, destStat, src, dest, opts, cb)
    else if (srcStat.isFile() ||
             srcStat.isCharacterDevice() ||
             srcStat.isBlockDevice()) return onFile(srcStat, destStat, src, dest, opts, cb)
    else if (srcStat.isSymbolicLink()) return onLink(destStat, src, dest, opts, cb)
  })
}

function onFile (srcStat, destStat, src, dest, opts, cb) {
  if (!destStat) return copyFile(srcStat, src, dest, opts, cb)
  return mayCopyFile(srcStat, src, dest, opts, cb)
}

function mayCopyFile (srcStat, src, dest, opts, cb) {
  if (opts.overwrite) {
    fs.unlink(dest, err => {
      if (err) return cb(err)
      return copyFile(srcStat, src, dest, opts, cb)
    })
  } else if (opts.errorOnExist) {
    return cb(new Error(`'${dest}' already exists`))
  } else return cb()
}

function copyFile (srcStat, src, dest, opts, cb) {
  if (typeof fs.copyFile === 'function') {
    return fs.copyFile(src, dest, err => {
      if (err) return cb(err)
      return setDestModeAndTimestamps(srcStat, dest, opts, cb)
    })
  }
  return copyFileFallback(srcStat, src, dest, opts, cb)
}

function copyFileFallback (srcStat, src, dest, opts, cb) {
  const rs = fs.createReadStream(src)
  rs.on('error', err => cb(err)).once('open', () => {
    const ws = fs.createWriteStream(dest, { mode: srcStat.mode })
    ws.on('error', err => cb(err))
      .on('open', () => rs.pipe(ws))
      .once('close', () => setDestModeAndTimestamps(srcStat, dest, opts, cb))
  })
}

function setDestModeAndTimestamps (srcStat, dest, opts, cb) {
  fs.chmod(dest, srcStat.mode, err => {
    if (err) return cb(err)
    if (opts.preserveTimestamps) {
      return utimes(dest, srcStat.atime, srcStat.mtime, cb)
    }
    return cb()
  })
}

function onDir (srcStat, destStat, src, dest, opts, cb) {
  if (!destStat) return mkDirAndCopy(srcStat, src, dest, opts, cb)
  if (destStat && !destStat.isDirectory()) {
    return cb(new Error(`Cannot overwrite non-directory '${dest}' with directory '${src}'.`))
  }
  return copyDir(src, dest, opts, cb)
}

function mkDirAndCopy (srcStat, src, dest, opts, cb) {
  fs.mkdir(dest, err => {
    if (err) return cb(err)
    copyDir(src, dest, opts, err => {
      if (err) return cb(err)
      return fs.chmod(dest, srcStat.mode, cb)
    })
  })
}

function copyDir (src, dest, opts, cb) {
  fs.readdir(src, (err, items) => {
    if (err) return cb(err)
    return copyDirItems(items, src, dest, opts, cb)
  })
}

function copyDirItems (items, src, dest, opts, cb) {
  const item = items.pop()
  if (!item) return cb()
  return copyDirItem(items, item, src, dest, opts, cb)
}

function copyDirItem (items, item, src, dest, opts, cb) {
  const srcItem = path.join(src, item)
  const destItem = path.join(dest, item)
  stat.checkPaths(srcItem, destItem, 'copy', (err, stats) => {
    if (err) return cb(err)
    const { destStat } = stats
    startCopy(destStat, srcItem, destItem, opts, err => {
      if (err) return cb(err)
      return copyDirItems(items, src, dest, opts, cb)
    })
  })
}

function onLink (destStat, src, dest, opts, cb) {
  fs.readlink(src, (err, resolvedSrc) => {
    if (err) return cb(err)
    if (opts.dereference) {
      resolvedSrc = path.resolve(process.cwd(), resolvedSrc)
    }

    if (!destStat) {
      return fs.symlink(resolvedSrc, dest, cb)
    } else {
      fs.readlink(dest, (err, resolvedDest) => {
        if (err) {
          // dest exists and is a regular file or directory,
          // Windows may throw UNKNOWN error. If dest already exists,
          // fs throws error anyway, so no need to guard against it here.
          if (err.code === 'EINVAL' || err.code === 'UNKNOWN') return fs.symlink(resolvedSrc, dest, cb)
          return cb(err)
        }
        if (opts.dereference) {
          resolvedDest = path.resolve(process.cwd(), resolvedDest)
        }
        if (stat.isSrcSubdir(resolvedSrc, resolvedDest)) {
          return cb(new Error(`Cannot copy '${resolvedSrc}' to a subdirectory of itself, '${resolvedDest}'.`))
        }

        // do not copy if src is a subdir of dest since unlinking
        // dest in this case would result in removing src contents
        // and therefore a broken symlink would be created.
        if (destStat.isDirectory() && stat.isSrcSubdir(resolvedDest, resolvedSrc)) {
          return cb(new Error(`Cannot overwrite '${resolvedDest}' with '${resolvedSrc}'.`))
        }
        return copyLink(resolvedSrc, dest, cb)
      })
    }
  })
}

function copyLink (resolvedSrc, dest, cb) {
  fs.unlink(dest, err => {
    if (err) return cb(err)
    return fs.symlink(resolvedSrc, dest, cb)
  })
}

module.exports = copy


/***/ }),

/***/ 5796:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
module.exports = {
  copy: u(__nccwpck_require__(1759))
}


/***/ }),

/***/ 7882:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const mkdir = __nccwpck_require__(1089)
const remove = __nccwpck_require__(6205)

const emptyDir = u(function emptyDir (dir, callback) {
  callback = callback || function () {}
  fs.readdir(dir, (err, items) => {
    if (err) return mkdir.mkdirs(dir, callback)

    items = items.map(item => path.join(dir, item))

    deleteItem()

    function deleteItem () {
      const item = items.pop()
      if (!item) return callback()
      remove.remove(item, err => {
        if (err) return callback(err)
        deleteItem()
      })
    }
  })
})

function emptyDirSync (dir) {
  let items
  try {
    items = fs.readdirSync(dir)
  } catch (err) {
    return mkdir.mkdirsSync(dir)
  }

  items.forEach(item => {
    item = path.join(dir, item)
    remove.removeSync(item)
  })
}

module.exports = {
  emptyDirSync,
  emptydirSync: emptyDirSync,
  emptyDir,
  emptydir: emptyDir
}


/***/ }),

/***/ 3529:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const path = __nccwpck_require__(6928)
const fs = __nccwpck_require__(5744)
const mkdir = __nccwpck_require__(1089)
const pathExists = (__nccwpck_require__(2881).pathExists)

function createFile (file, callback) {
  function makeFile () {
    fs.writeFile(file, '', err => {
      if (err) return callback(err)
      callback()
    })
  }

  fs.stat(file, (err, stats) => { // eslint-disable-line handle-callback-err
    if (!err && stats.isFile()) return callback()
    const dir = path.dirname(file)
    pathExists(dir, (err, dirExists) => {
      if (err) return callback(err)
      if (dirExists) return makeFile()
      mkdir.mkdirs(dir, err => {
        if (err) return callback(err)
        makeFile()
      })
    })
  })
}

function createFileSync (file) {
  let stats
  try {
    stats = fs.statSync(file)
  } catch (e) {}
  if (stats && stats.isFile()) return

  const dir = path.dirname(file)
  if (!fs.existsSync(dir)) {
    mkdir.mkdirsSync(dir)
  }

  fs.writeFileSync(file, '')
}

module.exports = {
  createFile: u(createFile),
  createFileSync
}


/***/ }),

/***/ 5779:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const file = __nccwpck_require__(3529)
const link = __nccwpck_require__(8751)
const symlink = __nccwpck_require__(4896)

module.exports = {
  // file
  createFile: file.createFile,
  createFileSync: file.createFileSync,
  ensureFile: file.createFile,
  ensureFileSync: file.createFileSync,
  // link
  createLink: link.createLink,
  createLinkSync: link.createLinkSync,
  ensureLink: link.createLink,
  ensureLinkSync: link.createLinkSync,
  // symlink
  createSymlink: symlink.createSymlink,
  createSymlinkSync: symlink.createSymlinkSync,
  ensureSymlink: symlink.createSymlink,
  ensureSymlinkSync: symlink.createSymlinkSync
}


/***/ }),

/***/ 8751:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const path = __nccwpck_require__(6928)
const fs = __nccwpck_require__(5744)
const mkdir = __nccwpck_require__(1089)
const pathExists = (__nccwpck_require__(2881).pathExists)

function createLink (srcpath, dstpath, callback) {
  function makeLink (srcpath, dstpath) {
    fs.link(srcpath, dstpath, err => {
      if (err) return callback(err)
      callback(null)
    })
  }

  pathExists(dstpath, (err, destinationExists) => {
    if (err) return callback(err)
    if (destinationExists) return callback(null)
    fs.lstat(srcpath, (err) => {
      if (err) {
        err.message = err.message.replace('lstat', 'ensureLink')
        return callback(err)
      }

      const dir = path.dirname(dstpath)
      pathExists(dir, (err, dirExists) => {
        if (err) return callback(err)
        if (dirExists) return makeLink(srcpath, dstpath)
        mkdir.mkdirs(dir, err => {
          if (err) return callback(err)
          makeLink(srcpath, dstpath)
        })
      })
    })
  })
}

function createLinkSync (srcpath, dstpath) {
  const destinationExists = fs.existsSync(dstpath)
  if (destinationExists) return undefined

  try {
    fs.lstatSync(srcpath)
  } catch (err) {
    err.message = err.message.replace('lstat', 'ensureLink')
    throw err
  }

  const dir = path.dirname(dstpath)
  const dirExists = fs.existsSync(dir)
  if (dirExists) return fs.linkSync(srcpath, dstpath)
  mkdir.mkdirsSync(dir)

  return fs.linkSync(srcpath, dstpath)
}

module.exports = {
  createLink: u(createLink),
  createLinkSync
}


/***/ }),

/***/ 3121:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const path = __nccwpck_require__(6928)
const fs = __nccwpck_require__(5744)
const pathExists = (__nccwpck_require__(2881).pathExists)

/**
 * Function that returns two types of paths, one relative to symlink, and one
 * relative to the current working directory. Checks if path is absolute or
 * relative. If the path is relative, this function checks if the path is
 * relative to symlink or relative to current working directory. This is an
 * initiative to find a smarter `srcpath` to supply when building symlinks.
 * This allows you to determine which path to use out of one of three possible
 * types of source paths. The first is an absolute path. This is detected by
 * `path.isAbsolute()`. When an absolute path is provided, it is checked to
 * see if it exists. If it does it's used, if not an error is returned
 * (callback)/ thrown (sync). The other two options for `srcpath` are a
 * relative url. By default Node's `fs.symlink` works by creating a symlink
 * using `dstpath` and expects the `srcpath` to be relative to the newly
 * created symlink. If you provide a `srcpath` that does not exist on the file
 * system it results in a broken symlink. To minimize this, the function
 * checks to see if the 'relative to symlink' source file exists, and if it
 * does it will use it. If it does not, it checks if there's a file that
 * exists that is relative to the current working directory, if does its used.
 * This preserves the expectations of the original fs.symlink spec and adds
 * the ability to pass in `relative to current working direcotry` paths.
 */

function symlinkPaths (srcpath, dstpath, callback) {
  if (path.isAbsolute(srcpath)) {
    return fs.lstat(srcpath, (err) => {
      if (err) {
        err.message = err.message.replace('lstat', 'ensureSymlink')
        return callback(err)
      }
      return callback(null, {
        'toCwd': srcpath,
        'toDst': srcpath
      })
    })
  } else {
    const dstdir = path.dirname(dstpath)
    const relativeToDst = path.join(dstdir, srcpath)
    return pathExists(relativeToDst, (err, exists) => {
      if (err) return callback(err)
      if (exists) {
        return callback(null, {
          'toCwd': relativeToDst,
          'toDst': srcpath
        })
      } else {
        return fs.lstat(srcpath, (err) => {
          if (err) {
            err.message = err.message.replace('lstat', 'ensureSymlink')
            return callback(err)
          }
          return callback(null, {
            'toCwd': srcpath,
            'toDst': path.relative(dstdir, srcpath)
          })
        })
      }
    })
  }
}

function symlinkPathsSync (srcpath, dstpath) {
  let exists
  if (path.isAbsolute(srcpath)) {
    exists = fs.existsSync(srcpath)
    if (!exists) throw new Error('absolute srcpath does not exist')
    return {
      'toCwd': srcpath,
      'toDst': srcpath
    }
  } else {
    const dstdir = path.dirname(dstpath)
    const relativeToDst = path.join(dstdir, srcpath)
    exists = fs.existsSync(relativeToDst)
    if (exists) {
      return {
        'toCwd': relativeToDst,
        'toDst': srcpath
      }
    } else {
      exists = fs.existsSync(srcpath)
      if (!exists) throw new Error('relative srcpath does not exist')
      return {
        'toCwd': srcpath,
        'toDst': path.relative(dstdir, srcpath)
      }
    }
  }
}

module.exports = {
  symlinkPaths,
  symlinkPathsSync
}


/***/ }),

/***/ 7045:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)

function symlinkType (srcpath, type, callback) {
  callback = (typeof type === 'function') ? type : callback
  type = (typeof type === 'function') ? false : type
  if (type) return callback(null, type)
  fs.lstat(srcpath, (err, stats) => {
    if (err) return callback(null, 'file')
    type = (stats && stats.isDirectory()) ? 'dir' : 'file'
    callback(null, type)
  })
}

function symlinkTypeSync (srcpath, type) {
  let stats

  if (type) return type
  try {
    stats = fs.lstatSync(srcpath)
  } catch (e) {
    return 'file'
  }
  return (stats && stats.isDirectory()) ? 'dir' : 'file'
}

module.exports = {
  symlinkType,
  symlinkTypeSync
}


/***/ }),

/***/ 4896:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const path = __nccwpck_require__(6928)
const fs = __nccwpck_require__(5744)
const _mkdirs = __nccwpck_require__(1089)
const mkdirs = _mkdirs.mkdirs
const mkdirsSync = _mkdirs.mkdirsSync

const _symlinkPaths = __nccwpck_require__(3121)
const symlinkPaths = _symlinkPaths.symlinkPaths
const symlinkPathsSync = _symlinkPaths.symlinkPathsSync

const _symlinkType = __nccwpck_require__(7045)
const symlinkType = _symlinkType.symlinkType
const symlinkTypeSync = _symlinkType.symlinkTypeSync

const pathExists = (__nccwpck_require__(2881).pathExists)

function createSymlink (srcpath, dstpath, type, callback) {
  callback = (typeof type === 'function') ? type : callback
  type = (typeof type === 'function') ? false : type

  pathExists(dstpath, (err, destinationExists) => {
    if (err) return callback(err)
    if (destinationExists) return callback(null)
    symlinkPaths(srcpath, dstpath, (err, relative) => {
      if (err) return callback(err)
      srcpath = relative.toDst
      symlinkType(relative.toCwd, type, (err, type) => {
        if (err) return callback(err)
        const dir = path.dirname(dstpath)
        pathExists(dir, (err, dirExists) => {
          if (err) return callback(err)
          if (dirExists) return fs.symlink(srcpath, dstpath, type, callback)
          mkdirs(dir, err => {
            if (err) return callback(err)
            fs.symlink(srcpath, dstpath, type, callback)
          })
        })
      })
    })
  })
}

function createSymlinkSync (srcpath, dstpath, type) {
  const destinationExists = fs.existsSync(dstpath)
  if (destinationExists) return undefined

  const relative = symlinkPathsSync(srcpath, dstpath)
  srcpath = relative.toDst
  type = symlinkTypeSync(relative.toCwd, type)
  const dir = path.dirname(dstpath)
  const exists = fs.existsSync(dir)
  if (exists) return fs.symlinkSync(srcpath, dstpath, type)
  mkdirsSync(dir)
  return fs.symlinkSync(srcpath, dstpath, type)
}

module.exports = {
  createSymlink: u(createSymlink),
  createSymlinkSync
}


/***/ }),

/***/ 3506:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

"use strict";

// This is adapted from https://github.com/normalize/mz
// Copyright (c) 2014-2016 Jonathan Ong me@jongleberry.com and Contributors
const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const fs = __nccwpck_require__(5744)

const api = [
  'access',
  'appendFile',
  'chmod',
  'chown',
  'close',
  'copyFile',
  'fchmod',
  'fchown',
  'fdatasync',
  'fstat',
  'fsync',
  'ftruncate',
  'futimes',
  'lchown',
  'lchmod',
  'link',
  'lstat',
  'mkdir',
  'mkdtemp',
  'open',
  'readFile',
  'readdir',
  'readlink',
  'realpath',
  'rename',
  'rmdir',
  'stat',
  'symlink',
  'truncate',
  'unlink',
  'utimes',
  'writeFile'
].filter(key => {
  // Some commands are not available on some systems. Ex:
  // fs.copyFile was added in Node.js v8.5.0
  // fs.mkdtemp was added in Node.js v5.10.0
  // fs.lchown is not available on at least some Linux
  return typeof fs[key] === 'function'
})

// Export all keys:
Object.keys(fs).forEach(key => {
  if (key === 'promises') {
    // fs.promises is a getter property that triggers ExperimentalWarning
    // Don't re-export it here, the getter is defined in "lib/index.js"
    return
  }
  exports[key] = fs[key]
})

// Universalify async methods:
api.forEach(method => {
  exports[method] = u(fs[method])
})

// We differ from mz/fs in that we still ship the old, broken, fs.exists()
// since we are a drop-in replacement for the native module
exports.exists = function (filename, callback) {
  if (typeof callback === 'function') {
    return fs.exists(filename, callback)
  }
  return new Promise(resolve => {
    return fs.exists(filename, resolve)
  })
}

// fs.read() & fs.write need special treatment due to multiple callback args

exports.read = function (fd, buffer, offset, length, position, callback) {
  if (typeof callback === 'function') {
    return fs.read(fd, buffer, offset, length, position, callback)
  }
  return new Promise((resolve, reject) => {
    fs.read(fd, buffer, offset, length, position, (err, bytesRead, buffer) => {
      if (err) return reject(err)
      resolve({ bytesRead, buffer })
    })
  })
}

// Function signature can be
// fs.write(fd, buffer[, offset[, length[, position]]], callback)
// OR
// fs.write(fd, string[, position[, encoding]], callback)
// We need to handle both cases, so we use ...args
exports.write = function (fd, buffer, ...args) {
  if (typeof args[args.length - 1] === 'function') {
    return fs.write(fd, buffer, ...args)
  }

  return new Promise((resolve, reject) => {
    fs.write(fd, buffer, ...args, (err, bytesWritten, buffer) => {
      if (err) return reject(err)
      resolve({ bytesWritten, buffer })
    })
  })
}

// fs.realpath.native only available in Node v9.2+
if (typeof fs.realpath.native === 'function') {
  exports.realpath.native = u(fs.realpath.native)
}


/***/ }),

/***/ 2136:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


module.exports = Object.assign(
  {},
  // Export promiseified graceful-fs:
  __nccwpck_require__(3506),
  // Export extra methods:
  __nccwpck_require__(1364),
  __nccwpck_require__(5796),
  __nccwpck_require__(7882),
  __nccwpck_require__(5779),
  __nccwpck_require__(8471),
  __nccwpck_require__(1089),
  __nccwpck_require__(4252),
  __nccwpck_require__(2076),
  __nccwpck_require__(484),
  __nccwpck_require__(2881),
  __nccwpck_require__(6205)
)

// Export fs.promises as a getter property so that we don't trigger
// ExperimentalWarning before fs.promises is actually accessed.
const fs = __nccwpck_require__(9896)
if (Object.getOwnPropertyDescriptor(fs, 'promises')) {
  Object.defineProperty(module.exports, "promises", ({
    get () { return fs.promises }
  }))
}


/***/ }),

/***/ 8471:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const jsonFile = __nccwpck_require__(6239)

jsonFile.outputJson = u(__nccwpck_require__(3753))
jsonFile.outputJsonSync = __nccwpck_require__(425)
// aliases
jsonFile.outputJSON = jsonFile.outputJson
jsonFile.outputJSONSync = jsonFile.outputJsonSync
jsonFile.writeJSON = jsonFile.writeJson
jsonFile.writeJSONSync = jsonFile.writeJsonSync
jsonFile.readJSON = jsonFile.readJson
jsonFile.readJSONSync = jsonFile.readJsonSync

module.exports = jsonFile


/***/ }),

/***/ 6239:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const jsonFile = __nccwpck_require__(2064)

module.exports = {
  // jsonfile exports
  readJson: u(jsonFile.readFile),
  readJsonSync: jsonFile.readFileSync,
  writeJson: u(jsonFile.writeFile),
  writeJsonSync: jsonFile.writeFileSync
}


/***/ }),

/***/ 425:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const mkdir = __nccwpck_require__(1089)
const jsonFile = __nccwpck_require__(6239)

function outputJsonSync (file, data, options) {
  const dir = path.dirname(file)

  if (!fs.existsSync(dir)) {
    mkdir.mkdirsSync(dir)
  }

  jsonFile.writeJsonSync(file, data, options)
}

module.exports = outputJsonSync


/***/ }),

/***/ 3753:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const path = __nccwpck_require__(6928)
const mkdir = __nccwpck_require__(1089)
const pathExists = (__nccwpck_require__(2881).pathExists)
const jsonFile = __nccwpck_require__(6239)

function outputJson (file, data, options, callback) {
  if (typeof options === 'function') {
    callback = options
    options = {}
  }

  const dir = path.dirname(file)

  pathExists(dir, (err, itDoes) => {
    if (err) return callback(err)
    if (itDoes) return jsonFile.writeJson(file, data, options, callback)

    mkdir.mkdirs(dir, err => {
      if (err) return callback(err)
      jsonFile.writeJson(file, data, options, callback)
    })
  })
}

module.exports = outputJson


/***/ }),

/***/ 1089:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const mkdirs = u(__nccwpck_require__(2009))
const mkdirsSync = __nccwpck_require__(185)

module.exports = {
  mkdirs,
  mkdirsSync,
  // alias
  mkdirp: mkdirs,
  mkdirpSync: mkdirsSync,
  ensureDir: mkdirs,
  ensureDirSync: mkdirsSync
}


/***/ }),

/***/ 185:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const invalidWin32Path = (__nccwpck_require__(4766).invalidWin32Path)

const o777 = parseInt('0777', 8)

function mkdirsSync (p, opts, made) {
  if (!opts || typeof opts !== 'object') {
    opts = { mode: opts }
  }

  let mode = opts.mode
  const xfs = opts.fs || fs

  if (process.platform === 'win32' && invalidWin32Path(p)) {
    const errInval = new Error(p + ' contains invalid WIN32 path characters.')
    errInval.code = 'EINVAL'
    throw errInval
  }

  if (mode === undefined) {
    mode = o777 & (~process.umask())
  }
  if (!made) made = null

  p = path.resolve(p)

  try {
    xfs.mkdirSync(p, mode)
    made = made || p
  } catch (err0) {
    if (err0.code === 'ENOENT') {
      if (path.dirname(p) === p) throw err0
      made = mkdirsSync(path.dirname(p), opts, made)
      mkdirsSync(p, opts, made)
    } else {
      // In the case of any other error, just see if there's a dir there
      // already. If so, then hooray!  If not, then something is borked.
      let stat
      try {
        stat = xfs.statSync(p)
      } catch (err1) {
        throw err0
      }
      if (!stat.isDirectory()) throw err0
    }
  }

  return made
}

module.exports = mkdirsSync


/***/ }),

/***/ 2009:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const invalidWin32Path = (__nccwpck_require__(4766).invalidWin32Path)

const o777 = parseInt('0777', 8)

function mkdirs (p, opts, callback, made) {
  if (typeof opts === 'function') {
    callback = opts
    opts = {}
  } else if (!opts || typeof opts !== 'object') {
    opts = { mode: opts }
  }

  if (process.platform === 'win32' && invalidWin32Path(p)) {
    const errInval = new Error(p + ' contains invalid WIN32 path characters.')
    errInval.code = 'EINVAL'
    return callback(errInval)
  }

  let mode = opts.mode
  const xfs = opts.fs || fs

  if (mode === undefined) {
    mode = o777 & (~process.umask())
  }
  if (!made) made = null

  callback = callback || function () {}
  p = path.resolve(p)

  xfs.mkdir(p, mode, er => {
    if (!er) {
      made = made || p
      return callback(null, made)
    }
    switch (er.code) {
      case 'ENOENT':
        if (path.dirname(p) === p) return callback(er)
        mkdirs(path.dirname(p), opts, (er, made) => {
          if (er) callback(er, made)
          else mkdirs(p, opts, callback, made)
        })
        break

      // In the case of any other error, just see if there's a dir
      // there already.  If so, then hooray!  If not, then something
      // is borked.
      default:
        xfs.stat(p, (er2, stat) => {
          // if the stat fails, then that's super weird.
          // let the original error be the failure reason.
          if (er2 || !stat.isDirectory()) callback(er, made)
          else callback(null, made)
        })
        break
    }
  })
}

module.exports = mkdirs


/***/ }),

/***/ 4766:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const path = __nccwpck_require__(6928)

// get drive on windows
function getRootPath (p) {
  p = path.normalize(path.resolve(p)).split(path.sep)
  if (p.length > 0) return p[0]
  return null
}

// http://stackoverflow.com/a/62888/10333 contains more accurate
// TODO: expand to include the rest
const INVALID_PATH_CHARS = /[<>:"|?*]/

function invalidWin32Path (p) {
  const rp = getRootPath(p)
  p = p.replace(rp, '')
  return INVALID_PATH_CHARS.test(p)
}

module.exports = {
  getRootPath,
  invalidWin32Path
}


/***/ }),

/***/ 4252:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


module.exports = {
  moveSync: __nccwpck_require__(7183)
}


/***/ }),

/***/ 7183:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const copySync = (__nccwpck_require__(1364).copySync)
const removeSync = (__nccwpck_require__(6205).removeSync)
const mkdirpSync = (__nccwpck_require__(1089).mkdirpSync)
const stat = __nccwpck_require__(887)

function moveSync (src, dest, opts) {
  opts = opts || {}
  const overwrite = opts.overwrite || opts.clobber || false

  const { srcStat } = stat.checkPathsSync(src, dest, 'move')
  stat.checkParentPathsSync(src, srcStat, dest, 'move')
  mkdirpSync(path.dirname(dest))
  return doRename(src, dest, overwrite)
}

function doRename (src, dest, overwrite) {
  if (overwrite) {
    removeSync(dest)
    return rename(src, dest, overwrite)
  }
  if (fs.existsSync(dest)) throw new Error('dest already exists.')
  return rename(src, dest, overwrite)
}

function rename (src, dest, overwrite) {
  try {
    fs.renameSync(src, dest)
  } catch (err) {
    if (err.code !== 'EXDEV') throw err
    return moveAcrossDevice(src, dest, overwrite)
  }
}

function moveAcrossDevice (src, dest, overwrite) {
  const opts = {
    overwrite,
    errorOnExist: true
  }
  copySync(src, dest, opts)
  return removeSync(src)
}

module.exports = moveSync


/***/ }),

/***/ 2076:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
module.exports = {
  move: u(__nccwpck_require__(7751))
}


/***/ }),

/***/ 7751:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const copy = (__nccwpck_require__(5796).copy)
const remove = (__nccwpck_require__(6205).remove)
const mkdirp = (__nccwpck_require__(1089).mkdirp)
const pathExists = (__nccwpck_require__(2881).pathExists)
const stat = __nccwpck_require__(887)

function move (src, dest, opts, cb) {
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }

  const overwrite = opts.overwrite || opts.clobber || false

  stat.checkPaths(src, dest, 'move', (err, stats) => {
    if (err) return cb(err)
    const { srcStat } = stats
    stat.checkParentPaths(src, srcStat, dest, 'move', err => {
      if (err) return cb(err)
      mkdirp(path.dirname(dest), err => {
        if (err) return cb(err)
        return doRename(src, dest, overwrite, cb)
      })
    })
  })
}

function doRename (src, dest, overwrite, cb) {
  if (overwrite) {
    return remove(dest, err => {
      if (err) return cb(err)
      return rename(src, dest, overwrite, cb)
    })
  }
  pathExists(dest, (err, destExists) => {
    if (err) return cb(err)
    if (destExists) return cb(new Error('dest already exists.'))
    return rename(src, dest, overwrite, cb)
  })
}

function rename (src, dest, overwrite, cb) {
  fs.rename(src, dest, err => {
    if (!err) return cb()
    if (err.code !== 'EXDEV') return cb(err)
    return moveAcrossDevice(src, dest, overwrite, cb)
  })
}

function moveAcrossDevice (src, dest, overwrite, cb) {
  const opts = {
    overwrite,
    errorOnExist: true
  }
  copy(src, dest, opts, err => {
    if (err) return cb(err)
    return remove(src, cb)
  })
}

module.exports = move


/***/ }),

/***/ 484:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const mkdir = __nccwpck_require__(1089)
const pathExists = (__nccwpck_require__(2881).pathExists)

function outputFile (file, data, encoding, callback) {
  if (typeof encoding === 'function') {
    callback = encoding
    encoding = 'utf8'
  }

  const dir = path.dirname(file)
  pathExists(dir, (err, itDoes) => {
    if (err) return callback(err)
    if (itDoes) return fs.writeFile(file, data, encoding, callback)

    mkdir.mkdirs(dir, err => {
      if (err) return callback(err)

      fs.writeFile(file, data, encoding, callback)
    })
  })
}

function outputFileSync (file, ...args) {
  const dir = path.dirname(file)
  if (fs.existsSync(dir)) {
    return fs.writeFileSync(file, ...args)
  }
  mkdir.mkdirsSync(dir)
  fs.writeFileSync(file, ...args)
}

module.exports = {
  outputFile: u(outputFile),
  outputFileSync
}


/***/ }),

/***/ 2881:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

const u = (__nccwpck_require__(5077)/* .fromPromise */ .z)
const fs = __nccwpck_require__(3506)

function pathExists (path) {
  return fs.access(path).then(() => true).catch(() => false)
}

module.exports = {
  pathExists: u(pathExists),
  pathExistsSync: fs.existsSync
}


/***/ }),

/***/ 6205:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const u = (__nccwpck_require__(5077)/* .fromCallback */ .S)
const rimraf = __nccwpck_require__(7864)

module.exports = {
  remove: u(rimraf),
  removeSync: rimraf.sync
}


/***/ }),

/***/ 7864:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)
const assert = __nccwpck_require__(2613)

const isWindows = (process.platform === 'win32')

function defaults (options) {
  const methods = [
    'unlink',
    'chmod',
    'stat',
    'lstat',
    'rmdir',
    'readdir'
  ]
  methods.forEach(m => {
    options[m] = options[m] || fs[m]
    m = m + 'Sync'
    options[m] = options[m] || fs[m]
  })

  options.maxBusyTries = options.maxBusyTries || 3
}

function rimraf (p, options, cb) {
  let busyTries = 0

  if (typeof options === 'function') {
    cb = options
    options = {}
  }

  assert(p, 'rimraf: missing path')
  assert.strictEqual(typeof p, 'string', 'rimraf: path should be a string')
  assert.strictEqual(typeof cb, 'function', 'rimraf: callback function required')
  assert(options, 'rimraf: invalid options argument provided')
  assert.strictEqual(typeof options, 'object', 'rimraf: options should be object')

  defaults(options)

  rimraf_(p, options, function CB (er) {
    if (er) {
      if ((er.code === 'EBUSY' || er.code === 'ENOTEMPTY' || er.code === 'EPERM') &&
          busyTries < options.maxBusyTries) {
        busyTries++
        const time = busyTries * 100
        // try again, with the same exact callback as this one.
        return setTimeout(() => rimraf_(p, options, CB), time)
      }

      // already gone
      if (er.code === 'ENOENT') er = null
    }

    cb(er)
  })
}

// Two possible strategies.
// 1. Assume it's a file.  unlink it, then do the dir stuff on EPERM or EISDIR
// 2. Assume it's a directory.  readdir, then do the file stuff on ENOTDIR
//
// Both result in an extra syscall when you guess wrong.  However, there
// are likely far more normal files in the world than directories.  This
// is based on the assumption that a the average number of files per
// directory is >= 1.
//
// If anyone ever complains about this, then I guess the strategy could
// be made configurable somehow.  But until then, YAGNI.
function rimraf_ (p, options, cb) {
  assert(p)
  assert(options)
  assert(typeof cb === 'function')

  // sunos lets the root user unlink directories, which is... weird.
  // so we have to lstat here and make sure it's not a dir.
  options.lstat(p, (er, st) => {
    if (er && er.code === 'ENOENT') {
      return cb(null)
    }

    // Windows can EPERM on stat.  Life is suffering.
    if (er && er.code === 'EPERM' && isWindows) {
      return fixWinEPERM(p, options, er, cb)
    }

    if (st && st.isDirectory()) {
      return rmdir(p, options, er, cb)
    }

    options.unlink(p, er => {
      if (er) {
        if (er.code === 'ENOENT') {
          return cb(null)
        }
        if (er.code === 'EPERM') {
          return (isWindows)
            ? fixWinEPERM(p, options, er, cb)
            : rmdir(p, options, er, cb)
        }
        if (er.code === 'EISDIR') {
          return rmdir(p, options, er, cb)
        }
      }
      return cb(er)
    })
  })
}

function fixWinEPERM (p, options, er, cb) {
  assert(p)
  assert(options)
  assert(typeof cb === 'function')
  if (er) {
    assert(er instanceof Error)
  }

  options.chmod(p, 0o666, er2 => {
    if (er2) {
      cb(er2.code === 'ENOENT' ? null : er)
    } else {
      options.stat(p, (er3, stats) => {
        if (er3) {
          cb(er3.code === 'ENOENT' ? null : er)
        } else if (stats.isDirectory()) {
          rmdir(p, options, er, cb)
        } else {
          options.unlink(p, cb)
        }
      })
    }
  })
}

function fixWinEPERMSync (p, options, er) {
  let stats

  assert(p)
  assert(options)
  if (er) {
    assert(er instanceof Error)
  }

  try {
    options.chmodSync(p, 0o666)
  } catch (er2) {
    if (er2.code === 'ENOENT') {
      return
    } else {
      throw er
    }
  }

  try {
    stats = options.statSync(p)
  } catch (er3) {
    if (er3.code === 'ENOENT') {
      return
    } else {
      throw er
    }
  }

  if (stats.isDirectory()) {
    rmdirSync(p, options, er)
  } else {
    options.unlinkSync(p)
  }
}

function rmdir (p, options, originalEr, cb) {
  assert(p)
  assert(options)
  if (originalEr) {
    assert(originalEr instanceof Error)
  }
  assert(typeof cb === 'function')

  // try to rmdir first, and only readdir on ENOTEMPTY or EEXIST (SunOS)
  // if we guessed wrong, and it's not a directory, then
  // raise the original error.
  options.rmdir(p, er => {
    if (er && (er.code === 'ENOTEMPTY' || er.code === 'EEXIST' || er.code === 'EPERM')) {
      rmkids(p, options, cb)
    } else if (er && er.code === 'ENOTDIR') {
      cb(originalEr)
    } else {
      cb(er)
    }
  })
}

function rmkids (p, options, cb) {
  assert(p)
  assert(options)
  assert(typeof cb === 'function')

  options.readdir(p, (er, files) => {
    if (er) return cb(er)

    let n = files.length
    let errState

    if (n === 0) return options.rmdir(p, cb)

    files.forEach(f => {
      rimraf(path.join(p, f), options, er => {
        if (errState) {
          return
        }
        if (er) return cb(errState = er)
        if (--n === 0) {
          options.rmdir(p, cb)
        }
      })
    })
  })
}

// this looks simpler, and is strictly *faster*, but will
// tie up the JavaScript thread and fail on excessively
// deep directory trees.
function rimrafSync (p, options) {
  let st

  options = options || {}
  defaults(options)

  assert(p, 'rimraf: missing path')
  assert.strictEqual(typeof p, 'string', 'rimraf: path should be a string')
  assert(options, 'rimraf: missing options')
  assert.strictEqual(typeof options, 'object', 'rimraf: options should be object')

  try {
    st = options.lstatSync(p)
  } catch (er) {
    if (er.code === 'ENOENT') {
      return
    }

    // Windows can EPERM on stat.  Life is suffering.
    if (er.code === 'EPERM' && isWindows) {
      fixWinEPERMSync(p, options, er)
    }
  }

  try {
    // sunos lets the root user unlink directories, which is... weird.
    if (st && st.isDirectory()) {
      rmdirSync(p, options, null)
    } else {
      options.unlinkSync(p)
    }
  } catch (er) {
    if (er.code === 'ENOENT') {
      return
    } else if (er.code === 'EPERM') {
      return isWindows ? fixWinEPERMSync(p, options, er) : rmdirSync(p, options, er)
    } else if (er.code !== 'EISDIR') {
      throw er
    }
    rmdirSync(p, options, er)
  }
}

function rmdirSync (p, options, originalEr) {
  assert(p)
  assert(options)
  if (originalEr) {
    assert(originalEr instanceof Error)
  }

  try {
    options.rmdirSync(p)
  } catch (er) {
    if (er.code === 'ENOTDIR') {
      throw originalEr
    } else if (er.code === 'ENOTEMPTY' || er.code === 'EEXIST' || er.code === 'EPERM') {
      rmkidsSync(p, options)
    } else if (er.code !== 'ENOENT') {
      throw er
    }
  }
}

function rmkidsSync (p, options) {
  assert(p)
  assert(options)
  options.readdirSync(p).forEach(f => rimrafSync(path.join(p, f), options))

  if (isWindows) {
    // We only end up here once we got ENOTEMPTY at least once, and
    // at this point, we are guaranteed to have removed all the kids.
    // So, we know that it won't be ENOENT or ENOTDIR or anything else.
    // try really hard to delete stuff on windows, because it has a
    // PROFOUNDLY annoying habit of not closing handles promptly when
    // files are deleted, resulting in spurious ENOTEMPTY errors.
    const startTime = Date.now()
    do {
      try {
        const ret = options.rmdirSync(p, options)
        return ret
      } catch (er) { }
    } while (Date.now() - startTime < 500) // give up after 500ms
  } else {
    const ret = options.rmdirSync(p, options)
    return ret
  }
}

module.exports = rimraf
rimraf.sync = rimrafSync


/***/ }),

/***/ 9635:
/***/ ((module) => {

"use strict";

/* eslint-disable node/no-deprecated-api */
module.exports = function (size) {
  if (typeof Buffer.allocUnsafe === 'function') {
    try {
      return Buffer.allocUnsafe(size)
    } catch (e) {
      return new Buffer(size)
    }
  }
  return new Buffer(size)
}


/***/ }),

/***/ 887:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const path = __nccwpck_require__(6928)

const NODE_VERSION_MAJOR_WITH_BIGINT = 10
const NODE_VERSION_MINOR_WITH_BIGINT = 5
const NODE_VERSION_PATCH_WITH_BIGINT = 0
const nodeVersion = process.versions.node.split('.')
const nodeVersionMajor = Number.parseInt(nodeVersion[0], 10)
const nodeVersionMinor = Number.parseInt(nodeVersion[1], 10)
const nodeVersionPatch = Number.parseInt(nodeVersion[2], 10)

function nodeSupportsBigInt () {
  if (nodeVersionMajor > NODE_VERSION_MAJOR_WITH_BIGINT) {
    return true
  } else if (nodeVersionMajor === NODE_VERSION_MAJOR_WITH_BIGINT) {
    if (nodeVersionMinor > NODE_VERSION_MINOR_WITH_BIGINT) {
      return true
    } else if (nodeVersionMinor === NODE_VERSION_MINOR_WITH_BIGINT) {
      if (nodeVersionPatch >= NODE_VERSION_PATCH_WITH_BIGINT) {
        return true
      }
    }
  }
  return false
}

function getStats (src, dest, cb) {
  if (nodeSupportsBigInt()) {
    fs.stat(src, { bigint: true }, (err, srcStat) => {
      if (err) return cb(err)
      fs.stat(dest, { bigint: true }, (err, destStat) => {
        if (err) {
          if (err.code === 'ENOENT') return cb(null, { srcStat, destStat: null })
          return cb(err)
        }
        return cb(null, { srcStat, destStat })
      })
    })
  } else {
    fs.stat(src, (err, srcStat) => {
      if (err) return cb(err)
      fs.stat(dest, (err, destStat) => {
        if (err) {
          if (err.code === 'ENOENT') return cb(null, { srcStat, destStat: null })
          return cb(err)
        }
        return cb(null, { srcStat, destStat })
      })
    })
  }
}

function getStatsSync (src, dest) {
  let srcStat, destStat
  if (nodeSupportsBigInt()) {
    srcStat = fs.statSync(src, { bigint: true })
  } else {
    srcStat = fs.statSync(src)
  }
  try {
    if (nodeSupportsBigInt()) {
      destStat = fs.statSync(dest, { bigint: true })
    } else {
      destStat = fs.statSync(dest)
    }
  } catch (err) {
    if (err.code === 'ENOENT') return { srcStat, destStat: null }
    throw err
  }
  return { srcStat, destStat }
}

function checkPaths (src, dest, funcName, cb) {
  getStats(src, dest, (err, stats) => {
    if (err) return cb(err)
    const { srcStat, destStat } = stats
    if (destStat && destStat.ino && destStat.dev && destStat.ino === srcStat.ino && destStat.dev === srcStat.dev) {
      return cb(new Error('Source and destination must not be the same.'))
    }
    if (srcStat.isDirectory() && isSrcSubdir(src, dest)) {
      return cb(new Error(errMsg(src, dest, funcName)))
    }
    return cb(null, { srcStat, destStat })
  })
}

function checkPathsSync (src, dest, funcName) {
  const { srcStat, destStat } = getStatsSync(src, dest)
  if (destStat && destStat.ino && destStat.dev && destStat.ino === srcStat.ino && destStat.dev === srcStat.dev) {
    throw new Error('Source and destination must not be the same.')
  }
  if (srcStat.isDirectory() && isSrcSubdir(src, dest)) {
    throw new Error(errMsg(src, dest, funcName))
  }
  return { srcStat, destStat }
}

// recursively check if dest parent is a subdirectory of src.
// It works for all file types including symlinks since it
// checks the src and dest inodes. It starts from the deepest
// parent and stops once it reaches the src parent or the root path.
function checkParentPaths (src, srcStat, dest, funcName, cb) {
  const srcParent = path.resolve(path.dirname(src))
  const destParent = path.resolve(path.dirname(dest))
  if (destParent === srcParent || destParent === path.parse(destParent).root) return cb()
  if (nodeSupportsBigInt()) {
    fs.stat(destParent, { bigint: true }, (err, destStat) => {
      if (err) {
        if (err.code === 'ENOENT') return cb()
        return cb(err)
      }
      if (destStat.ino && destStat.dev && destStat.ino === srcStat.ino && destStat.dev === srcStat.dev) {
        return cb(new Error(errMsg(src, dest, funcName)))
      }
      return checkParentPaths(src, srcStat, destParent, funcName, cb)
    })
  } else {
    fs.stat(destParent, (err, destStat) => {
      if (err) {
        if (err.code === 'ENOENT') return cb()
        return cb(err)
      }
      if (destStat.ino && destStat.dev && destStat.ino === srcStat.ino && destStat.dev === srcStat.dev) {
        return cb(new Error(errMsg(src, dest, funcName)))
      }
      return checkParentPaths(src, srcStat, destParent, funcName, cb)
    })
  }
}

function checkParentPathsSync (src, srcStat, dest, funcName) {
  const srcParent = path.resolve(path.dirname(src))
  const destParent = path.resolve(path.dirname(dest))
  if (destParent === srcParent || destParent === path.parse(destParent).root) return
  let destStat
  try {
    if (nodeSupportsBigInt()) {
      destStat = fs.statSync(destParent, { bigint: true })
    } else {
      destStat = fs.statSync(destParent)
    }
  } catch (err) {
    if (err.code === 'ENOENT') return
    throw err
  }
  if (destStat.ino && destStat.dev && destStat.ino === srcStat.ino && destStat.dev === srcStat.dev) {
    throw new Error(errMsg(src, dest, funcName))
  }
  return checkParentPathsSync(src, srcStat, destParent, funcName)
}

// return true if dest is a subdir of src, otherwise false.
// It only checks the path strings.
function isSrcSubdir (src, dest) {
  const srcArr = path.resolve(src).split(path.sep).filter(i => i)
  const destArr = path.resolve(dest).split(path.sep).filter(i => i)
  return srcArr.reduce((acc, cur, i) => acc && destArr[i] === cur, true)
}

function errMsg (src, dest, funcName) {
  return `Cannot ${funcName} '${src}' to a subdirectory of itself, '${dest}'.`
}

module.exports = {
  checkPaths,
  checkPathsSync,
  checkParentPaths,
  checkParentPathsSync,
  isSrcSubdir
}


/***/ }),

/***/ 6934:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(5744)
const os = __nccwpck_require__(857)
const path = __nccwpck_require__(6928)

// HFS, ext{2,3}, FAT do not, Node.js v0.10 does not
function hasMillisResSync () {
  let tmpfile = path.join('millis-test-sync' + Date.now().toString() + Math.random().toString().slice(2))
  tmpfile = path.join(os.tmpdir(), tmpfile)

  // 550 millis past UNIX epoch
  const d = new Date(1435410243862)
  fs.writeFileSync(tmpfile, 'https://github.com/jprichardson/node-fs-extra/pull/141')
  const fd = fs.openSync(tmpfile, 'r+')
  fs.futimesSync(fd, d, d)
  fs.closeSync(fd)
  return fs.statSync(tmpfile).mtime > 1435410243000
}

function hasMillisRes (callback) {
  let tmpfile = path.join('millis-test' + Date.now().toString() + Math.random().toString().slice(2))
  tmpfile = path.join(os.tmpdir(), tmpfile)

  // 550 millis past UNIX epoch
  const d = new Date(1435410243862)
  fs.writeFile(tmpfile, 'https://github.com/jprichardson/node-fs-extra/pull/141', err => {
    if (err) return callback(err)
    fs.open(tmpfile, 'r+', (err, fd) => {
      if (err) return callback(err)
      fs.futimes(fd, d, d, err => {
        if (err) return callback(err)
        fs.close(fd, err => {
          if (err) return callback(err)
          fs.stat(tmpfile, (err, stats) => {
            if (err) return callback(err)
            callback(null, stats.mtime > 1435410243000)
          })
        })
      })
    })
  })
}

function timeRemoveMillis (timestamp) {
  if (typeof timestamp === 'number') {
    return Math.floor(timestamp / 1000) * 1000
  } else if (timestamp instanceof Date) {
    return new Date(Math.floor(timestamp.getTime() / 1000) * 1000)
  } else {
    throw new Error('fs-extra: timeRemoveMillis() unknown parameter type')
  }
}

function utimesMillis (path, atime, mtime, callback) {
  // if (!HAS_MILLIS_RES) return fs.utimes(path, atime, mtime, callback)
  fs.open(path, 'r+', (err, fd) => {
    if (err) return callback(err)
    fs.futimes(fd, atime, mtime, futimesErr => {
      fs.close(fd, closeErr => {
        if (callback) callback(futimesErr || closeErr)
      })
    })
  })
}

function utimesMillisSync (path, atime, mtime) {
  const fd = fs.openSync(path, 'r+')
  fs.futimesSync(fd, atime, mtime)
  return fs.closeSync(fd)
}

module.exports = {
  hasMillisRes,
  hasMillisResSync,
  timeRemoveMillis,
  utimesMillis,
  utimesMillisSync
}


/***/ }),

/***/ 3964:
/***/ ((module) => {

"use strict";


module.exports = clone

var getPrototypeOf = Object.getPrototypeOf || function (obj) {
  return obj.__proto__
}

function clone (obj) {
  if (obj === null || typeof obj !== 'object')
    return obj

  if (obj instanceof Object)
    var copy = { __proto__: getPrototypeOf(obj) }
  else
    var copy = Object.create(null)

  Object.getOwnPropertyNames(obj).forEach(function (key) {
    Object.defineProperty(copy, key, Object.getOwnPropertyDescriptor(obj, key))
  })

  return copy
}


/***/ }),

/***/ 5744:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var fs = __nccwpck_require__(9896)
var polyfills = __nccwpck_require__(3501)
var legacy = __nccwpck_require__(2270)
var clone = __nccwpck_require__(3964)

var util = __nccwpck_require__(9023)

/* istanbul ignore next - node 0.x polyfill */
var gracefulQueue
var previousSymbol

/* istanbul ignore else - node 0.x polyfill */
if (typeof Symbol === 'function' && typeof Symbol.for === 'function') {
  gracefulQueue = Symbol.for('graceful-fs.queue')
  // This is used in testing by future versions
  previousSymbol = Symbol.for('graceful-fs.previous')
} else {
  gracefulQueue = '___graceful-fs.queue'
  previousSymbol = '___graceful-fs.previous'
}

function noop () {}

function publishQueue(context, queue) {
  Object.defineProperty(context, gracefulQueue, {
    get: function() {
      return queue
    }
  })
}

var debug = noop
if (util.debuglog)
  debug = util.debuglog('gfs4')
else if (/\bgfs4\b/i.test(process.env.NODE_DEBUG || ''))
  debug = function() {
    var m = util.format.apply(util, arguments)
    m = 'GFS4: ' + m.split(/\n/).join('\nGFS4: ')
    console.error(m)
  }

// Once time initialization
if (!fs[gracefulQueue]) {
  // This queue can be shared by multiple loaded instances
  var queue = global[gracefulQueue] || []
  publishQueue(fs, queue)

  // Patch fs.close/closeSync to shared queue version, because we need
  // to retry() whenever a close happens *anywhere* in the program.
  // This is essential when multiple graceful-fs instances are
  // in play at the same time.
  fs.close = (function (fs$close) {
    function close (fd, cb) {
      return fs$close.call(fs, fd, function (err) {
        // This function uses the graceful-fs shared queue
        if (!err) {
          resetQueue()
        }

        if (typeof cb === 'function')
          cb.apply(this, arguments)
      })
    }

    Object.defineProperty(close, previousSymbol, {
      value: fs$close
    })
    return close
  })(fs.close)

  fs.closeSync = (function (fs$closeSync) {
    function closeSync (fd) {
      // This function uses the graceful-fs shared queue
      fs$closeSync.apply(fs, arguments)
      resetQueue()
    }

    Object.defineProperty(closeSync, previousSymbol, {
      value: fs$closeSync
    })
    return closeSync
  })(fs.closeSync)

  if (/\bgfs4\b/i.test(process.env.NODE_DEBUG || '')) {
    process.on('exit', function() {
      debug(fs[gracefulQueue])
      __nccwpck_require__(2613).equal(fs[gracefulQueue].length, 0)
    })
  }
}

if (!global[gracefulQueue]) {
  publishQueue(global, fs[gracefulQueue]);
}

module.exports = patch(clone(fs))
if (process.env.TEST_GRACEFUL_FS_GLOBAL_PATCH && !fs.__patched) {
    module.exports = patch(fs)
    fs.__patched = true;
}

function patch (fs) {
  // Everything that references the open() function needs to be in here
  polyfills(fs)
  fs.gracefulify = patch

  fs.createReadStream = createReadStream
  fs.createWriteStream = createWriteStream
  var fs$readFile = fs.readFile
  fs.readFile = readFile
  function readFile (path, options, cb) {
    if (typeof options === 'function')
      cb = options, options = null

    return go$readFile(path, options, cb)

    function go$readFile (path, options, cb, startTime) {
      return fs$readFile(path, options, function (err) {
        if (err && (err.code === 'EMFILE' || err.code === 'ENFILE'))
          enqueue([go$readFile, [path, options, cb], err, startTime || Date.now(), Date.now()])
        else {
          if (typeof cb === 'function')
            cb.apply(this, arguments)
        }
      })
    }
  }

  var fs$writeFile = fs.writeFile
  fs.writeFile = writeFile
  function writeFile (path, data, options, cb) {
    if (typeof options === 'function')
      cb = options, options = null

    return go$writeFile(path, data, options, cb)

    function go$writeFile (path, data, options, cb, startTime) {
      return fs$writeFile(path, data, options, function (err) {
        if (err && (err.code === 'EMFILE' || err.code === 'ENFILE'))
          enqueue([go$writeFile, [path, data, options, cb], err, startTime || Date.now(), Date.now()])
        else {
          if (typeof cb === 'function')
            cb.apply(this, arguments)
        }
      })
    }
  }

  var fs$appendFile = fs.appendFile
  if (fs$appendFile)
    fs.appendFile = appendFile
  function appendFile (path, data, options, cb) {
    if (typeof options === 'function')
      cb = options, options = null

    return go$appendFile(path, data, options, cb)

    function go$appendFile (path, data, options, cb, startTime) {
      return fs$appendFile(path, data, options, function (err) {
        if (err && (err.code === 'EMFILE' || err.code === 'ENFILE'))
          enqueue([go$appendFile, [path, data, options, cb], err, startTime || Date.now(), Date.now()])
        else {
          if (typeof cb === 'function')
            cb.apply(this, arguments)
        }
      })
    }
  }

  var fs$copyFile = fs.copyFile
  if (fs$copyFile)
    fs.copyFile = copyFile
  function copyFile (src, dest, flags, cb) {
    if (typeof flags === 'function') {
      cb = flags
      flags = 0
    }
    return go$copyFile(src, dest, flags, cb)

    function go$copyFile (src, dest, flags, cb, startTime) {
      return fs$copyFile(src, dest, flags, function (err) {
        if (err && (err.code === 'EMFILE' || err.code === 'ENFILE'))
          enqueue([go$copyFile, [src, dest, flags, cb], err, startTime || Date.now(), Date.now()])
        else {
          if (typeof cb === 'function')
            cb.apply(this, arguments)
        }
      })
    }
  }

  var fs$readdir = fs.readdir
  fs.readdir = readdir
  var noReaddirOptionVersions = /^v[0-5]\./
  function readdir (path, options, cb) {
    if (typeof options === 'function')
      cb = options, options = null

    var go$readdir = noReaddirOptionVersions.test(process.version)
      ? function go$readdir (path, options, cb, startTime) {
        return fs$readdir(path, fs$readdirCallback(
          path, options, cb, startTime
        ))
      }
      : function go$readdir (path, options, cb, startTime) {
        return fs$readdir(path, options, fs$readdirCallback(
          path, options, cb, startTime
        ))
      }

    return go$readdir(path, options, cb)

    function fs$readdirCallback (path, options, cb, startTime) {
      return function (err, files) {
        if (err && (err.code === 'EMFILE' || err.code === 'ENFILE'))
          enqueue([
            go$readdir,
            [path, options, cb],
            err,
            startTime || Date.now(),
            Date.now()
          ])
        else {
          if (files && files.sort)
            files.sort()

          if (typeof cb === 'function')
            cb.call(this, err, files)
        }
      }
    }
  }

  if (process.version.substr(0, 4) === 'v0.8') {
    var legStreams = legacy(fs)
    ReadStream = legStreams.ReadStream
    WriteStream = legStreams.WriteStream
  }

  var fs$ReadStream = fs.ReadStream
  if (fs$ReadStream) {
    ReadStream.prototype = Object.create(fs$ReadStream.prototype)
    ReadStream.prototype.open = ReadStream$open
  }

  var fs$WriteStream = fs.WriteStream
  if (fs$WriteStream) {
    WriteStream.prototype = Object.create(fs$WriteStream.prototype)
    WriteStream.prototype.open = WriteStream$open
  }

  Object.defineProperty(fs, 'ReadStream', {
    get: function () {
      return ReadStream
    },
    set: function (val) {
      ReadStream = val
    },
    enumerable: true,
    configurable: true
  })
  Object.defineProperty(fs, 'WriteStream', {
    get: function () {
      return WriteStream
    },
    set: function (val) {
      WriteStream = val
    },
    enumerable: true,
    configurable: true
  })

  // legacy names
  var FileReadStream = ReadStream
  Object.defineProperty(fs, 'FileReadStream', {
    get: function () {
      return FileReadStream
    },
    set: function (val) {
      FileReadStream = val
    },
    enumerable: true,
    configurable: true
  })
  var FileWriteStream = WriteStream
  Object.defineProperty(fs, 'FileWriteStream', {
    get: function () {
      return FileWriteStream
    },
    set: function (val) {
      FileWriteStream = val
    },
    enumerable: true,
    configurable: true
  })

  function ReadStream (path, options) {
    if (this instanceof ReadStream)
      return fs$ReadStream.apply(this, arguments), this
    else
      return ReadStream.apply(Object.create(ReadStream.prototype), arguments)
  }

  function ReadStream$open () {
    var that = this
    open(that.path, that.flags, that.mode, function (err, fd) {
      if (err) {
        if (that.autoClose)
          that.destroy()

        that.emit('error', err)
      } else {
        that.fd = fd
        that.emit('open', fd)
        that.read()
      }
    })
  }

  function WriteStream (path, options) {
    if (this instanceof WriteStream)
      return fs$WriteStream.apply(this, arguments), this
    else
      return WriteStream.apply(Object.create(WriteStream.prototype), arguments)
  }

  function WriteStream$open () {
    var that = this
    open(that.path, that.flags, that.mode, function (err, fd) {
      if (err) {
        that.destroy()
        that.emit('error', err)
      } else {
        that.fd = fd
        that.emit('open', fd)
      }
    })
  }

  function createReadStream (path, options) {
    return new fs.ReadStream(path, options)
  }

  function createWriteStream (path, options) {
    return new fs.WriteStream(path, options)
  }

  var fs$open = fs.open
  fs.open = open
  function open (path, flags, mode, cb) {
    if (typeof mode === 'function')
      cb = mode, mode = null

    return go$open(path, flags, mode, cb)

    function go$open (path, flags, mode, cb, startTime) {
      return fs$open(path, flags, mode, function (err, fd) {
        if (err && (err.code === 'EMFILE' || err.code === 'ENFILE'))
          enqueue([go$open, [path, flags, mode, cb], err, startTime || Date.now(), Date.now()])
        else {
          if (typeof cb === 'function')
            cb.apply(this, arguments)
        }
      })
    }
  }

  return fs
}

function enqueue (elem) {
  debug('ENQUEUE', elem[0].name, elem[1])
  fs[gracefulQueue].push(elem)
  retry()
}

// keep track of the timeout between retry() calls
var retryTimer

// reset the startTime and lastTime to now
// this resets the start of the 60 second overall timeout as well as the
// delay between attempts so that we'll retry these jobs sooner
function resetQueue () {
  var now = Date.now()
  for (var i = 0; i < fs[gracefulQueue].length; ++i) {
    // entries that are only a length of 2 are from an older version, don't
    // bother modifying those since they'll be retried anyway.
    if (fs[gracefulQueue][i].length > 2) {
      fs[gracefulQueue][i][3] = now // startTime
      fs[gracefulQueue][i][4] = now // lastTime
    }
  }
  // call retry to make sure we're actively processing the queue
  retry()
}

function retry () {
  // clear the timer and remove it to help prevent unintended concurrency
  clearTimeout(retryTimer)
  retryTimer = undefined

  if (fs[gracefulQueue].length === 0)
    return

  var elem = fs[gracefulQueue].shift()
  var fn = elem[0]
  var args = elem[1]
  // these items may be unset if they were added by an older graceful-fs
  var err = elem[2]
  var startTime = elem[3]
  var lastTime = elem[4]

  // if we don't have a startTime we have no way of knowing if we've waited
  // long enough, so go ahead and retry this item now
  if (startTime === undefined) {
    debug('RETRY', fn.name, args)
    fn.apply(null, args)
  } else if (Date.now() - startTime >= 60000) {
    // it's been more than 60 seconds total, bail now
    debug('TIMEOUT', fn.name, args)
    var cb = args.pop()
    if (typeof cb === 'function')
      cb.call(null, err)
  } else {
    // the amount of time between the last attempt and right now
    var sinceAttempt = Date.now() - lastTime
    // the amount of time between when we first tried, and when we last tried
    // rounded up to at least 1
    var sinceStart = Math.max(lastTime - startTime, 1)
    // backoff. wait longer than the total time we've been retrying, but only
    // up to a maximum of 100ms
    var desiredDelay = Math.min(sinceStart * 1.2, 100)
    // it's been long enough since the last retry, do it again
    if (sinceAttempt >= desiredDelay) {
      debug('RETRY', fn.name, args)
      fn.apply(null, args.concat([startTime]))
    } else {
      // if we can't do this job yet, push it to the end of the queue
      // and let the next iteration check again
      fs[gracefulQueue].push(elem)
    }
  }

  // schedule our next run if one isn't already scheduled
  if (retryTimer === undefined) {
    retryTimer = setTimeout(retry, 0)
  }
}


/***/ }),

/***/ 2270:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var Stream = (__nccwpck_require__(2203).Stream)

module.exports = legacy

function legacy (fs) {
  return {
    ReadStream: ReadStream,
    WriteStream: WriteStream
  }

  function ReadStream (path, options) {
    if (!(this instanceof ReadStream)) return new ReadStream(path, options);

    Stream.call(this);

    var self = this;

    this.path = path;
    this.fd = null;
    this.readable = true;
    this.paused = false;

    this.flags = 'r';
    this.mode = 438; /*=0666*/
    this.bufferSize = 64 * 1024;

    options = options || {};

    // Mixin options into this
    var keys = Object.keys(options);
    for (var index = 0, length = keys.length; index < length; index++) {
      var key = keys[index];
      this[key] = options[key];
    }

    if (this.encoding) this.setEncoding(this.encoding);

    if (this.start !== undefined) {
      if ('number' !== typeof this.start) {
        throw TypeError('start must be a Number');
      }
      if (this.end === undefined) {
        this.end = Infinity;
      } else if ('number' !== typeof this.end) {
        throw TypeError('end must be a Number');
      }

      if (this.start > this.end) {
        throw new Error('start must be <= end');
      }

      this.pos = this.start;
    }

    if (this.fd !== null) {
      process.nextTick(function() {
        self._read();
      });
      return;
    }

    fs.open(this.path, this.flags, this.mode, function (err, fd) {
      if (err) {
        self.emit('error', err);
        self.readable = false;
        return;
      }

      self.fd = fd;
      self.emit('open', fd);
      self._read();
    })
  }

  function WriteStream (path, options) {
    if (!(this instanceof WriteStream)) return new WriteStream(path, options);

    Stream.call(this);

    this.path = path;
    this.fd = null;
    this.writable = true;

    this.flags = 'w';
    this.encoding = 'binary';
    this.mode = 438; /*=0666*/
    this.bytesWritten = 0;

    options = options || {};

    // Mixin options into this
    var keys = Object.keys(options);
    for (var index = 0, length = keys.length; index < length; index++) {
      var key = keys[index];
      this[key] = options[key];
    }

    if (this.start !== undefined) {
      if ('number' !== typeof this.start) {
        throw TypeError('start must be a Number');
      }
      if (this.start < 0) {
        throw new Error('start must be >= zero');
      }

      this.pos = this.start;
    }

    this.busy = false;
    this._queue = [];

    if (this.fd === null) {
      this._open = fs.open;
      this._queue.push([this._open, this.path, this.flags, this.mode, undefined]);
      this.flush();
    }
  }
}


/***/ }),

/***/ 3501:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var constants = __nccwpck_require__(9140)

var origCwd = process.cwd
var cwd = null

var platform = process.env.GRACEFUL_FS_PLATFORM || process.platform

process.cwd = function() {
  if (!cwd)
    cwd = origCwd.call(process)
  return cwd
}
try {
  process.cwd()
} catch (er) {}

// This check is needed until node.js 12 is required
if (typeof process.chdir === 'function') {
  var chdir = process.chdir
  process.chdir = function (d) {
    cwd = null
    chdir.call(process, d)
  }
  if (Object.setPrototypeOf) Object.setPrototypeOf(process.chdir, chdir)
}

module.exports = patch

function patch (fs) {
  // (re-)implement some things that are known busted or missing.

  // lchmod, broken prior to 0.6.2
  // back-port the fix here.
  if (constants.hasOwnProperty('O_SYMLINK') &&
      process.version.match(/^v0\.6\.[0-2]|^v0\.5\./)) {
    patchLchmod(fs)
  }

  // lutimes implementation, or no-op
  if (!fs.lutimes) {
    patchLutimes(fs)
  }

  // https://github.com/isaacs/node-graceful-fs/issues/4
  // Chown should not fail on einval or eperm if non-root.
  // It should not fail on enosys ever, as this just indicates
  // that a fs doesn't support the intended operation.

  fs.chown = chownFix(fs.chown)
  fs.fchown = chownFix(fs.fchown)
  fs.lchown = chownFix(fs.lchown)

  fs.chmod = chmodFix(fs.chmod)
  fs.fchmod = chmodFix(fs.fchmod)
  fs.lchmod = chmodFix(fs.lchmod)

  fs.chownSync = chownFixSync(fs.chownSync)
  fs.fchownSync = chownFixSync(fs.fchownSync)
  fs.lchownSync = chownFixSync(fs.lchownSync)

  fs.chmodSync = chmodFixSync(fs.chmodSync)
  fs.fchmodSync = chmodFixSync(fs.fchmodSync)
  fs.lchmodSync = chmodFixSync(fs.lchmodSync)

  fs.stat = statFix(fs.stat)
  fs.fstat = statFix(fs.fstat)
  fs.lstat = statFix(fs.lstat)

  fs.statSync = statFixSync(fs.statSync)
  fs.fstatSync = statFixSync(fs.fstatSync)
  fs.lstatSync = statFixSync(fs.lstatSync)

  // if lchmod/lchown do not exist, then make them no-ops
  if (fs.chmod && !fs.lchmod) {
    fs.lchmod = function (path, mode, cb) {
      if (cb) process.nextTick(cb)
    }
    fs.lchmodSync = function () {}
  }
  if (fs.chown && !fs.lchown) {
    fs.lchown = function (path, uid, gid, cb) {
      if (cb) process.nextTick(cb)
    }
    fs.lchownSync = function () {}
  }

  // on Windows, A/V software can lock the directory, causing this
  // to fail with an EACCES or EPERM if the directory contains newly
  // created files.  Try again on failure, for up to 60 seconds.

  // Set the timeout this long because some Windows Anti-Virus, such as Parity
  // bit9, may lock files for up to a minute, causing npm package install
  // failures. Also, take care to yield the scheduler. Windows scheduling gives
  // CPU to a busy looping process, which can cause the program causing the lock
  // contention to be starved of CPU by node, so the contention doesn't resolve.
  if (platform === "win32") {
    fs.rename = typeof fs.rename !== 'function' ? fs.rename
    : (function (fs$rename) {
      function rename (from, to, cb) {
        var start = Date.now()
        var backoff = 0;
        fs$rename(from, to, function CB (er) {
          if (er
              && (er.code === "EACCES" || er.code === "EPERM" || er.code === "EBUSY")
              && Date.now() - start < 60000) {
            setTimeout(function() {
              fs.stat(to, function (stater, st) {
                if (stater && stater.code === "ENOENT")
                  fs$rename(from, to, CB);
                else
                  cb(er)
              })
            }, backoff)
            if (backoff < 100)
              backoff += 10;
            return;
          }
          if (cb) cb(er)
        })
      }
      if (Object.setPrototypeOf) Object.setPrototypeOf(rename, fs$rename)
      return rename
    })(fs.rename)
  }

  // if read() returns EAGAIN, then just try it again.
  fs.read = typeof fs.read !== 'function' ? fs.read
  : (function (fs$read) {
    function read (fd, buffer, offset, length, position, callback_) {
      var callback
      if (callback_ && typeof callback_ === 'function') {
        var eagCounter = 0
        callback = function (er, _, __) {
          if (er && er.code === 'EAGAIN' && eagCounter < 10) {
            eagCounter ++
            return fs$read.call(fs, fd, buffer, offset, length, position, callback)
          }
          callback_.apply(this, arguments)
        }
      }
      return fs$read.call(fs, fd, buffer, offset, length, position, callback)
    }

    // This ensures `util.promisify` works as it does for native `fs.read`.
    if (Object.setPrototypeOf) Object.setPrototypeOf(read, fs$read)
    return read
  })(fs.read)

  fs.readSync = typeof fs.readSync !== 'function' ? fs.readSync
  : (function (fs$readSync) { return function (fd, buffer, offset, length, position) {
    var eagCounter = 0
    while (true) {
      try {
        return fs$readSync.call(fs, fd, buffer, offset, length, position)
      } catch (er) {
        if (er.code === 'EAGAIN' && eagCounter < 10) {
          eagCounter ++
          continue
        }
        throw er
      }
    }
  }})(fs.readSync)

  function patchLchmod (fs) {
    fs.lchmod = function (path, mode, callback) {
      fs.open( path
             , constants.O_WRONLY | constants.O_SYMLINK
             , mode
             , function (err, fd) {
        if (err) {
          if (callback) callback(err)
          return
        }
        // prefer to return the chmod error, if one occurs,
        // but still try to close, and report closing errors if they occur.
        fs.fchmod(fd, mode, function (err) {
          fs.close(fd, function(err2) {
            if (callback) callback(err || err2)
          })
        })
      })
    }

    fs.lchmodSync = function (path, mode) {
      var fd = fs.openSync(path, constants.O_WRONLY | constants.O_SYMLINK, mode)

      // prefer to return the chmod error, if one occurs,
      // but still try to close, and report closing errors if they occur.
      var threw = true
      var ret
      try {
        ret = fs.fchmodSync(fd, mode)
        threw = false
      } finally {
        if (threw) {
          try {
            fs.closeSync(fd)
          } catch (er) {}
        } else {
          fs.closeSync(fd)
        }
      }
      return ret
    }
  }

  function patchLutimes (fs) {
    if (constants.hasOwnProperty("O_SYMLINK") && fs.futimes) {
      fs.lutimes = function (path, at, mt, cb) {
        fs.open(path, constants.O_SYMLINK, function (er, fd) {
          if (er) {
            if (cb) cb(er)
            return
          }
          fs.futimes(fd, at, mt, function (er) {
            fs.close(fd, function (er2) {
              if (cb) cb(er || er2)
            })
          })
        })
      }

      fs.lutimesSync = function (path, at, mt) {
        var fd = fs.openSync(path, constants.O_SYMLINK)
        var ret
        var threw = true
        try {
          ret = fs.futimesSync(fd, at, mt)
          threw = false
        } finally {
          if (threw) {
            try {
              fs.closeSync(fd)
            } catch (er) {}
          } else {
            fs.closeSync(fd)
          }
        }
        return ret
      }

    } else if (fs.futimes) {
      fs.lutimes = function (_a, _b, _c, cb) { if (cb) process.nextTick(cb) }
      fs.lutimesSync = function () {}
    }
  }

  function chmodFix (orig) {
    if (!orig) return orig
    return function (target, mode, cb) {
      return orig.call(fs, target, mode, function (er) {
        if (chownErOk(er)) er = null
        if (cb) cb.apply(this, arguments)
      })
    }
  }

  function chmodFixSync (orig) {
    if (!orig) return orig
    return function (target, mode) {
      try {
        return orig.call(fs, target, mode)
      } catch (er) {
        if (!chownErOk(er)) throw er
      }
    }
  }


  function chownFix (orig) {
    if (!orig) return orig
    return function (target, uid, gid, cb) {
      return orig.call(fs, target, uid, gid, function (er) {
        if (chownErOk(er)) er = null
        if (cb) cb.apply(this, arguments)
      })
    }
  }

  function chownFixSync (orig) {
    if (!orig) return orig
    return function (target, uid, gid) {
      try {
        return orig.call(fs, target, uid, gid)
      } catch (er) {
        if (!chownErOk(er)) throw er
      }
    }
  }

  function statFix (orig) {
    if (!orig) return orig
    // Older versions of Node erroneously returned signed integers for
    // uid + gid.
    return function (target, options, cb) {
      if (typeof options === 'function') {
        cb = options
        options = null
      }
      function callback (er, stats) {
        if (stats) {
          if (stats.uid < 0) stats.uid += 0x100000000
          if (stats.gid < 0) stats.gid += 0x100000000
        }
        if (cb) cb.apply(this, arguments)
      }
      return options ? orig.call(fs, target, options, callback)
        : orig.call(fs, target, callback)
    }
  }

  function statFixSync (orig) {
    if (!orig) return orig
    // Older versions of Node erroneously returned signed integers for
    // uid + gid.
    return function (target, options) {
      var stats = options ? orig.call(fs, target, options)
        : orig.call(fs, target)
      if (stats) {
        if (stats.uid < 0) stats.uid += 0x100000000
        if (stats.gid < 0) stats.gid += 0x100000000
      }
      return stats;
    }
  }

  // ENOSYS means that the fs doesn't support the op. Just ignore
  // that, because it doesn't matter.
  //
  // if there's no getuid, or if getuid() is something other
  // than 0, and the error is EINVAL or EPERM, then just ignore
  // it.
  //
  // This specific case is a silent failure in cp, install, tar,
  // and most other unix tools that manage permissions.
  //
  // When running as root, or if other types of errors are
  // encountered, then it's strict.
  function chownErOk (er) {
    if (!er)
      return true

    if (er.code === "ENOSYS")
      return true

    var nonroot = !process.getuid || process.getuid() !== 0
    if (nonroot) {
      if (er.code === "EINVAL" || er.code === "EPERM")
        return true
    }

    return false
  }
}


/***/ }),

/***/ 3813:
/***/ ((module) => {

"use strict";


module.exports = (flag, argv = process.argv) => {
	const prefix = flag.startsWith('-') ? '' : (flag.length === 1 ? '-' : '--');
	const position = argv.indexOf(prefix + flag);
	const terminatorPosition = argv.indexOf('--');
	return position !== -1 && (terminatorPosition === -1 || position < terminatorPosition);
};


/***/ }),

/***/ 2064:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

var _fs
try {
  _fs = __nccwpck_require__(5744)
} catch (_) {
  _fs = __nccwpck_require__(9896)
}

function readFile (file, options, callback) {
  if (callback == null) {
    callback = options
    options = {}
  }

  if (typeof options === 'string') {
    options = {encoding: options}
  }

  options = options || {}
  var fs = options.fs || _fs

  var shouldThrow = true
  if ('throws' in options) {
    shouldThrow = options.throws
  }

  fs.readFile(file, options, function (err, data) {
    if (err) return callback(err)

    data = stripBom(data)

    var obj
    try {
      obj = JSON.parse(data, options ? options.reviver : null)
    } catch (err2) {
      if (shouldThrow) {
        err2.message = file + ': ' + err2.message
        return callback(err2)
      } else {
        return callback(null, null)
      }
    }

    callback(null, obj)
  })
}

function readFileSync (file, options) {
  options = options || {}
  if (typeof options === 'string') {
    options = {encoding: options}
  }

  var fs = options.fs || _fs

  var shouldThrow = true
  if ('throws' in options) {
    shouldThrow = options.throws
  }

  try {
    var content = fs.readFileSync(file, options)
    content = stripBom(content)
    return JSON.parse(content, options.reviver)
  } catch (err) {
    if (shouldThrow) {
      err.message = file + ': ' + err.message
      throw err
    } else {
      return null
    }
  }
}

function stringify (obj, options) {
  var spaces
  var EOL = '\n'
  if (typeof options === 'object' && options !== null) {
    if (options.spaces) {
      spaces = options.spaces
    }
    if (options.EOL) {
      EOL = options.EOL
    }
  }

  var str = JSON.stringify(obj, options ? options.replacer : null, spaces)

  return str.replace(/\n/g, EOL) + EOL
}

function writeFile (file, obj, options, callback) {
  if (callback == null) {
    callback = options
    options = {}
  }
  options = options || {}
  var fs = options.fs || _fs

  var str = ''
  try {
    str = stringify(obj, options)
  } catch (err) {
    // Need to return whether a callback was passed or not
    if (callback) callback(err, null)
    return
  }

  fs.writeFile(file, str, options, callback)
}

function writeFileSync (file, obj, options) {
  options = options || {}
  var fs = options.fs || _fs

  var str = stringify(obj, options)
  // not sure if fs.writeFileSync returns anything, but just in case
  return fs.writeFileSync(file, str, options)
}

function stripBom (content) {
  // we do this because JSON.parse would convert it to a utf8 string if encoding wasn't specified
  if (Buffer.isBuffer(content)) content = content.toString('utf8')
  content = content.replace(/^\uFEFF/, '')
  return content
}

var jsonfile = {
  readFile: readFile,
  readFileSync: readFileSync,
  writeFile: writeFile,
  writeFileSync: writeFileSync
}

module.exports = jsonfile


/***/ }),

/***/ 2838:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/* eslint max-classes-per-file: ["error", 2] */
/* eslint no-underscore-dangle: ["error", { "allow": ["_getLocationKeys"] }] */

const flatted = __nccwpck_require__(8686);
const levels = __nccwpck_require__(1630);

class SerDe {
  constructor() {
    const deserialise = {
      __LOG4JS_undefined__: undefined,
      __LOG4JS_NaN__: Number('abc'),
      __LOG4JS_Infinity__: 1 / 0,
      '__LOG4JS_-Infinity__': -1 / 0,
    };
    this.deMap = deserialise;
    this.serMap = {};
    Object.keys(this.deMap).forEach((key) => {
      const value = this.deMap[key];
      this.serMap[value] = key;
    });
  }

  canSerialise(key) {
    if (typeof key === 'string') return false;
    return key in this.serMap;
  }

  serialise(key) {
    if (this.canSerialise(key)) return this.serMap[key];
    return key;
  }

  canDeserialise(key) {
    return key in this.deMap;
  }

  deserialise(key) {
    if (this.canDeserialise(key)) return this.deMap[key];
    return key;
  }
}
const serde = new SerDe();

/**
 * @name LoggingEvent
 * @namespace Log4js
 */
class LoggingEvent {
  /**
   * Models a logging event.
   * @constructor
   * @param {string} categoryName name of category
   * @param {Log4js.Level} level level of message
   * @param {Array} data objects to log
   * @param {Error} [error]
   * @author Seth Chisamore
   */
  constructor(categoryName, level, data, context, location, error) {
    this.startTime = new Date();
    this.categoryName = categoryName;
    this.data = data;
    this.level = level;
    this.context = Object.assign({}, context); // eslint-disable-line prefer-object-spread
    this.pid = process.pid;
    this.error = error;

    if (typeof location !== 'undefined') {
      if (!location || typeof location !== 'object' || Array.isArray(location))
        throw new TypeError(
          'Invalid location type passed to LoggingEvent constructor'
        );

      this.constructor._getLocationKeys().forEach((key) => {
        if (typeof location[key] !== 'undefined') this[key] = location[key];
      });
    }
  }

  /** @private */
  static _getLocationKeys() {
    return [
      'fileName',
      'lineNumber',
      'columnNumber',
      'callStack',
      'className',
      'functionName',
      'functionAlias',
      'callerName',
    ];
  }

  serialise() {
    return flatted.stringify(this, (key, value) => {
      // JSON.stringify(new Error('test')) returns {}, which is not really useful for us.
      // The following allows us to serialize errors (semi) correctly.
      if (value instanceof Error) {
        // eslint-disable-next-line prefer-object-spread
        value = Object.assign(
          { message: value.message, stack: value.stack },
          value
        );
      }
      // JSON.stringify({a: Number('abc'), b: 1/0, c: -1/0}) returns {a: null, b: null, c: null}.
      // The following allows us to serialize to NaN, Infinity and -Infinity correctly.
      // JSON.stringify([undefined]) returns [null].
      // The following allows us to serialize to undefined correctly.
      return serde.serialise(value);
    });
  }

  static deserialise(serialised) {
    let event;
    try {
      const rehydratedEvent = flatted.parse(serialised, (key, value) => {
        if (value && value.message && value.stack) {
          const fakeError = new Error(value);
          Object.keys(value).forEach((k) => {
            fakeError[k] = value[k];
          });
          value = fakeError;
        }
        return serde.deserialise(value);
      });
      this._getLocationKeys().forEach((key) => {
        if (typeof rehydratedEvent[key] !== 'undefined') {
          if (!rehydratedEvent.location) rehydratedEvent.location = {};
          rehydratedEvent.location[key] = rehydratedEvent[key];
        }
      });
      event = new LoggingEvent(
        rehydratedEvent.categoryName,
        levels.getLevel(rehydratedEvent.level.levelStr),
        rehydratedEvent.data,
        rehydratedEvent.context,
        rehydratedEvent.location,
        rehydratedEvent.error
      );
      event.startTime = new Date(rehydratedEvent.startTime);
      event.pid = rehydratedEvent.pid;
      if (rehydratedEvent.cluster) {
        event.cluster = rehydratedEvent.cluster;
      }
    } catch (e) {
      event = new LoggingEvent('log4js', levels.ERROR, [
        'Unable to parse log:',
        serialised,
        'because: ',
        e,
      ]);
    }

    return event;
  }
}

module.exports = LoggingEvent;


/***/ }),

/***/ 3556:
/***/ ((module) => {

function maxFileSizeUnitTransform(maxLogSize) {
  if (typeof maxLogSize === 'number' && Number.isInteger(maxLogSize)) {
    return maxLogSize;
  }

  const units = {
    K: 1024,
    M: 1024 * 1024,
    G: 1024 * 1024 * 1024,
  };
  const validUnit = Object.keys(units);
  const unit = maxLogSize.slice(-1).toLocaleUpperCase();
  const value = maxLogSize.slice(0, -1).trim();

  if (validUnit.indexOf(unit) < 0 || !Number.isInteger(Number(value))) {
    throw Error(`maxLogSize: "${maxLogSize}" is invalid`);
  } else {
    return value * units[unit];
  }
}

function adapter(configAdapter, config) {
  const newConfig = Object.assign({}, config); // eslint-disable-line prefer-object-spread
  Object.keys(configAdapter).forEach((key) => {
    if (newConfig[key]) {
      newConfig[key] = configAdapter[key](config[key]);
    }
  });
  return newConfig;
}

function fileAppenderAdapter(config) {
  const configAdapter = {
    maxLogSize: maxFileSizeUnitTransform,
  };
  return adapter(configAdapter, config);
}

const adapters = {
  dateFile: fileAppenderAdapter,
  file: fileAppenderAdapter,
  fileSync: fileAppenderAdapter,
};

module.exports.modifyConfig = (config) =>
  adapters[config.type] ? adapters[config.type](config) : config;


/***/ }),

/***/ 8494:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:categoryFilter');

function categoryFilter(excludes, appender) {
  if (typeof excludes === 'string') excludes = [excludes];
  return (logEvent) => {
    debug(`Checking ${logEvent.categoryName} against ${excludes}`);
    if (excludes.indexOf(logEvent.categoryName) === -1) {
      debug('Not excluded, sending to appender');
      appender(logEvent);
    }
  };
}

function configure(config, layouts, findAppender) {
  const appender = findAppender(config.appender);
  return categoryFilter(config.exclude, appender);
}

module.exports.configure = configure;


/***/ }),

/***/ 6571:
/***/ ((module) => {

// eslint-disable-next-line no-console
const consoleLog = console.log.bind(console);

function consoleAppender(layout, timezoneOffset) {
  return (loggingEvent) => {
    consoleLog(layout(loggingEvent, timezoneOffset));
  };
}

function configure(config, layouts) {
  let layout = layouts.colouredLayout;
  if (config.layout) {
    layout = layouts.layout(config.layout.type, config.layout);
  }
  return consoleAppender(layout, config.timezoneOffset);
}

module.exports.configure = configure;


/***/ }),

/***/ 6614:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const streams = __nccwpck_require__(248);
const os = __nccwpck_require__(857);

const eol = os.EOL;

function openTheStream(filename, pattern, options) {
  const stream = new streams.DateRollingFileStream(filename, pattern, options);
  stream.on('error', (err) => {
    // eslint-disable-next-line no-console
    console.error(
      'log4js.dateFileAppender - Writing to file %s, error happened ',
      filename,
      err
    );
  });
  stream.on('drain', () => {
    process.emit('log4js:pause', false);
  });
  return stream;
}

/**
 * File appender that rolls files according to a date pattern.
 * @param filename base filename.
 * @param pattern the format that will be added to the end of filename when rolling,
 *          also used to check when to roll files - defaults to '.yyyy-MM-dd'
 * @param layout layout function for log messages - defaults to basicLayout
 * @param options - options to be passed to the underlying stream
 * @param timezoneOffset - optional timezone offset in minutes (default system local)
 */
function appender(filename, pattern, layout, options, timezoneOffset) {
  // the options for file appender use maxLogSize, but the docs say any file appender
  // options should work for dateFile as well.
  options.maxSize = options.maxLogSize;

  const writer = openTheStream(filename, pattern, options);

  const app = function (logEvent) {
    if (!writer.writable) {
      return;
    }
    if (!writer.write(layout(logEvent, timezoneOffset) + eol, 'utf8')) {
      process.emit('log4js:pause', true);
    }
  };

  app.shutdown = function (complete) {
    writer.end('', 'utf-8', complete);
  };

  return app;
}

function configure(config, layouts) {
  let layout = layouts.basicLayout;
  if (config.layout) {
    layout = layouts.layout(config.layout.type, config.layout);
  }

  if (!config.alwaysIncludePattern) {
    config.alwaysIncludePattern = false;
  }

  // security default (instead of relying on streamroller default)
  config.mode = config.mode || 0o600;

  return appender(
    config.filename,
    config.pattern,
    layout,
    config,
    config.timezoneOffset
  );
}

module.exports.configure = configure;


/***/ }),

/***/ 7602:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:file');
const path = __nccwpck_require__(6928);
const streams = __nccwpck_require__(248);
const os = __nccwpck_require__(857);

const eol = os.EOL;

let mainSighupListenerStarted = false;
const sighupListeners = new Set();
function mainSighupHandler() {
  sighupListeners.forEach((app) => {
    app.sighupHandler();
  });
}

/**
 * File Appender writing the logs to a text file. Supports rolling of logs by size.
 *
 * @param file the file log messages will be written to
 * @param layout a function that takes a logEvent and returns a string
 *   (defaults to basicLayout).
 * @param logSize - the maximum size (in bytes) for a log file,
 *   if not provided then logs won't be rotated.
 * @param numBackups - the number of log files to keep after logSize
 *   has been reached (default 5)
 * @param options - options to be passed to the underlying stream
 * @param timezoneOffset - optional timezone offset in minutes (default system local)
 */
function fileAppender(
  file,
  layout,
  logSize,
  numBackups,
  options,
  timezoneOffset
) {
  if (typeof file !== 'string' || file.length === 0) {
    throw new Error(`Invalid filename: ${file}`);
  } else if (file.endsWith(path.sep)) {
    throw new Error(`Filename is a directory: ${file}`);
  } else if (file.indexOf(`~${path.sep}`) === 0) {
    // handle ~ expansion: https://github.com/nodejs/node/issues/684
    // exclude ~ and ~filename as these can be valid files
    file = file.replace('~', os.homedir());
  }
  file = path.normalize(file);
  numBackups = !numBackups && numBackups !== 0 ? 5 : numBackups;

  debug(
    'Creating file appender (',
    file,
    ', ',
    logSize,
    ', ',
    numBackups,
    ', ',
    options,
    ', ',
    timezoneOffset,
    ')'
  );

  function openTheStream(filePath, fileSize, numFiles, opt) {
    const stream = new streams.RollingFileStream(
      filePath,
      fileSize,
      numFiles,
      opt
    );
    stream.on('error', (err) => {
      // eslint-disable-next-line no-console
      console.error(
        'log4js.fileAppender - Writing to file %s, error happened ',
        filePath,
        err
      );
    });
    stream.on('drain', () => {
      process.emit('log4js:pause', false);
    });
    return stream;
  }

  let writer = openTheStream(file, logSize, numBackups, options);

  const app = function (loggingEvent) {
    if (!writer.writable) {
      return;
    }
    if (options.removeColor === true) {
      // eslint-disable-next-line no-control-regex
      const regex = /\x1b[[0-9;]*m/g;
      loggingEvent.data = loggingEvent.data.map((d) => {
        if (typeof d === 'string') return d.replace(regex, '');
        return d;
      });
    }
    if (!writer.write(layout(loggingEvent, timezoneOffset) + eol, 'utf8')) {
      process.emit('log4js:pause', true);
    }
  };

  app.reopen = function () {
    writer.end(() => {
      writer = openTheStream(file, logSize, numBackups, options);
    });
  };

  app.sighupHandler = function () {
    debug('SIGHUP handler called.');
    app.reopen();
  };

  app.shutdown = function (complete) {
    sighupListeners.delete(app);
    if (sighupListeners.size === 0 && mainSighupListenerStarted) {
      process.removeListener('SIGHUP', mainSighupHandler);
      mainSighupListenerStarted = false;
    }
    writer.end('', 'utf-8', complete);
  };

  // On SIGHUP, close and reopen all files. This allows this appender to work with
  // logrotate. Note that if you are using logrotate, you should not set
  // `logSize`.
  sighupListeners.add(app);
  if (!mainSighupListenerStarted) {
    process.on('SIGHUP', mainSighupHandler);
    mainSighupListenerStarted = true;
  }

  return app;
}

function configure(config, layouts) {
  let layout = layouts.basicLayout;
  if (config.layout) {
    layout = layouts.layout(config.layout.type, config.layout);
  }

  // security default (instead of relying on streamroller default)
  config.mode = config.mode || 0o600;

  return fileAppender(
    config.filename,
    layout,
    config.maxLogSize,
    config.backups,
    config,
    config.timezoneOffset
  );
}

module.exports.configure = configure;


/***/ }),

/***/ 7673:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:fileSync');
const path = __nccwpck_require__(6928);
const fs = __nccwpck_require__(9896);
const os = __nccwpck_require__(857);

const eol = os.EOL;

function touchFile(file, options) {
  // attempt to create the directory
  const mkdir = (dir) => {
    try {
      return fs.mkdirSync(dir, { recursive: true });
    } catch (e) {
      // backward-compatible fs.mkdirSync for nodejs pre-10.12.0 (without recursive option)
      // recursive creation of parent first
      if (e.code === 'ENOENT') {
        mkdir(path.dirname(dir));
        return mkdir(dir);
      }

      // throw error for all except EEXIST and EROFS (read-only filesystem)
      if (e.code !== 'EEXIST' && e.code !== 'EROFS') {
        throw e;
      }

      // EEXIST: throw if file and not directory
      // EROFS : throw if directory not found
      else {
        try {
          if (fs.statSync(dir).isDirectory()) {
            return dir;
          }
          throw e;
        } catch (err) {
          throw e;
        }
      }
    }
  };
  mkdir(path.dirname(file));

  // try to throw EISDIR, EROFS, EACCES
  fs.appendFileSync(file, '', { mode: options.mode, flag: options.flags });
}

class RollingFileSync {
  constructor(filename, maxLogSize, backups, options) {
    debug('In RollingFileStream');

    if (maxLogSize < 0) {
      throw new Error(`maxLogSize (${maxLogSize}) should be > 0`);
    }

    this.filename = filename;
    this.size = maxLogSize;
    this.backups = backups;
    this.options = options;
    this.currentSize = 0;

    function currentFileSize(file) {
      let fileSize = 0;

      try {
        fileSize = fs.statSync(file).size;
      } catch (e) {
        // file does not exist
        touchFile(file, options);
      }
      return fileSize;
    }

    this.currentSize = currentFileSize(this.filename);
  }

  shouldRoll() {
    debug(
      'should roll with current size %d, and max size %d',
      this.currentSize,
      this.size
    );
    return this.currentSize >= this.size;
  }

  roll(filename) {
    const that = this;
    const nameMatcher = new RegExp(`^${path.basename(filename)}`);

    function justTheseFiles(item) {
      return nameMatcher.test(item);
    }

    function index(filename_) {
      return (
        parseInt(filename_.slice(`${path.basename(filename)}.`.length), 10) || 0
      );
    }

    function byIndex(a, b) {
      return index(a) - index(b);
    }

    function increaseFileIndex(fileToRename) {
      const idx = index(fileToRename);
      debug(`Index of ${fileToRename} is ${idx}`);
      if (that.backups === 0) {
        fs.truncateSync(filename, 0);
      } else if (idx < that.backups) {
        // on windows, you can get a EEXIST error if you rename a file to an existing file
        // so, we'll try to delete the file we're renaming to first
        try {
          fs.unlinkSync(`${filename}.${idx + 1}`);
        } catch (e) {
          // ignore err: if we could not delete, it's most likely that it doesn't exist
        }

        debug(`Renaming ${fileToRename} -> ${filename}.${idx + 1}`);
        fs.renameSync(
          path.join(path.dirname(filename), fileToRename),
          `${filename}.${idx + 1}`
        );
      }
    }

    function renameTheFiles() {
      // roll the backups (rename file.n to file.n+1, where n <= numBackups)
      debug('Renaming the old files');

      const files = fs.readdirSync(path.dirname(filename));
      files
        .filter(justTheseFiles)
        .sort(byIndex)
        .reverse()
        .forEach(increaseFileIndex);
    }

    debug('Rolling, rolling, rolling');
    renameTheFiles();
  }

  // eslint-disable-next-line no-unused-vars
  write(chunk, encoding) {
    const that = this;

    function writeTheChunk() {
      debug('writing the chunk to the file');
      that.currentSize += chunk.length;
      fs.appendFileSync(that.filename, chunk);
    }

    debug('in write');

    if (this.shouldRoll()) {
      this.currentSize = 0;
      this.roll(this.filename);
    }

    writeTheChunk();
  }
}

/**
 * File Appender writing the logs to a text file. Supports rolling of logs by size.
 *
 * @param file the file log messages will be written to
 * @param layout a function that takes a logevent and returns a string
 *   (defaults to basicLayout).
 * @param logSize - the maximum size (in bytes) for a log file,
 *   if not provided then logs won't be rotated.
 * @param numBackups - the number of log files to keep after logSize
 *   has been reached (default 5)
 * @param options - options to be passed to the underlying stream
 * @param timezoneOffset - optional timezone offset in minutes (default system local)
 */
function fileAppender(
  file,
  layout,
  logSize,
  numBackups,
  options,
  timezoneOffset
) {
  if (typeof file !== 'string' || file.length === 0) {
    throw new Error(`Invalid filename: ${file}`);
  } else if (file.endsWith(path.sep)) {
    throw new Error(`Filename is a directory: ${file}`);
  } else if (file.indexOf(`~${path.sep}`) === 0) {
    // handle ~ expansion: https://github.com/nodejs/node/issues/684
    // exclude ~ and ~filename as these can be valid files
    file = file.replace('~', os.homedir());
  }
  file = path.normalize(file);
  numBackups = !numBackups && numBackups !== 0 ? 5 : numBackups;

  debug(
    'Creating fileSync appender (',
    file,
    ', ',
    logSize,
    ', ',
    numBackups,
    ', ',
    options,
    ', ',
    timezoneOffset,
    ')'
  );

  function openTheStream(filePath, fileSize, numFiles) {
    let stream;

    if (fileSize) {
      stream = new RollingFileSync(filePath, fileSize, numFiles, options);
    } else {
      stream = ((f) => {
        // touch the file to apply flags (like w to truncate the file)
        touchFile(f, options);

        return {
          write(data) {
            fs.appendFileSync(f, data);
          },
        };
      })(filePath);
    }

    return stream;
  }

  const logFile = openTheStream(file, logSize, numBackups);

  return (loggingEvent) => {
    logFile.write(layout(loggingEvent, timezoneOffset) + eol);
  };
}

function configure(config, layouts) {
  let layout = layouts.basicLayout;
  if (config.layout) {
    layout = layouts.layout(config.layout.type, config.layout);
  }

  const options = {
    flags: config.flags || 'a',
    encoding: config.encoding || 'utf8',
    mode: config.mode || 0o600,
  };

  return fileAppender(
    config.filename,
    layout,
    config.maxLogSize,
    config.backups,
    options,
    config.timezoneOffset
  );
}

module.exports.configure = configure;


/***/ }),

/***/ 3718:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const path = __nccwpck_require__(6928);
const debug = __nccwpck_require__(2830)('log4js:appenders');
const configuration = __nccwpck_require__(8507);
const clustering = __nccwpck_require__(455);
const levels = __nccwpck_require__(1630);
const layouts = __nccwpck_require__(6794);
const adapters = __nccwpck_require__(3556);

// pre-load the core appenders so that webpack can find them
const coreAppenders = new Map();
coreAppenders.set('console', __nccwpck_require__(6571));
coreAppenders.set('stdout', __nccwpck_require__(9303));
coreAppenders.set('stderr', __nccwpck_require__(8680));
coreAppenders.set('logLevelFilter', __nccwpck_require__(2722));
coreAppenders.set('categoryFilter', __nccwpck_require__(8494));
coreAppenders.set('noLogFilter', __nccwpck_require__(8799));
coreAppenders.set('file', __nccwpck_require__(7602));
coreAppenders.set('dateFile', __nccwpck_require__(6614));
coreAppenders.set('fileSync', __nccwpck_require__(7673));
coreAppenders.set('tcp', __nccwpck_require__(1477));

const appenders = new Map();

const tryLoading = (modulePath, config) => {
  let resolvedPath;
  try {
    const modulePathCJS = `${modulePath}.cjs`;
    resolvedPath = require.resolve(modulePathCJS);
    debug('Loading module from ', modulePathCJS);
  } catch (e) {
    resolvedPath = modulePath;
    debug('Loading module from ', modulePath);
  }
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    return require(resolvedPath);
  } catch (e) {
    // if the module was found, and we still got an error, then raise it
    configuration.throwExceptionIf(
      config,
      e.code !== 'MODULE_NOT_FOUND',
      `appender "${modulePath}" could not be loaded (error was: ${e})`
    );
    return undefined;
  }
};

const loadAppenderModule = (type, config) =>
  coreAppenders.get(type) ||
  tryLoading(`./${type}`, config) ||
  tryLoading(type, config) ||
  (require.main &&
    require.main.filename &&
    tryLoading(path.join(path.dirname(require.main.filename), type), config)) ||
  tryLoading(path.join(process.cwd(), type), config);

const appendersLoading = new Set();

const getAppender = (name, config) => {
  if (appenders.has(name)) return appenders.get(name);
  if (!config.appenders[name]) return false;
  if (appendersLoading.has(name))
    throw new Error(`Dependency loop detected for appender ${name}.`);
  appendersLoading.add(name);

  debug(`Creating appender ${name}`);
  // eslint-disable-next-line no-use-before-define
  const appender = createAppender(name, config);
  appendersLoading.delete(name);
  appenders.set(name, appender);
  return appender;
};

const createAppender = (name, config) => {
  const appenderConfig = config.appenders[name];
  const appenderModule = appenderConfig.type.configure
    ? appenderConfig.type
    : loadAppenderModule(appenderConfig.type, config);
  configuration.throwExceptionIf(
    config,
    configuration.not(appenderModule),
    `appender "${name}" is not valid (type "${appenderConfig.type}" could not be found)`
  );
  if (appenderModule.appender) {
    process.emitWarning(
      `Appender ${appenderConfig.type} exports an appender function.`,
      'DeprecationWarning',
      'log4js-node-DEP0001'
    );
    debug(
      '[log4js-node-DEP0001]',
      `DEPRECATION: Appender ${appenderConfig.type} exports an appender function.`
    );
  }
  if (appenderModule.shutdown) {
    process.emitWarning(
      `Appender ${appenderConfig.type} exports a shutdown function.`,
      'DeprecationWarning',
      'log4js-node-DEP0002'
    );
    debug(
      '[log4js-node-DEP0002]',
      `DEPRECATION: Appender ${appenderConfig.type} exports a shutdown function.`
    );
  }

  debug(`${name}: clustering.isMaster ? ${clustering.isMaster()}`);
  debug(
    // eslint-disable-next-line global-require
    `${name}: appenderModule is ${(__nccwpck_require__(9023).inspect)(appenderModule)}`
  );
  return clustering.onlyOnMaster(
    () => {
      debug(
        `calling appenderModule.configure for ${name} / ${appenderConfig.type}`
      );
      return appenderModule.configure(
        adapters.modifyConfig(appenderConfig),
        layouts,
        (appender) => getAppender(appender, config),
        levels
      );
    },
    /* istanbul ignore next: fn never gets called by non-master yet needed to pass config validation */ () => {}
  );
};

const setup = (config) => {
  appenders.clear();
  appendersLoading.clear();
  if (!config) {
    return;
  }

  const usedAppenders = [];
  Object.values(config.categories).forEach((category) => {
    usedAppenders.push(...category.appenders);
  });
  Object.keys(config.appenders).forEach((name) => {
    // dodgy hard-coding of special case for tcp-server and multiprocess which may not have
    // any categories associated with it, but needs to be started up anyway
    if (
      usedAppenders.includes(name) ||
      config.appenders[name].type === 'tcp-server' ||
      config.appenders[name].type === 'multiprocess'
    ) {
      getAppender(name, config);
    }
  });
};

const init = () => {
  setup();
};
init();

configuration.addListener((config) => {
  configuration.throwExceptionIf(
    config,
    configuration.not(configuration.anObject(config.appenders)),
    'must have a property "appenders" of type object.'
  );
  const appenderNames = Object.keys(config.appenders);
  configuration.throwExceptionIf(
    config,
    configuration.not(appenderNames.length),
    'must define at least one appender.'
  );

  appenderNames.forEach((name) => {
    configuration.throwExceptionIf(
      config,
      configuration.not(config.appenders[name].type),
      `appender "${name}" is not valid (must be an object with property "type")`
    );
  });
});

configuration.addListener(setup);

module.exports = appenders;
module.exports.init = init;


/***/ }),

/***/ 2722:
/***/ ((module) => {

function logLevelFilter(minLevelString, maxLevelString, appender, levels) {
  const minLevel = levels.getLevel(minLevelString);
  const maxLevel = levels.getLevel(maxLevelString, levels.FATAL);
  return (logEvent) => {
    const eventLevel = logEvent.level;
    if (
      minLevel.isLessThanOrEqualTo(eventLevel) &&
      maxLevel.isGreaterThanOrEqualTo(eventLevel)
    ) {
      appender(logEvent);
    }
  };
}

function configure(config, layouts, findAppender, levels) {
  const appender = findAppender(config.appender);
  return logLevelFilter(config.level, config.maxLevel, appender, levels);
}

module.exports.configure = configure;


/***/ }),

/***/ 8799:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:noLogFilter');

/**
 * The function removes empty or null regexp from the array
 * @param {string[]} regexp
 * @returns {string[]} a filtered string array with not empty or null regexp
 */
function removeNullOrEmptyRegexp(regexp) {
  const filtered = regexp.filter((el) => el != null && el !== '');
  return filtered;
}

/**
 * Returns a function that will exclude the events in case they match
 * with the regular expressions provided
 * @param {(string|string[])} filters contains the regexp that will be used for the evaluation
 * @param {*} appender
 * @returns {function}
 */
function noLogFilter(filters, appender) {
  return (logEvent) => {
    debug(`Checking data: ${logEvent.data} against filters: ${filters}`);
    if (typeof filters === 'string') {
      filters = [filters];
    }
    filters = removeNullOrEmptyRegexp(filters);
    const regex = new RegExp(filters.join('|'), 'i');
    if (
      filters.length === 0 ||
      logEvent.data.findIndex((value) => regex.test(value)) < 0
    ) {
      debug('Not excluded, sending to appender');
      appender(logEvent);
    }
  };
}

function configure(config, layouts, findAppender) {
  const appender = findAppender(config.appender);
  return noLogFilter(config.exclude, appender);
}

module.exports.configure = configure;


/***/ }),

/***/ 1149:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:recording');

const recordedEvents = [];

function configure() {
  return function (logEvent) {
    debug(
      `received logEvent, number of events now ${recordedEvents.length + 1}`
    );
    debug('log event was ', logEvent);
    recordedEvents.push(logEvent);
  };
}

function replay() {
  return recordedEvents.slice();
}

function reset() {
  recordedEvents.length = 0;
}

module.exports = {
  configure,
  replay,
  playback: replay,
  reset,
  erase: reset,
};


/***/ }),

/***/ 8680:
/***/ ((module) => {

function stderrAppender(layout, timezoneOffset) {
  return (loggingEvent) => {
    process.stderr.write(`${layout(loggingEvent, timezoneOffset)}\n`);
  };
}

function configure(config, layouts) {
  let layout = layouts.colouredLayout;
  if (config.layout) {
    layout = layouts.layout(config.layout.type, config.layout);
  }
  return stderrAppender(layout, config.timezoneOffset);
}

module.exports.configure = configure;


/***/ }),

/***/ 9303:
/***/ ((__unused_webpack_module, exports) => {

function stdoutAppender(layout, timezoneOffset) {
  return (loggingEvent) => {
    process.stdout.write(`${layout(loggingEvent, timezoneOffset)}\n`);
  };
}

function configure(config, layouts) {
  let layout = layouts.colouredLayout;
  if (config.layout) {
    layout = layouts.layout(config.layout.type, config.layout);
  }
  return stdoutAppender(layout, config.timezoneOffset);
}

exports.configure = configure;


/***/ }),

/***/ 1477:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:tcp');
const net = __nccwpck_require__(9278);

function appender(config, layout) {
  let canWrite = false;
  const buffer = [];
  let socket;
  let shutdownAttempts = 3;
  let endMsg = '__LOG4JS__';

  function write(loggingEvent) {
    debug('Writing log event to socket');
    canWrite = socket.write(`${layout(loggingEvent)}${endMsg}`, 'utf8');
  }

  function emptyBuffer() {
    let evt;
    debug('emptying buffer');
    while ((evt = buffer.shift())) {
      write(evt);
    }
  }

  function createSocket() {
    debug(
      `appender creating socket to ${config.host || 'localhost'}:${
        config.port || 5000
      }`
    );
    endMsg = `${config.endMsg || '__LOG4JS__'}`;
    socket = net.createConnection(
      config.port || 5000,
      config.host || 'localhost'
    );
    socket.on('connect', () => {
      debug('socket connected');
      emptyBuffer();
      canWrite = true;
    });
    socket.on('drain', () => {
      debug('drain event received, emptying buffer');
      canWrite = true;
      emptyBuffer();
    });
    socket.on('timeout', socket.end.bind(socket));
    socket.on('error', (e) => {
      debug('connection error', e);
      canWrite = false;
      emptyBuffer();
    });
    socket.on('close', createSocket);
  }

  createSocket();

  function log(loggingEvent) {
    if (canWrite) {
      write(loggingEvent);
    } else {
      debug('buffering log event because it cannot write at the moment');
      buffer.push(loggingEvent);
    }
  }

  log.shutdown = function (cb) {
    debug('shutdown called');
    if (buffer.length && shutdownAttempts) {
      debug('buffer has items, waiting 100ms to empty');
      shutdownAttempts -= 1;
      setTimeout(() => {
        log.shutdown(cb);
      }, 100);
    } else {
      socket.removeAllListeners('close');
      socket.end(cb);
    }
  };
  return log;
}

function configure(config, layouts) {
  debug(`configure with config = ${config}`);
  let layout = function (loggingEvent) {
    return loggingEvent.serialise();
  };
  if (config.layout) {
    layout = layouts.layout(config.layout.type, config.layout);
  }
  return appender(config, layout);
}

module.exports.configure = configure;


/***/ }),

/***/ 8185:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:categories');
const configuration = __nccwpck_require__(8507);
const levels = __nccwpck_require__(1630);
const appenders = __nccwpck_require__(3718);

const categories = new Map();

/**
 * Add inherited config to this category.  That includes extra appenders from parent,
 * and level, if none is set on this category.
 * This is recursive, so each parent also gets loaded with inherited appenders.
 * Inheritance is blocked if a category has inherit=false
 * @param  {*} config
 * @param  {*} category the child category
 * @param  {string} categoryName dotted path to category
 * @return {void}
 */
function inheritFromParent(config, category, categoryName) {
  if (category.inherit === false) return;
  const lastDotIndex = categoryName.lastIndexOf('.');
  if (lastDotIndex < 0) return; // category is not a child
  const parentCategoryName = categoryName.slice(0, lastDotIndex);
  let parentCategory = config.categories[parentCategoryName];

  if (!parentCategory) {
    // parent is missing, so implicitly create it, so that it can inherit from its parents
    parentCategory = { inherit: true, appenders: [] };
  }

  // make sure parent has had its inheritance taken care of before pulling its properties to this child
  inheritFromParent(config, parentCategory, parentCategoryName);

  // if the parent is not in the config (because we just created it above),
  // and it inherited a valid configuration, add it to config.categories
  if (
    !config.categories[parentCategoryName] &&
    parentCategory.appenders &&
    parentCategory.appenders.length &&
    parentCategory.level
  ) {
    config.categories[parentCategoryName] = parentCategory;
  }

  category.appenders = category.appenders || [];
  category.level = category.level || parentCategory.level;

  // merge in appenders from parent (parent is already holding its inherited appenders)
  parentCategory.appenders.forEach((ap) => {
    if (!category.appenders.includes(ap)) {
      category.appenders.push(ap);
    }
  });
  category.parent = parentCategory;
}

/**
 * Walk all categories in the config, and pull down any configuration from parent to child.
 * This includes inherited appenders, and level, where level is not set.
 * Inheritance is skipped where a category has inherit=false.
 * @param  {*} config
 */
function addCategoryInheritance(config) {
  if (!config.categories) return;
  const categoryNames = Object.keys(config.categories);
  categoryNames.forEach((name) => {
    const category = config.categories[name];
    // add inherited appenders and level to this category
    inheritFromParent(config, category, name);
  });
}

configuration.addPreProcessingListener((config) =>
  addCategoryInheritance(config)
);

configuration.addListener((config) => {
  configuration.throwExceptionIf(
    config,
    configuration.not(configuration.anObject(config.categories)),
    'must have a property "categories" of type object.'
  );

  const categoryNames = Object.keys(config.categories);
  configuration.throwExceptionIf(
    config,
    configuration.not(categoryNames.length),
    'must define at least one category.'
  );

  categoryNames.forEach((name) => {
    const category = config.categories[name];
    configuration.throwExceptionIf(
      config,
      [
        configuration.not(category.appenders),
        configuration.not(category.level),
      ],
      `category "${name}" is not valid (must be an object with properties "appenders" and "level")`
    );

    configuration.throwExceptionIf(
      config,
      configuration.not(Array.isArray(category.appenders)),
      `category "${name}" is not valid (appenders must be an array of appender names)`
    );

    configuration.throwExceptionIf(
      config,
      configuration.not(category.appenders.length),
      `category "${name}" is not valid (appenders must contain at least one appender name)`
    );

    if (Object.prototype.hasOwnProperty.call(category, 'enableCallStack')) {
      configuration.throwExceptionIf(
        config,
        typeof category.enableCallStack !== 'boolean',
        `category "${name}" is not valid (enableCallStack must be boolean type)`
      );
    }

    category.appenders.forEach((appender) => {
      configuration.throwExceptionIf(
        config,
        configuration.not(appenders.get(appender)),
        `category "${name}" is not valid (appender "${appender}" is not defined)`
      );
    });

    configuration.throwExceptionIf(
      config,
      configuration.not(levels.getLevel(category.level)),
      `category "${name}" is not valid (level "${category.level}" not recognised;` +
        ` valid levels are ${levels.levels.join(', ')})`
    );
  });

  configuration.throwExceptionIf(
    config,
    configuration.not(config.categories.default),
    'must define a "default" category.'
  );
});

const setup = (config) => {
  categories.clear();
  if (!config) {
    return;
  }

  const categoryNames = Object.keys(config.categories);
  categoryNames.forEach((name) => {
    const category = config.categories[name];
    const categoryAppenders = [];
    category.appenders.forEach((appender) => {
      categoryAppenders.push(appenders.get(appender));
      debug(`Creating category ${name}`);
      categories.set(name, {
        appenders: categoryAppenders,
        level: levels.getLevel(category.level),
        enableCallStack: category.enableCallStack || false,
      });
    });
  });
};

const init = () => {
  setup();
};
init();

configuration.addListener(setup);

const configForCategory = (category) => {
  debug(`configForCategory: searching for config for ${category}`);
  if (categories.has(category)) {
    debug(`configForCategory: ${category} exists in config, returning it`);
    return categories.get(category);
  }

  let sourceCategoryConfig;
  if (category.indexOf('.') > 0) {
    debug(`configForCategory: ${category} has hierarchy, cloning from parents`);
    sourceCategoryConfig = {
      ...configForCategory(category.slice(0, category.lastIndexOf('.'))),
    };
  } else {
    if (!categories.has('default')) {
      setup({ categories: { default: { appenders: ['out'], level: 'OFF' } } });
    }
    debug('configForCategory: cloning default category');
    sourceCategoryConfig = { ...categories.get('default') };
  }
  categories.set(category, sourceCategoryConfig);
  return sourceCategoryConfig;
};

const appendersForCategory = (category) =>
  configForCategory(category).appenders;

const getLevelForCategory = (category) => configForCategory(category).level;
const setLevelForCategory = (category, level) => {
  configForCategory(category).level = level;
};

const getEnableCallStackForCategory = (category) =>
  configForCategory(category).enableCallStack === true;
const setEnableCallStackForCategory = (category, useCallStack) => {
  configForCategory(category).enableCallStack = useCallStack;
};

module.exports = categories;
module.exports = Object.assign(module.exports, {
  appendersForCategory,
  getLevelForCategory,
  setLevelForCategory,
  getEnableCallStackForCategory,
  setEnableCallStackForCategory,
  init,
});


/***/ }),

/***/ 455:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('log4js:clustering');
const LoggingEvent = __nccwpck_require__(2838);
const configuration = __nccwpck_require__(8507);

let disabled = false;
let cluster = null;
try {
  // eslint-disable-next-line global-require
  cluster = __nccwpck_require__(9907);
} catch (e) {
  debug('cluster module not present');
  disabled = true;
}

const listeners = [];

let pm2 = false;
let pm2InstanceVar = 'NODE_APP_INSTANCE';

const isPM2Master = () => pm2 && process.env[pm2InstanceVar] === '0';
const isMaster = () =>
  disabled || (cluster && cluster.isMaster) || isPM2Master();

const sendToListeners = (logEvent) => {
  listeners.forEach((l) => l(logEvent));
};

// in a multi-process node environment, worker loggers will use
// process.send
const receiver = (worker, message) => {
  // prior to node v6, the worker parameter was not passed (args were message, handle)
  debug('cluster message received from worker ', worker, ': ', message);
  if (worker.topic && worker.data) {
    message = worker;
    worker = undefined;
  }
  if (message && message.topic && message.topic === 'log4js:message') {
    debug('received message: ', message.data);
    const logEvent = LoggingEvent.deserialise(message.data);
    sendToListeners(logEvent);
  }
};

if (!disabled) {
  configuration.addListener((config) => {
    // clear out the listeners, because configure has been called.
    listeners.length = 0;

    ({
      pm2,
      disableClustering: disabled,
      pm2InstanceVar = 'NODE_APP_INSTANCE',
    } = config);

    debug(`clustering disabled ? ${disabled}`);
    debug(`cluster.isMaster ? ${cluster && cluster.isMaster}`);
    debug(`pm2 enabled ? ${pm2}`);
    debug(`pm2InstanceVar = ${pm2InstanceVar}`);
    debug(`process.env[${pm2InstanceVar}] = ${process.env[pm2InstanceVar]}`);

    // just in case configure is called after shutdown
    if (pm2) {
      process.removeListener('message', receiver);
    }
    if (cluster && cluster.removeListener) {
      cluster.removeListener('message', receiver);
    }

    if (disabled || config.disableClustering) {
      debug('Not listening for cluster messages, because clustering disabled.');
    } else if (isPM2Master()) {
      // PM2 cluster support
      // PM2 runs everything as workers - install pm2-intercom for this to work.
      // we only want one of the app instances to write logs
      debug('listening for PM2 broadcast messages');
      process.on('message', receiver);
    } else if (cluster && cluster.isMaster) {
      debug('listening for cluster messages');
      cluster.on('message', receiver);
    } else {
      debug('not listening for messages, because we are not a master process');
    }
  });
}

module.exports = {
  onlyOnMaster: (fn, notMaster) => (isMaster() ? fn() : notMaster),
  isMaster,
  send: (msg) => {
    if (isMaster()) {
      sendToListeners(msg);
    } else {
      if (!pm2) {
        msg.cluster = {
          workerId: cluster.worker.id,
          worker: process.pid,
        };
      }
      process.send({ topic: 'log4js:message', data: msg.serialise() });
    }
  },
  onMessage: (listener) => {
    listeners.push(listener);
  },
};


/***/ }),

/***/ 8507:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const util = __nccwpck_require__(9023);
const debug = __nccwpck_require__(2830)('log4js:configuration');

const preProcessingListeners = [];
const listeners = [];

const not = (thing) => !thing;

const anObject = (thing) =>
  thing && typeof thing === 'object' && !Array.isArray(thing);

const validIdentifier = (thing) => /^[A-Za-z][A-Za-z0-9_]*$/g.test(thing);

const anInteger = (thing) =>
  thing && typeof thing === 'number' && Number.isInteger(thing);

const addListener = (fn) => {
  listeners.push(fn);
  debug(`Added listener, now ${listeners.length} listeners`);
};

const addPreProcessingListener = (fn) => {
  preProcessingListeners.push(fn);
  debug(
    `Added pre-processing listener, now ${preProcessingListeners.length} listeners`
  );
};

const throwExceptionIf = (config, checks, message) => {
  const tests = Array.isArray(checks) ? checks : [checks];
  tests.forEach((test) => {
    if (test) {
      throw new Error(
        `Problem with log4js configuration: (${util.inspect(config, {
          depth: 5,
        })}) - ${message}`
      );
    }
  });
};

const configure = (candidate) => {
  debug('New configuration to be validated: ', candidate);
  throwExceptionIf(candidate, not(anObject(candidate)), 'must be an object.');

  debug(`Calling pre-processing listeners (${preProcessingListeners.length})`);
  preProcessingListeners.forEach((listener) => listener(candidate));
  debug('Configuration pre-processing finished.');

  debug(`Calling configuration listeners (${listeners.length})`);
  listeners.forEach((listener) => listener(candidate));
  debug('Configuration finished.');
};

module.exports = {
  configure,
  addListener,
  addPreProcessingListener,
  throwExceptionIf,
  anObject,
  anInteger,
  validIdentifier,
  not,
};


/***/ }),

/***/ 8256:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/* eslint no-underscore-dangle: ["error", { "allow": ["__statusCode", "_remoteAddress", "__headers", "_logging"] }] */

const levels = __nccwpck_require__(1630);

const DEFAULT_FORMAT =
  ':remote-addr - -' +
  ' ":method :url HTTP/:http-version"' +
  ' :status :content-length ":referrer"' +
  ' ":user-agent"';

/**
 * Return request url path,
 * adding this function prevents the Cyclomatic Complexity,
 * for the assemble_tokens function at low, to pass the tests.
 *
 * @param  {IncomingMessage} req
 * @return {string}
 * @api private
 */
function getUrl(req) {
  return req.originalUrl || req.url;
}

/**
 * Adds custom {token, replacement} objects to defaults,
 * overwriting the defaults if any tokens clash
 *
 * @param  {IncomingMessage} req
 * @param  {ServerResponse} res
 * @param  {Array} customTokens
 *    [{ token: string-or-regexp, replacement: string-or-replace-function }]
 * @return {Array}
 */
function assembleTokens(req, res, customTokens) {
  const arrayUniqueTokens = (array) => {
    const a = array.concat();
    for (let i = 0; i < a.length; ++i) {
      for (let j = i + 1; j < a.length; ++j) {
        // not === because token can be regexp object
        // eslint-disable-next-line eqeqeq
        if (a[i].token == a[j].token) {
          a.splice(j--, 1); // eslint-disable-line no-plusplus
        }
      }
    }
    return a;
  };

  const defaultTokens = [];
  defaultTokens.push({ token: ':url', replacement: getUrl(req) });
  defaultTokens.push({ token: ':protocol', replacement: req.protocol });
  defaultTokens.push({ token: ':hostname', replacement: req.hostname });
  defaultTokens.push({ token: ':method', replacement: req.method });
  defaultTokens.push({
    token: ':status',
    replacement: res.__statusCode || res.statusCode,
  });
  defaultTokens.push({
    token: ':response-time',
    replacement: res.responseTime,
  });
  defaultTokens.push({ token: ':date', replacement: new Date().toUTCString() });
  defaultTokens.push({
    token: ':referrer',
    replacement: req.headers.referer || req.headers.referrer || '',
  });
  defaultTokens.push({
    token: ':http-version',
    replacement: `${req.httpVersionMajor}.${req.httpVersionMinor}`,
  });
  defaultTokens.push({
    token: ':remote-addr',
    replacement:
      req.headers['x-forwarded-for'] ||
      req.ip ||
      req._remoteAddress ||
      (req.socket &&
        (req.socket.remoteAddress ||
          (req.socket.socket && req.socket.socket.remoteAddress))),
  });
  defaultTokens.push({
    token: ':user-agent',
    replacement: req.headers['user-agent'],
  });
  defaultTokens.push({
    token: ':content-length',
    replacement:
      res.getHeader('content-length') ||
      (res.__headers && res.__headers['Content-Length']) ||
      '-',
  });
  defaultTokens.push({
    token: /:req\[([^\]]+)]/g,
    replacement(_, field) {
      return req.headers[field.toLowerCase()];
    },
  });
  defaultTokens.push({
    token: /:res\[([^\]]+)]/g,
    replacement(_, field) {
      return (
        res.getHeader(field.toLowerCase()) ||
        (res.__headers && res.__headers[field])
      );
    },
  });

  return arrayUniqueTokens(customTokens.concat(defaultTokens));
}

/**
 * Return formatted log line.
 *
 * @param  {string} str
 * @param {Array} tokens
 * @return {string}
 * @api private
 */
function format(str, tokens) {
  for (let i = 0; i < tokens.length; i++) {
    str = str.replace(tokens[i].token, tokens[i].replacement);
  }
  return str;
}

/**
 * Return RegExp Object about nolog
 *
 * @param  {(string|Array)} nolog
 * @return {RegExp}
 * @api private
 *
 * syntax
 *  1. String
 *   1.1 "\\.gif"
 *         NOT LOGGING http://example.com/hoge.gif and http://example.com/hoge.gif?fuga
 *         LOGGING http://example.com/hoge.agif
 *   1.2 in "\\.gif|\\.jpg$"
 *         NOT LOGGING http://example.com/hoge.gif and
 *           http://example.com/hoge.gif?fuga and http://example.com/hoge.jpg?fuga
 *         LOGGING http://example.com/hoge.agif,
 *           http://example.com/hoge.ajpg and http://example.com/hoge.jpg?hoge
 *   1.3 in "\\.(gif|jpe?g|png)$"
 *         NOT LOGGING http://example.com/hoge.gif and http://example.com/hoge.jpeg
 *         LOGGING http://example.com/hoge.gif?uid=2 and http://example.com/hoge.jpg?pid=3
 *  2. RegExp
 *   2.1 in /\.(gif|jpe?g|png)$/
 *         SAME AS 1.3
 *  3. Array
 *   3.1 ["\\.jpg$", "\\.png", "\\.gif"]
 *         SAME AS "\\.jpg|\\.png|\\.gif"
 */
function createNoLogCondition(nolog) {
  let regexp = null;

  if (nolog instanceof RegExp) {
    regexp = nolog;
  }

  if (typeof nolog === 'string') {
    regexp = new RegExp(nolog);
  }

  if (Array.isArray(nolog)) {
    // convert to strings
    const regexpsAsStrings = nolog.map((reg) =>
      reg.source ? reg.source : reg
    );
    regexp = new RegExp(regexpsAsStrings.join('|'));
  }

  return regexp;
}

/**
 * Allows users to define rules around status codes to assign them to a specific
 * logging level.
 * There are two types of rules:
 *   - RANGE: matches a code within a certain range
 *     E.g. { 'from': 200, 'to': 299, 'level': 'info' }
 *   - CONTAINS: matches a code to a set of expected codes
 *     E.g. { 'codes': [200, 203], 'level': 'debug' }
 * Note*: Rules are respected only in order of prescendence.
 *
 * @param {Number} statusCode
 * @param {Level} currentLevel
 * @param {Object} ruleSet
 * @return {Level}
 * @api private
 */
function matchRules(statusCode, currentLevel, ruleSet) {
  let level = currentLevel;

  if (ruleSet) {
    const matchedRule = ruleSet.find((rule) => {
      let ruleMatched = false;
      if (rule.from && rule.to) {
        ruleMatched = statusCode >= rule.from && statusCode <= rule.to;
      } else {
        ruleMatched = rule.codes.indexOf(statusCode) !== -1;
      }
      return ruleMatched;
    });
    if (matchedRule) {
      level = levels.getLevel(matchedRule.level, level);
    }
  }
  return level;
}

/**
 * Log requests with the given `options` or a `format` string.
 *
 * Options:
 *
 *   - `format`        Format string, see below for tokens
 *   - `level`         A log4js levels instance. Supports also 'auto'
 *   - `nolog`         A string or RegExp to exclude target logs or function(req, res): boolean
 *   - `statusRules`   A array of rules for setting specific logging levels base on status codes
 *   - `context`       Whether to add a response of express to the context
 *
 * Tokens:
 *
 *   - `:req[header]` ex: `:req[Accept]`
 *   - `:res[header]` ex: `:res[Content-Length]`
 *   - `:http-version`
 *   - `:response-time`
 *   - `:remote-addr`
 *   - `:date`
 *   - `:method`
 *   - `:url`
 *   - `:referrer`
 *   - `:user-agent`
 *   - `:status`
 *
 * @return {Function}
 * @param logger4js
 * @param options
 * @api public
 */
module.exports = function getLogger(logger4js, options) {
  if (typeof options === 'string' || typeof options === 'function') {
    options = { format: options };
  } else {
    options = options || {};
  }

  const thisLogger = logger4js;
  let level = levels.getLevel(options.level, levels.INFO);
  const fmt = options.format || DEFAULT_FORMAT;

  return (req, res, next) => {
    // mount safety
    if (typeof req._logging !== 'undefined') return next();

    // nologs
    if (typeof options.nolog !== 'function') {
      const nolog = createNoLogCondition(options.nolog);
      if (nolog && nolog.test(req.originalUrl)) return next();
    }

    if (thisLogger.isLevelEnabled(level) || options.level === 'auto') {
      const start = new Date();
      const { writeHead } = res;

      // flag as logging
      req._logging = true;

      // proxy for statusCode.
      res.writeHead = (code, headers) => {
        res.writeHead = writeHead;
        res.writeHead(code, headers);

        res.__statusCode = code;
        res.__headers = headers || {};
      };

      // hook on end request to emit the log entry of the HTTP request.
      let finished = false;
      const handler = () => {
        if (finished) {
          return;
        }
        finished = true;

        // nologs
        if (typeof options.nolog === 'function') {
          if (options.nolog(req, res) === true) {
            req._logging = false;
            return;
          }
        }

        res.responseTime = new Date() - start;
        // status code response level handling
        if (res.statusCode && options.level === 'auto') {
          level = levels.INFO;
          if (res.statusCode >= 300) level = levels.WARN;
          if (res.statusCode >= 400) level = levels.ERROR;
        }
        level = matchRules(res.statusCode, level, options.statusRules);

        const combinedTokens = assembleTokens(req, res, options.tokens || []);

        if (options.context) thisLogger.addContext('res', res);
        if (typeof fmt === 'function') {
          const line = fmt(req, res, (str) => format(str, combinedTokens));
          if (line) thisLogger.log(level, line);
        } else {
          thisLogger.log(level, format(fmt, combinedTokens));
        }
        if (options.context) thisLogger.removeContext('res');
      };
      res.on('end', handler);
      res.on('finish', handler);
      res.on('error', handler);
      res.on('close', handler);
    }

    // ensure next gets always called
    return next();
  };
};


/***/ }),

/***/ 6794:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const dateFormat = __nccwpck_require__(876);
const os = __nccwpck_require__(857);
const util = __nccwpck_require__(9023);
const path = __nccwpck_require__(6928);
const url = __nccwpck_require__(7016);
const debug = __nccwpck_require__(2830)('log4js:layouts');

const styles = {
  // styles
  bold: [1, 22],
  italic: [3, 23],
  underline: [4, 24],
  inverse: [7, 27],
  // grayscale
  white: [37, 39],
  grey: [90, 39],
  black: [90, 39],
  // colors
  blue: [34, 39],
  cyan: [36, 39],
  green: [32, 39],
  magenta: [35, 39],
  red: [91, 39],
  yellow: [33, 39],
};

function colorizeStart(style) {
  return style ? `\x1B[${styles[style][0]}m` : '';
}

function colorizeEnd(style) {
  return style ? `\x1B[${styles[style][1]}m` : '';
}

/**
 * Taken from masylum's fork (https://github.com/masylum/log4js-node)
 */
function colorize(str, style) {
  return colorizeStart(style) + str + colorizeEnd(style);
}

function timestampLevelAndCategory(loggingEvent, colour) {
  return colorize(
    util.format(
      '[%s] [%s] %s - ',
      dateFormat.asString(loggingEvent.startTime),
      loggingEvent.level.toString(),
      loggingEvent.categoryName
    ),
    colour
  );
}

/**
 * BasicLayout is a simple layout for storing the logs. The logs are stored
 * in following format:
 * <pre>
 * [startTime] [logLevel] categoryName - message\n
 * </pre>
 *
 * @author Stephan Strittmatter
 */
function basicLayout(loggingEvent) {
  return (
    timestampLevelAndCategory(loggingEvent) + util.format(...loggingEvent.data)
  );
}

/**
 * colouredLayout - taken from masylum's fork.
 * same as basicLayout, but with colours.
 */
function colouredLayout(loggingEvent) {
  return (
    timestampLevelAndCategory(loggingEvent, loggingEvent.level.colour) +
    util.format(...loggingEvent.data)
  );
}

function messagePassThroughLayout(loggingEvent) {
  return util.format(...loggingEvent.data);
}

function dummyLayout(loggingEvent) {
  return loggingEvent.data[0];
}

/**
 * PatternLayout
 * Format for specifiers is %[padding].[truncation][field]{[format]}
 * e.g. %5.10p - left pad the log level by 5 characters, up to a max of 10
 * both padding and truncation can be negative.
 * Negative truncation = trunc from end of string
 * Positive truncation = trunc from start of string
 * Negative padding = pad right
 * Positive padding = pad left
 *
 * Fields can be any of:
 *  - %r time in toLocaleTimeString format
 *  - %p log level
 *  - %c log category
 *  - %h hostname
 *  - %m log data
 *  - %m{l} where l is an integer, log data.slice(l)
 *  - %m{l,u} where l and u are integers, log data.slice(l, u)
 *  - %d date in constious formats
 *  - %% %
 *  - %n newline
 *  - %z pid
 *  - %f filename
 *  - %l line number
 *  - %o column postion
 *  - %s call stack
 *  - %C class name [#1316](https://github.com/log4js-node/log4js-node/pull/1316)
 *  - %M method or function name [#1316](https://github.com/log4js-node/log4js-node/pull/1316)
 *  - %A method or function alias [#1316](https://github.com/log4js-node/log4js-node/pull/1316)
 *  - %F fully qualified caller name [#1316](https://github.com/log4js-node/log4js-node/pull/1316)
 *  - %x{<tokenname>} add dynamic tokens to your log. Tokens are specified in the tokens parameter
 *  - %X{<tokenname>} add dynamic tokens to your log. Tokens are specified in logger context
 * You can use %[ and %] to define a colored block.
 *
 * Tokens are specified as simple key:value objects.
 * The key represents the token name whereas the value can be a string or function
 * which is called to extract the value to put in the log message. If token is not
 * found, it doesn't replace the field.
 *
 * A sample token would be: { 'pid' : function() { return process.pid; } }
 *
 * Takes a pattern string, array of tokens and returns a layout function.
 * @return {Function}
 * @param pattern
 * @param tokens
 * @param timezoneOffset
 *
 * @authors ['Stephan Strittmatter', 'Jan Schmidle']
 */
function patternLayout(pattern, tokens) {
  const TTCC_CONVERSION_PATTERN = '%r %p %c - %m%n';
  const regex =
    /%(-?[0-9]+)?(\.?-?[0-9]+)?([[\]cdhmnprzxXyflosCMAF%])(\{([^}]+)\})?|([^%]+)/;

  pattern = pattern || TTCC_CONVERSION_PATTERN;

  function categoryName(loggingEvent, specifier) {
    let loggerName = loggingEvent.categoryName;
    if (specifier) {
      const precision = parseInt(specifier, 10);
      const loggerNameBits = loggerName.split('.');
      if (precision < loggerNameBits.length) {
        loggerName = loggerNameBits
          .slice(loggerNameBits.length - precision)
          .join('.');
      }
    }
    return loggerName;
  }

  function formatAsDate(loggingEvent, specifier) {
    let format = dateFormat.ISO8601_FORMAT;
    if (specifier) {
      format = specifier;
      // Pick up special cases
      switch (format) {
        case 'ISO8601':
        case 'ISO8601_FORMAT':
          format = dateFormat.ISO8601_FORMAT;
          break;
        case 'ISO8601_WITH_TZ_OFFSET':
        case 'ISO8601_WITH_TZ_OFFSET_FORMAT':
          format = dateFormat.ISO8601_WITH_TZ_OFFSET_FORMAT;
          break;
        case 'ABSOLUTE':
          process.emitWarning(
            'Pattern %d{ABSOLUTE} is deprecated in favor of %d{ABSOLUTETIME}. ' +
              'Please use %d{ABSOLUTETIME} instead.',
            'DeprecationWarning',
            'log4js-node-DEP0003'
          );
          debug(
            '[log4js-node-DEP0003]',
            'DEPRECATION: Pattern %d{ABSOLUTE} is deprecated and replaced by %d{ABSOLUTETIME}.'
          );
        // falls through
        case 'ABSOLUTETIME':
        case 'ABSOLUTETIME_FORMAT':
          format = dateFormat.ABSOLUTETIME_FORMAT;
          break;
        case 'DATE':
          process.emitWarning(
            'Pattern %d{DATE} is deprecated due to the confusion it causes when used. ' +
              'Please use %d{DATETIME} instead.',
            'DeprecationWarning',
            'log4js-node-DEP0004'
          );
          debug(
            '[log4js-node-DEP0004]',
            'DEPRECATION: Pattern %d{DATE} is deprecated and replaced by %d{DATETIME}.'
          );
        // falls through
        case 'DATETIME':
        case 'DATETIME_FORMAT':
          format = dateFormat.DATETIME_FORMAT;
          break;
        // no default
      }
    }
    // Format the date
    return dateFormat.asString(format, loggingEvent.startTime);
  }

  function hostname() {
    return os.hostname().toString();
  }

  function formatMessage(loggingEvent, specifier) {
    let dataSlice = loggingEvent.data;
    if (specifier) {
      const [lowerBound, upperBound] = specifier.split(',');
      dataSlice = dataSlice.slice(lowerBound, upperBound);
    }
    return util.format(...dataSlice);
  }

  function endOfLine() {
    return os.EOL;
  }

  function logLevel(loggingEvent) {
    return loggingEvent.level.toString();
  }

  function startTime(loggingEvent) {
    return dateFormat.asString('hh:mm:ss', loggingEvent.startTime);
  }

  function startColour(loggingEvent) {
    return colorizeStart(loggingEvent.level.colour);
  }

  function endColour(loggingEvent) {
    return colorizeEnd(loggingEvent.level.colour);
  }

  function percent() {
    return '%';
  }

  function pid(loggingEvent) {
    return loggingEvent && loggingEvent.pid
      ? loggingEvent.pid.toString()
      : process.pid.toString();
  }

  function clusterInfo() {
    // this used to try to return the master and worker pids,
    // but it would never have worked because master pid is not available to workers
    // leaving this here to maintain compatibility for patterns
    return pid();
  }

  function userDefined(loggingEvent, specifier) {
    if (typeof tokens[specifier] !== 'undefined') {
      return typeof tokens[specifier] === 'function'
        ? tokens[specifier](loggingEvent)
        : tokens[specifier];
    }

    return null;
  }

  function contextDefined(loggingEvent, specifier) {
    const resolver = loggingEvent.context[specifier];

    if (typeof resolver !== 'undefined') {
      return typeof resolver === 'function' ? resolver(loggingEvent) : resolver;
    }

    return null;
  }

  function fileName(loggingEvent, specifier) {
    let filename = loggingEvent.fileName || '';

    // support for ESM as it uses url instead of path for file
    /* istanbul ignore next: unsure how to simulate ESM for test coverage */
    const convertFileURLToPath = function (filepath) {
      const urlPrefix = 'file://';
      if (filepath.startsWith(urlPrefix)) {
        // https://nodejs.org/api/url.html#urlfileurltopathurl
        if (typeof url.fileURLToPath === 'function') {
          filepath = url.fileURLToPath(filepath);
        }
        // backward-compatible for nodejs pre-10.12.0 (without url.fileURLToPath method)
        else {
          // posix: file:///hello/world/foo.txt -> /hello/world/foo.txt -> /hello/world/foo.txt
          // win32: file:///C:/path/foo.txt     -> /C:/path/foo.txt     -> \C:\path\foo.txt     -> C:\path\foo.txt
          // win32: file://nas/foo.txt          -> //nas/foo.txt        -> nas\foo.txt          -> \\nas\foo.txt
          filepath = path.normalize(
            filepath.replace(new RegExp(`^${urlPrefix}`), '')
          );
          if (process.platform === 'win32') {
            if (filepath.startsWith('\\')) {
              filepath = filepath.slice(1);
            } else {
              filepath = path.sep + path.sep + filepath;
            }
          }
        }
      }
      return filepath;
    };
    filename = convertFileURLToPath(filename);

    if (specifier) {
      const fileDepth = parseInt(specifier, 10);
      const fileList = filename.split(path.sep);
      if (fileList.length > fileDepth) {
        filename = fileList.slice(-fileDepth).join(path.sep);
      }
    }

    return filename;
  }

  function lineNumber(loggingEvent) {
    return loggingEvent.lineNumber ? `${loggingEvent.lineNumber}` : '';
  }

  function columnNumber(loggingEvent) {
    return loggingEvent.columnNumber ? `${loggingEvent.columnNumber}` : '';
  }

  function callStack(loggingEvent) {
    return loggingEvent.callStack || '';
  }

  function className(loggingEvent) {
    return loggingEvent.className || '';
  }

  function functionName(loggingEvent) {
    return loggingEvent.functionName || '';
  }

  function functionAlias(loggingEvent) {
    return loggingEvent.functionAlias || '';
  }

  function callerName(loggingEvent) {
    return loggingEvent.callerName || '';
  }

  const replacers = {
    c: categoryName,
    d: formatAsDate,
    h: hostname,
    m: formatMessage,
    n: endOfLine,
    p: logLevel,
    r: startTime,
    '[': startColour,
    ']': endColour,
    y: clusterInfo,
    z: pid,
    '%': percent,
    x: userDefined,
    X: contextDefined,
    f: fileName,
    l: lineNumber,
    o: columnNumber,
    s: callStack,
    C: className,
    M: functionName,
    A: functionAlias,
    F: callerName,
  };

  function replaceToken(conversionCharacter, loggingEvent, specifier) {
    return replacers[conversionCharacter](loggingEvent, specifier);
  }

  function truncate(truncation, toTruncate) {
    let len;
    if (truncation) {
      len = parseInt(truncation.slice(1), 10);
      // negative truncate length means truncate from end of string
      return len > 0 ? toTruncate.slice(0, len) : toTruncate.slice(len);
    }

    return toTruncate;
  }

  function pad(padding, toPad) {
    let len;
    if (padding) {
      if (padding.charAt(0) === '-') {
        len = parseInt(padding.slice(1), 10);
        // Right pad with spaces
        while (toPad.length < len) {
          toPad += ' ';
        }
      } else {
        len = parseInt(padding, 10);
        // Left pad with spaces
        while (toPad.length < len) {
          toPad = ` ${toPad}`;
        }
      }
    }
    return toPad;
  }

  function truncateAndPad(toTruncAndPad, truncation, padding) {
    let replacement = toTruncAndPad;
    replacement = truncate(truncation, replacement);
    replacement = pad(padding, replacement);
    return replacement;
  }

  return function (loggingEvent) {
    let formattedString = '';
    let result;
    let searchString = pattern;

    while ((result = regex.exec(searchString)) !== null) {
      // const matchedString = result[0];
      const padding = result[1];
      const truncation = result[2];
      const conversionCharacter = result[3];
      const specifier = result[5];
      const text = result[6];

      // Check if the pattern matched was just normal text
      if (text) {
        formattedString += text.toString();
      } else {
        // Create a raw replacement string based on the conversion
        // character and specifier
        const replacement = replaceToken(
          conversionCharacter,
          loggingEvent,
          specifier
        );
        formattedString += truncateAndPad(replacement, truncation, padding);
      }
      searchString = searchString.slice(result.index + result[0].length);
    }
    return formattedString;
  };
}

const layoutMakers = {
  messagePassThrough() {
    return messagePassThroughLayout;
  },
  basic() {
    return basicLayout;
  },
  colored() {
    return colouredLayout;
  },
  coloured() {
    return colouredLayout;
  },
  pattern(config) {
    return patternLayout(config && config.pattern, config && config.tokens);
  },
  dummy() {
    return dummyLayout;
  },
};

module.exports = {
  basicLayout,
  messagePassThroughLayout,
  patternLayout,
  colouredLayout,
  coloredLayout: colouredLayout,
  dummyLayout,
  addLayout(name, serializerGenerator) {
    layoutMakers[name] = serializerGenerator;
  },
  layout(name, config) {
    return layoutMakers[name] && layoutMakers[name](config);
  },
};


/***/ }),

/***/ 1630:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const configuration = __nccwpck_require__(8507);

const validColours = [
  'white',
  'grey',
  'black',
  'blue',
  'cyan',
  'green',
  'magenta',
  'red',
  'yellow',
];

class Level {
  constructor(level, levelStr, colour) {
    this.level = level;
    this.levelStr = levelStr;
    this.colour = colour;
  }

  toString() {
    return this.levelStr;
  }

  /**
   * converts given String to corresponding Level
   * @param {(Level|string)} sArg -- String value of Level OR Log4js.Level
   * @param {Level} [defaultLevel] -- default Level, if no String representation
   * @return {Level}
   */
  static getLevel(sArg, defaultLevel) {
    if (!sArg) {
      return defaultLevel;
    }

    if (sArg instanceof Level) {
      return sArg;
    }

    // a json-serialised level won't be an instance of Level (see issue #768)
    if (sArg instanceof Object && sArg.levelStr) {
      sArg = sArg.levelStr;
    }

    return Level[sArg.toString().toUpperCase()] || defaultLevel;
  }

  static addLevels(customLevels) {
    if (customLevels) {
      const levels = Object.keys(customLevels);
      levels.forEach((l) => {
        const levelStr = l.toUpperCase();
        Level[levelStr] = new Level(
          customLevels[l].value,
          levelStr,
          customLevels[l].colour
        );
        const existingLevelIndex = Level.levels.findIndex(
          (lvl) => lvl.levelStr === levelStr
        );
        if (existingLevelIndex > -1) {
          Level.levels[existingLevelIndex] = Level[levelStr];
        } else {
          Level.levels.push(Level[levelStr]);
        }
      });
      Level.levels.sort((a, b) => a.level - b.level);
    }
  }

  isLessThanOrEqualTo(otherLevel) {
    if (typeof otherLevel === 'string') {
      otherLevel = Level.getLevel(otherLevel);
    }
    return this.level <= otherLevel.level;
  }

  isGreaterThanOrEqualTo(otherLevel) {
    if (typeof otherLevel === 'string') {
      otherLevel = Level.getLevel(otherLevel);
    }
    return this.level >= otherLevel.level;
  }

  isEqualTo(otherLevel) {
    if (typeof otherLevel === 'string') {
      otherLevel = Level.getLevel(otherLevel);
    }
    return this.level === otherLevel.level;
  }
}

Level.levels = [];
Level.addLevels({
  ALL: { value: Number.MIN_VALUE, colour: 'grey' },
  TRACE: { value: 5000, colour: 'blue' },
  DEBUG: { value: 10000, colour: 'cyan' },
  INFO: { value: 20000, colour: 'green' },
  WARN: { value: 30000, colour: 'yellow' },
  ERROR: { value: 40000, colour: 'red' },
  FATAL: { value: 50000, colour: 'magenta' },
  MARK: { value: 9007199254740992, colour: 'grey' }, // 2^53
  OFF: { value: Number.MAX_VALUE, colour: 'grey' },
});

configuration.addListener((config) => {
  const levelConfig = config.levels;
  if (levelConfig) {
    configuration.throwExceptionIf(
      config,
      configuration.not(configuration.anObject(levelConfig)),
      'levels must be an object'
    );
    const newLevels = Object.keys(levelConfig);
    newLevels.forEach((l) => {
      configuration.throwExceptionIf(
        config,
        configuration.not(configuration.validIdentifier(l)),
        `level name "${l}" is not a valid identifier (must start with a letter, only contain A-Z,a-z,0-9,_)`
      );
      configuration.throwExceptionIf(
        config,
        configuration.not(configuration.anObject(levelConfig[l])),
        `level "${l}" must be an object`
      );
      configuration.throwExceptionIf(
        config,
        configuration.not(levelConfig[l].value),
        `level "${l}" must have a 'value' property`
      );
      configuration.throwExceptionIf(
        config,
        configuration.not(configuration.anInteger(levelConfig[l].value)),
        `level "${l}".value must have an integer value`
      );
      configuration.throwExceptionIf(
        config,
        configuration.not(levelConfig[l].colour),
        `level "${l}" must have a 'colour' property`
      );
      configuration.throwExceptionIf(
        config,
        configuration.not(validColours.indexOf(levelConfig[l].colour) > -1),
        `level "${l}".colour must be one of ${validColours.join(', ')}`
      );
    });
  }
});

configuration.addListener((config) => {
  Level.addLevels(config.levels);
});

module.exports = Level;


/***/ }),

/***/ 892:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/**
 * @fileoverview log4js is a library to log in JavaScript in similar manner
 * than in log4j for Java (but not really).
 *
 * <h3>Example:</h3>
 * <pre>
 *  const logging = require('log4js');
 *  const log = logging.getLogger('some-category');
 *
 *  //call the log
 *  log.trace('trace me' );
 * </pre>
 *
 * NOTE: the authors below are the original browser-based log4js authors
 * don't try to contact them about bugs in this version :)
 * @author Stephan Strittmatter - http://jroller.com/page/stritti
 * @author Seth Chisamore - http://www.chisamore.com
 * @since 2005-05-20
 * Website: http://log4js.berlios.de
 */
const debug = __nccwpck_require__(2830)('log4js:main');
const fs = __nccwpck_require__(9896);
const deepClone = __nccwpck_require__(8825)({ proto: true });
const configuration = __nccwpck_require__(8507);
const layouts = __nccwpck_require__(6794);
const levels = __nccwpck_require__(1630);
const appenders = __nccwpck_require__(3718);
const categories = __nccwpck_require__(8185);
const Logger = __nccwpck_require__(2949);
const clustering = __nccwpck_require__(455);
const connectLogger = __nccwpck_require__(8256);
const recordingModule = __nccwpck_require__(1149);

let enabled = false;

function sendLogEventToAppender(logEvent) {
  if (!enabled) return;
  debug('Received log event ', logEvent);
  const categoryAppenders = categories.appendersForCategory(
    logEvent.categoryName
  );
  categoryAppenders.forEach((appender) => {
    appender(logEvent);
  });
}

function loadConfigurationFile(filename) {
  debug(`Loading configuration from ${filename}`);
  try {
    return JSON.parse(fs.readFileSync(filename, 'utf8'));
  } catch (e) {
    throw new Error(
      `Problem reading config from file "${filename}". Error was ${e.message}`,
      e
    );
  }
}

function configure(configurationFileOrObject) {
  if (enabled) {
    // eslint-disable-next-line no-use-before-define
    shutdown();
  }

  let configObject = configurationFileOrObject;

  if (typeof configObject === 'string') {
    configObject = loadConfigurationFile(configurationFileOrObject);
  }
  debug(`Configuration is ${configObject}`);

  configuration.configure(deepClone(configObject));

  clustering.onMessage(sendLogEventToAppender);

  enabled = true;

  // eslint-disable-next-line no-use-before-define
  return log4js;
}

function isConfigured() {
  return enabled;
}

function recording() {
  return recordingModule;
}

/**
 * This callback type is called `shutdownCallback` and is displayed as a global symbol.
 *
 * @callback shutdownCallback
 * @param {Error} [error]
 */

/**
 * Shutdown all log appenders. This will first disable all writing to appenders
 * and then call the shutdown function each appender.
 *
 * @param {shutdownCallback} [callback] - The callback to be invoked once all appenders have
 *  shutdown. If an error occurs, the callback will be given the error object
 *  as the first argument.
 */
function shutdown(callback = () => {}) {
  if (typeof callback !== 'function') {
    throw new TypeError('Invalid callback passed to shutdown');
  }
  debug('Shutdown called. Disabling all log writing.');
  // First, disable all writing to appenders. This prevents appenders from
  // not being able to be drained because of run-away log writes.
  enabled = false;

  // Clone out to maintain a reference
  const appendersToCheck = Array.from(appenders.values());

  // Reset immediately to prevent leaks
  appenders.init();
  categories.init();

  // Count the number of shutdown functions
  const shutdownFunctions = appendersToCheck.reduce(
    (accum, next) => (next.shutdown ? accum + 1 : accum),
    0
  );
  if (shutdownFunctions === 0) {
    debug('No appenders with shutdown functions found.');
    callback();
  }

  let completed = 0;
  let error;
  debug(`Found ${shutdownFunctions} appenders with shutdown functions.`);
  function complete(err) {
    error = error || err;
    completed += 1;
    debug(`Appender shutdowns complete: ${completed} / ${shutdownFunctions}`);
    if (completed >= shutdownFunctions) {
      debug('All shutdown functions completed.');
      callback(error);
    }
  }

  // Call each of the shutdown functions
  appendersToCheck
    .filter((a) => a.shutdown)
    .forEach((a) => a.shutdown(complete));
}

/**
 * Get a logger instance.
 * @static
 * @param {string} [category=default]
 * @return {Logger} instance of logger for the category
 */
function getLogger(category) {
  if (!enabled) {
    configure(
      process.env.LOG4JS_CONFIG || {
        appenders: { out: { type: 'stdout' } },
        categories: { default: { appenders: ['out'], level: 'OFF' } },
      }
    );
  }
  return new Logger(category || 'default');
}

/**
 * @name log4js
 * @namespace Log4js
 * @property getLogger
 * @property configure
 * @property shutdown
 */
const log4js = {
  getLogger,
  configure,
  isConfigured,
  shutdown,
  connectLogger,
  levels,
  addLayout: layouts.addLayout,
  recording,
};

module.exports = log4js;


/***/ }),

/***/ 2949:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

/* eslint no-underscore-dangle: ["error", { "allow": ["_log"] }] */

const debug = __nccwpck_require__(2830)('log4js:logger');
const LoggingEvent = __nccwpck_require__(2838);
const levels = __nccwpck_require__(1630);
const clustering = __nccwpck_require__(455);
const categories = __nccwpck_require__(8185);
const configuration = __nccwpck_require__(8507);

const stackReg = /^(?:\s*)at (?:(.+) \()?(?:([^(]+?):(\d+):(\d+))\)?$/;
/**
 * The top entry is the Error
 */
const baseCallStackSkip = 1;
/**
 * The _log function is 3 levels deep, we need to skip those to make it to the callSite
 */
const defaultErrorCallStackSkip = 3;

/**
 *
 * @param {Error} data
 * @param {number} skipIdx
 * @returns {import('../types/log4js').CallStack | null}
 */
function defaultParseCallStack(
  data,
  skipIdx = defaultErrorCallStackSkip + baseCallStackSkip
) {
  try {
    const stacklines = data.stack.split('\n').slice(skipIdx);
    if (!stacklines.length) {
      // There's no stack in this stack
      // Should we try a previous index if skipIdx was set?
      return null;
    }
    const lineMatch = stackReg.exec(stacklines[0]);
    /* istanbul ignore else: failsafe */
    if (lineMatch && lineMatch.length === 5) {
      // extract class, function and alias names
      let className = '';
      let functionName = '';
      let functionAlias = '';
      if (lineMatch[1] && lineMatch[1] !== '') {
        // WARN: this will unset alias if alias is not present.
        [functionName, functionAlias] = lineMatch[1]
          .replace(/[[\]]/g, '')
          .split(' as ');
        functionAlias = functionAlias || '';

        if (functionName.includes('.'))
          [className, functionName] = functionName.split('.');
      }

      return {
        fileName: lineMatch[2],
        lineNumber: parseInt(lineMatch[3], 10),
        columnNumber: parseInt(lineMatch[4], 10),
        callStack: stacklines.join('\n'),
        className,
        functionName,
        functionAlias,
        callerName: lineMatch[1] || '',
      };
      // eslint-disable-next-line no-else-return
    } else {
      // will never get here unless nodejs has changes to Error
      console.error('log4js.logger - defaultParseCallStack error'); // eslint-disable-line no-console
    }
  } catch (err) {
    // will never get error unless nodejs has breaking changes to Error
    console.error('log4js.logger - defaultParseCallStack error', err); // eslint-disable-line no-console
  }
  return null;
}

/**
 * Logger to log messages.
 * use {@see log4js#getLogger(String)} to get an instance.
 *
 * @name Logger
 * @namespace Log4js
 * @param name name of category to log to
 * @param level - the loglevel for the category
 * @param dispatch - the function which will receive the logevents
 *
 * @author Stephan Strittmatter
 */
class Logger {
  constructor(name) {
    if (!name) {
      throw new Error('No category provided.');
    }
    this.category = name;
    this.context = {};
    /** @private */
    this.callStackSkipIndex = 0;
    /** @private */
    this.parseCallStack = defaultParseCallStack;
    debug(`Logger created (${this.category}, ${this.level})`);
  }

  get level() {
    return levels.getLevel(
      categories.getLevelForCategory(this.category),
      levels.OFF
    );
  }

  set level(level) {
    categories.setLevelForCategory(
      this.category,
      levels.getLevel(level, this.level)
    );
  }

  get useCallStack() {
    return categories.getEnableCallStackForCategory(this.category);
  }

  set useCallStack(bool) {
    categories.setEnableCallStackForCategory(this.category, bool === true);
  }

  get callStackLinesToSkip() {
    return this.callStackSkipIndex;
  }

  set callStackLinesToSkip(number) {
    if (typeof number !== 'number') {
      throw new TypeError('Must be a number');
    }
    if (number < 0) {
      throw new RangeError('Must be >= 0');
    }
    this.callStackSkipIndex = number;
  }

  log(level, ...args) {
    const logLevel = levels.getLevel(level);
    if (!logLevel) {
      if (configuration.validIdentifier(level) && args.length > 0) {
        // logLevel not found but of valid signature, WARN before fallback to INFO
        this.log(
          levels.WARN,
          'log4js:logger.log: valid log-level not found as first parameter given:',
          level
        );
        this.log(levels.INFO, `[${level}]`, ...args);
      } else {
        // apart from fallback, allow .log(...args) to be synonym with .log("INFO", ...args)
        this.log(levels.INFO, level, ...args);
      }
    } else if (this.isLevelEnabled(logLevel)) {
      this._log(logLevel, args);
    }
  }

  isLevelEnabled(otherLevel) {
    return this.level.isLessThanOrEqualTo(otherLevel);
  }

  _log(level, data) {
    debug(`sending log data (${level}) to appenders`);
    const error = data.find((item) => item instanceof Error);
    let callStack;
    if (this.useCallStack) {
      try {
        if (error) {
          callStack = this.parseCallStack(
            error,
            this.callStackSkipIndex + baseCallStackSkip
          );
        }
      } catch (_err) {
        // Ignore Error and use the original method of creating a new Error.
      }
      callStack =
        callStack ||
        this.parseCallStack(
          new Error(),
          this.callStackSkipIndex +
            defaultErrorCallStackSkip +
            baseCallStackSkip
        );
    }
    const loggingEvent = new LoggingEvent(
      this.category,
      level,
      data,
      this.context,
      callStack,
      error
    );
    clustering.send(loggingEvent);
  }

  addContext(key, value) {
    this.context[key] = value;
  }

  removeContext(key) {
    delete this.context[key];
  }

  clearContext() {
    this.context = {};
  }

  setParseCallStackFunction(parseFunction) {
    if (typeof parseFunction === 'function') {
      this.parseCallStack = parseFunction;
    } else if (typeof parseFunction === 'undefined') {
      this.parseCallStack = defaultParseCallStack;
    } else {
      throw new TypeError('Invalid type passed to setParseCallStackFunction');
    }
  }
}

function addLevelMethods(target) {
  const level = levels.getLevel(target);

  const levelStrLower = level.toString().toLowerCase();
  const levelMethod = levelStrLower.replace(/_([a-z])/g, (g) =>
    g[1].toUpperCase()
  );
  const isLevelMethod = levelMethod[0].toUpperCase() + levelMethod.slice(1);

  Logger.prototype[`is${isLevelMethod}Enabled`] = function () {
    return this.isLevelEnabled(level);
  };

  Logger.prototype[levelMethod] = function (...args) {
    this.log(level, ...args);
  };
}

levels.levels.forEach(addLevelMethods);

configuration.addListener(() => {
  levels.levels.forEach(addLevelMethods);
});

module.exports = Logger;


/***/ }),

/***/ 744:
/***/ ((module) => {

/**
 * Helpers.
 */

var s = 1000;
var m = s * 60;
var h = m * 60;
var d = h * 24;
var w = d * 7;
var y = d * 365.25;

/**
 * Parse or format the given `val`.
 *
 * Options:
 *
 *  - `long` verbose formatting [false]
 *
 * @param {String|Number} val
 * @param {Object} [options]
 * @throws {Error} throw an error if val is not a non-empty string or a number
 * @return {String|Number}
 * @api public
 */

module.exports = function (val, options) {
  options = options || {};
  var type = typeof val;
  if (type === 'string' && val.length > 0) {
    return parse(val);
  } else if (type === 'number' && isFinite(val)) {
    return options.long ? fmtLong(val) : fmtShort(val);
  }
  throw new Error(
    'val is not a non-empty string or a valid number. val=' +
      JSON.stringify(val)
  );
};

/**
 * Parse the given `str` and return milliseconds.
 *
 * @param {String} str
 * @return {Number}
 * @api private
 */

function parse(str) {
  str = String(str);
  if (str.length > 100) {
    return;
  }
  var match = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
    str
  );
  if (!match) {
    return;
  }
  var n = parseFloat(match[1]);
  var type = (match[2] || 'ms').toLowerCase();
  switch (type) {
    case 'years':
    case 'year':
    case 'yrs':
    case 'yr':
    case 'y':
      return n * y;
    case 'weeks':
    case 'week':
    case 'w':
      return n * w;
    case 'days':
    case 'day':
    case 'd':
      return n * d;
    case 'hours':
    case 'hour':
    case 'hrs':
    case 'hr':
    case 'h':
      return n * h;
    case 'minutes':
    case 'minute':
    case 'mins':
    case 'min':
    case 'm':
      return n * m;
    case 'seconds':
    case 'second':
    case 'secs':
    case 'sec':
    case 's':
      return n * s;
    case 'milliseconds':
    case 'millisecond':
    case 'msecs':
    case 'msec':
    case 'ms':
      return n;
    default:
      return undefined;
  }
}

/**
 * Short format for `ms`.
 *
 * @param {Number} ms
 * @return {String}
 * @api private
 */

function fmtShort(ms) {
  var msAbs = Math.abs(ms);
  if (msAbs >= d) {
    return Math.round(ms / d) + 'd';
  }
  if (msAbs >= h) {
    return Math.round(ms / h) + 'h';
  }
  if (msAbs >= m) {
    return Math.round(ms / m) + 'm';
  }
  if (msAbs >= s) {
    return Math.round(ms / s) + 's';
  }
  return ms + 'ms';
}

/**
 * Long format for `ms`.
 *
 * @param {Number} ms
 * @return {String}
 * @api private
 */

function fmtLong(ms) {
  var msAbs = Math.abs(ms);
  if (msAbs >= d) {
    return plural(ms, msAbs, d, 'day');
  }
  if (msAbs >= h) {
    return plural(ms, msAbs, h, 'hour');
  }
  if (msAbs >= m) {
    return plural(ms, msAbs, m, 'minute');
  }
  if (msAbs >= s) {
    return plural(ms, msAbs, s, 'second');
  }
  return ms + ' ms';
}

/**
 * Pluralization helper.
 */

function plural(ms, msAbs, n, name) {
  var isPlural = msAbs >= n * 1.5;
  return Math.round(ms / n) + ' ' + name + (isPlural ? 's' : '');
}


/***/ }),

/***/ 8825:
/***/ ((module) => {

"use strict";

module.exports = rfdc

function copyBuffer (cur) {
  if (cur instanceof Buffer) {
    return Buffer.from(cur)
  }

  return new cur.constructor(cur.buffer.slice(), cur.byteOffset, cur.length)
}

function rfdc (opts) {
  opts = opts || {}
  if (opts.circles) return rfdcCircles(opts)

  const constructorHandlers = new Map()
  constructorHandlers.set(Date, (o) => new Date(o))
  constructorHandlers.set(Map, (o, fn) => new Map(cloneArray(Array.from(o), fn)))
  constructorHandlers.set(Set, (o, fn) => new Set(cloneArray(Array.from(o), fn)))
  if (opts.constructorHandlers) {
    for (const handler of opts.constructorHandlers) {
      constructorHandlers.set(handler[0], handler[1])
    }
  }

  let handler = null

  return opts.proto ? cloneProto : clone

  function cloneArray (a, fn) {
    const keys = Object.keys(a)
    const a2 = new Array(keys.length)
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i]
      const cur = a[k]
      if (typeof cur !== 'object' || cur === null) {
        a2[k] = cur
      } else if (cur.constructor !== Object && (handler = constructorHandlers.get(cur.constructor))) {
        a2[k] = handler(cur, fn)
      } else if (ArrayBuffer.isView(cur)) {
        a2[k] = copyBuffer(cur)
      } else {
        a2[k] = fn(cur)
      }
    }
    return a2
  }

  function clone (o) {
    if (typeof o !== 'object' || o === null) return o
    if (Array.isArray(o)) return cloneArray(o, clone)
    if (o.constructor !== Object && (handler = constructorHandlers.get(o.constructor))) {
      return handler(o, clone)
    }
    const o2 = {}
    for (const k in o) {
      if (Object.hasOwnProperty.call(o, k) === false) continue
      const cur = o[k]
      if (typeof cur !== 'object' || cur === null) {
        o2[k] = cur
      } else if (cur.constructor !== Object && (handler = constructorHandlers.get(cur.constructor))) {
        o2[k] = handler(cur, clone)
      } else if (ArrayBuffer.isView(cur)) {
        o2[k] = copyBuffer(cur)
      } else {
        o2[k] = clone(cur)
      }
    }
    return o2
  }

  function cloneProto (o) {
    if (typeof o !== 'object' || o === null) return o
    if (Array.isArray(o)) return cloneArray(o, cloneProto)
    if (o.constructor !== Object && (handler = constructorHandlers.get(o.constructor))) {
      return handler(o, cloneProto)
    }
    const o2 = {}
    for (const k in o) {
      const cur = o[k]
      if (typeof cur !== 'object' || cur === null) {
        o2[k] = cur
      } else if (cur.constructor !== Object && (handler = constructorHandlers.get(cur.constructor))) {
        o2[k] = handler(cur, cloneProto)
      } else if (ArrayBuffer.isView(cur)) {
        o2[k] = copyBuffer(cur)
      } else {
        o2[k] = cloneProto(cur)
      }
    }
    return o2
  }
}

function rfdcCircles (opts) {
  const refs = []
  const refsNew = []

  const constructorHandlers = new Map()
  constructorHandlers.set(Date, (o) => new Date(o))
  constructorHandlers.set(Map, (o, fn) => new Map(cloneArray(Array.from(o), fn)))
  constructorHandlers.set(Set, (o, fn) => new Set(cloneArray(Array.from(o), fn)))
  if (opts.constructorHandlers) {
    for (const handler of opts.constructorHandlers) {
      constructorHandlers.set(handler[0], handler[1])
    }
  }

  let handler = null
  return opts.proto ? cloneProto : clone

  function cloneArray (a, fn) {
    const keys = Object.keys(a)
    const a2 = new Array(keys.length)
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i]
      const cur = a[k]
      if (typeof cur !== 'object' || cur === null) {
        a2[k] = cur
      } else if (cur.constructor !== Object && (handler = constructorHandlers.get(cur.constructor))) {
        a2[k] = handler(cur, fn)
      } else if (ArrayBuffer.isView(cur)) {
        a2[k] = copyBuffer(cur)
      } else {
        const index = refs.indexOf(cur)
        if (index !== -1) {
          a2[k] = refsNew[index]
        } else {
          a2[k] = fn(cur)
        }
      }
    }
    return a2
  }

  function clone (o) {
    if (typeof o !== 'object' || o === null) return o
    if (Array.isArray(o)) return cloneArray(o, clone)
    if (o.constructor !== Object && (handler = constructorHandlers.get(o.constructor))) {
      return handler(o, clone)
    }
    const o2 = {}
    refs.push(o)
    refsNew.push(o2)
    for (const k in o) {
      if (Object.hasOwnProperty.call(o, k) === false) continue
      const cur = o[k]
      if (typeof cur !== 'object' || cur === null) {
        o2[k] = cur
      } else if (cur.constructor !== Object && (handler = constructorHandlers.get(cur.constructor))) {
        o2[k] = handler(cur, clone)
      } else if (ArrayBuffer.isView(cur)) {
        o2[k] = copyBuffer(cur)
      } else {
        const i = refs.indexOf(cur)
        if (i !== -1) {
          o2[k] = refsNew[i]
        } else {
          o2[k] = clone(cur)
        }
      }
    }
    refs.pop()
    refsNew.pop()
    return o2
  }

  function cloneProto (o) {
    if (typeof o !== 'object' || o === null) return o
    if (Array.isArray(o)) return cloneArray(o, cloneProto)
    if (o.constructor !== Object && (handler = constructorHandlers.get(o.constructor))) {
      return handler(o, cloneProto)
    }
    const o2 = {}
    refs.push(o)
    refsNew.push(o2)
    for (const k in o) {
      const cur = o[k]
      if (typeof cur !== 'object' || cur === null) {
        o2[k] = cur
      } else if (cur.constructor !== Object && (handler = constructorHandlers.get(cur.constructor))) {
        o2[k] = handler(cur, cloneProto)
      } else if (ArrayBuffer.isView(cur)) {
        o2[k] = copyBuffer(cur)
      } else {
        const i = refs.indexOf(cur)
        if (i !== -1) {
          o2[k] = refsNew[i]
        } else {
          o2[k] = cloneProto(cur)
        }
      }
    }
    refs.pop()
    refsNew.pop()
    return o2
  }
}


/***/ }),

/***/ 4431:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const RollingFileWriteStream = __nccwpck_require__(440);

// just to adapt the previous version
class DateRollingFileStream extends RollingFileWriteStream {
  constructor(filename, pattern, options) {
    if (pattern && typeof(pattern) === 'object') {
      options = pattern;
      pattern = null;
    }
    if (!options) {
      options = {};
    }
    if (!pattern) {
      pattern = 'yyyy-MM-dd';
    }
    options.pattern = pattern;
    if (!options.numBackups && options.numBackups !== 0) {
      if (!options.daysToKeep && options.daysToKeep !== 0) {
        options.daysToKeep = 1;
      } else {
        process.emitWarning(
          "options.daysToKeep is deprecated due to the confusion it causes when used " +
          "together with file size rolling. Please use options.numBackups instead.",
          "DeprecationWarning", "streamroller-DEP0001"
        );
      }
      options.numBackups = options.daysToKeep;
    } else {
      options.daysToKeep = options.numBackups;
    }
    super(filename, options);
    this.mode = this.options.mode;
  }

  get theStream() {
    return this.currentFileStream;
  }

}

module.exports = DateRollingFileStream;


/***/ }),

/***/ 1723:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const RollingFileWriteStream = __nccwpck_require__(440);

// just to adapt the previous version
class RollingFileStream extends RollingFileWriteStream {
  constructor(filename, size, backups, options) {
    if (!options) {
      options = {};
    }
    if (size) {
      options.maxSize = size;
    }
    if (!options.numBackups && options.numBackups !== 0) {
      if (!backups && backups !== 0) {
        backups = 1;
      }
      options.numBackups = backups;
    }
    super(filename, options);
    this.backups = options.numBackups;
    this.size = this.options.maxSize;
  }

  get theStream() {
    return this.currentFileStream;
  }

}

module.exports = RollingFileStream;


/***/ }),

/***/ 440:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)("streamroller:RollingFileWriteStream");
const fs = __nccwpck_require__(2136);
const path = __nccwpck_require__(6928);
const os = __nccwpck_require__(857);
const newNow = __nccwpck_require__(9548);
const format = __nccwpck_require__(876);
const { Writable } = __nccwpck_require__(2203);
const fileNameFormatter = __nccwpck_require__(4873);
const fileNameParser = __nccwpck_require__(332);
const moveAndMaybeCompressFile = __nccwpck_require__(8162);

const deleteFiles = fileNames => {
  debug(`deleteFiles: files to delete: ${fileNames}`);
  return Promise.all(fileNames.map(f => fs.unlink(f).catch((e) => {
    debug(`deleteFiles: error when unlinking ${f}, ignoring. Error was ${e}`);
  })));
};

/**
 * RollingFileWriteStream is mainly used when writing to a file rolling by date or size.
 * RollingFileWriteStream inherits from stream.Writable
 */
class RollingFileWriteStream extends Writable {
  /**
   * Create a RollingFileWriteStream
   * @constructor
   * @param {string} filePath - The file path to write.
   * @param {object} options - The extra options
   * @param {number} options.numToKeep - The max numbers of files to keep.
   * @param {number} options.maxSize - The maxSize one file can reach. Unit is Byte.
   *                                   This should be more than 1024. The default is 0.
   *                                   If not specified or 0, then no log rolling will happen.
   * @param {string} options.mode - The mode of the files. The default is '0600'. Refer to stream.writable for more.
   * @param {string} options.flags - The default is 'a'. Refer to stream.flags for more.
   * @param {boolean} options.compress - Whether to compress backup files.
   * @param {boolean} options.keepFileExt - Whether to keep the file extension.
   * @param {string} options.pattern - The date string pattern in the file name.
   * @param {boolean} options.alwaysIncludePattern - Whether to add date to the name of the first file.
   */
  constructor(filePath, options) {
    debug(`constructor: creating RollingFileWriteStream. path=${filePath}`);
    if (typeof filePath !== "string" || filePath.length === 0) {
      throw new Error(`Invalid filename: ${filePath}`);
    } else if (filePath.endsWith(path.sep)) {
      throw new Error(`Filename is a directory: ${filePath}`);
    } else if (filePath.indexOf(`~${path.sep}`) === 0) {
      // handle ~ expansion: https://github.com/nodejs/node/issues/684
      // exclude ~ and ~filename as these can be valid files
      filePath = filePath.replace("~", os.homedir());
    }
    super(options);
    this.options = this._parseOption(options);
    this.fileObject = path.parse(filePath);
    if (this.fileObject.dir === "") {
      this.fileObject = path.parse(path.join(process.cwd(), filePath));
    }
    this.fileFormatter = fileNameFormatter({
      file: this.fileObject,
      alwaysIncludeDate: this.options.alwaysIncludePattern,
      needsIndex: this.options.maxSize < Number.MAX_SAFE_INTEGER,
      compress: this.options.compress,
      keepFileExt: this.options.keepFileExt,
      fileNameSep: this.options.fileNameSep
    });

    this.fileNameParser = fileNameParser({
      file: this.fileObject,
      keepFileExt: this.options.keepFileExt,
      pattern: this.options.pattern,
      fileNameSep: this.options.fileNameSep
    });

    this.state = {
      currentSize: 0
    };

    if (this.options.pattern) {
      this.state.currentDate = format(this.options.pattern, newNow());
    }

    this.filename = this.fileFormatter({
      index: 0,
      date: this.state.currentDate
    });
    if (["a", "a+", "as", "as+"].includes(this.options.flags)) {
      this._setExistingSizeAndDate();
    }

    debug(
      `constructor: create new file ${this.filename}, state=${JSON.stringify(
        this.state
      )}`
    );
    this._renewWriteStream();
  }

  _setExistingSizeAndDate() {
    try {
      const stats = fs.statSync(this.filename);
      this.state.currentSize = stats.size;
      if (this.options.pattern) {
        this.state.currentDate = format(this.options.pattern, stats.mtime);
      }
    } catch (e) {
      //file does not exist, that's fine - move along
      return;
    }
  }

  _parseOption(rawOptions) {
    const defaultOptions = {
      maxSize: 0,
      numToKeep: Number.MAX_SAFE_INTEGER,
      encoding: "utf8",
      mode: parseInt("0600", 8),
      flags: "a",
      compress: false,
      keepFileExt: false,
      alwaysIncludePattern: false
    };
    const options = Object.assign({}, defaultOptions, rawOptions);
    if (!options.maxSize) {
      delete options.maxSize;
    } else if (options.maxSize <= 0) {
      throw new Error(`options.maxSize (${options.maxSize}) should be > 0`);
    }
    // options.numBackups will supercede options.numToKeep
    if (options.numBackups || options.numBackups === 0) {
      if (options.numBackups < 0) {
        throw new Error(`options.numBackups (${options.numBackups}) should be >= 0`);
      } else if (options.numBackups >= Number.MAX_SAFE_INTEGER) {
        // to cater for numToKeep (include the hot file) at Number.MAX_SAFE_INTEGER
        throw new Error(`options.numBackups (${options.numBackups}) should be < Number.MAX_SAFE_INTEGER`);
      } else {
        options.numToKeep = options.numBackups + 1;
      }
    } else if (options.numToKeep <= 0) {
      throw new Error(`options.numToKeep (${options.numToKeep}) should be > 0`);
    }
    debug(
      `_parseOption: creating stream with option=${JSON.stringify(options)}`
    );
    return options;
  }

  _final(callback) {
    this.currentFileStream.end("", this.options.encoding, callback);
  }

  _write(chunk, encoding, callback) {
    this._shouldRoll().then(() => {
      debug(
        `_write: writing chunk. ` +
          `file=${this.currentFileStream.path} ` +
          `state=${JSON.stringify(this.state)} ` +
          `chunk=${chunk}`
      );
      this.currentFileStream.write(chunk, encoding, e => {
        this.state.currentSize += chunk.length;
        callback(e);
      });
    });
  }

  async _shouldRoll() {
    if (this._dateChanged() || this._tooBig()) {
      debug(
        `_shouldRoll: rolling because dateChanged? ${this._dateChanged()} or tooBig? ${this._tooBig()}`
      );
      await this._roll();
    }
  }

  _dateChanged() {
    return (
      this.state.currentDate &&
      this.state.currentDate !== format(this.options.pattern, newNow())
    );
  }

  _tooBig() {
    return this.state.currentSize >= this.options.maxSize;
  }

  _roll() {
    debug(`_roll: closing the current stream`);
    return new Promise((resolve, reject) => {
      this.currentFileStream.end("", this.options.encoding, () => {
        this._moveOldFiles()
          .then(resolve)
          .catch(reject);
      });
    });
  }

  async _moveOldFiles() {
    const files = await this._getExistingFiles();
    const todaysFiles = this.state.currentDate
      ? files.filter(f => f.date === this.state.currentDate)
      : files;
    for (let i = todaysFiles.length; i >= 0; i--) {
      debug(`_moveOldFiles: i = ${i}`);
      const sourceFilePath = this.fileFormatter({
        date: this.state.currentDate,
        index: i
      });
      const targetFilePath = this.fileFormatter({
        date: this.state.currentDate,
        index: i + 1
      });

      const moveAndCompressOptions = {
        compress: this.options.compress && i === 0,
        mode: this.options.mode
      };
      await moveAndMaybeCompressFile(
        sourceFilePath,
        targetFilePath,
        moveAndCompressOptions
      );
    }

    this.state.currentSize = 0;
    this.state.currentDate = this.state.currentDate
      ? format(this.options.pattern, newNow())
      : null;
    debug(
      `_moveOldFiles: finished rolling files. state=${JSON.stringify(
        this.state
      )}`
    );
    this._renewWriteStream();
    // wait for the file to be open before cleaning up old ones,
    // otherwise the daysToKeep calculations can be off
    await new Promise((resolve, reject) => {
      this.currentFileStream.write("", "utf8", () => {
        this._clean()
          .then(resolve)
          .catch(reject);
      });
    });
  }

  // Sorted from the oldest to the latest
  async _getExistingFiles() {
    const files = await fs.readdir(this.fileObject.dir)
      .catch( /* istanbul ignore next: will not happen on windows */ () => []);

    debug(`_getExistingFiles: files=${files}`);
    const existingFileDetails = files
      .map(n => this.fileNameParser(n))
      .filter(n => n);

    const getKey = n =>
      (n.timestamp ? n.timestamp : newNow().getTime()) - n.index;
    existingFileDetails.sort((a, b) => getKey(a) - getKey(b));

    return existingFileDetails;
  }

  _renewWriteStream() {
    const filePath = this.fileFormatter({
      date: this.state.currentDate,
      index: 0
    });

    // attempt to create the directory
    const mkdir = (dir) => {
      try {
        return fs.mkdirSync(dir, { recursive: true });
      }
      // backward-compatible fs.mkdirSync for nodejs pre-10.12.0 (without recursive option)
      catch (e) {
        // recursive creation of parent first
        if (e.code === "ENOENT") {
          mkdir(path.dirname(dir));
          return mkdir(dir);
        }

        // throw error for all except EEXIST and EROFS (read-only filesystem)
        if (e.code !== "EEXIST" && e.code !== "EROFS") {
          throw e;
        }

        // EEXIST: throw if file and not directory
        // EROFS : throw if directory not found
        else {
          try {
            if (fs.statSync(dir).isDirectory()) {
              return dir;
            }
            throw e;
          } catch (err) {
            throw e;
          }
        }
      }
    };
    mkdir(this.fileObject.dir);

    const ops = {
      flags: this.options.flags,
      encoding: this.options.encoding,
      mode: this.options.mode
    };
    const renameKey = function(obj, oldKey, newKey) {
      obj[newKey] = obj[oldKey];
      delete obj[oldKey];
      return obj;
    };
    // try to throw EISDIR, EROFS, EACCES
    fs.appendFileSync(filePath, "", renameKey({ ...ops }, "flags", "flag"));
    this.currentFileStream = fs.createWriteStream(filePath, ops);
    this.currentFileStream.on("error", e => {
      this.emit("error", e);
    });
  }

  async _clean() {
    const existingFileDetails = await this._getExistingFiles();
    debug(
      `_clean: numToKeep = ${this.options.numToKeep}, existingFiles = ${existingFileDetails.length}`
    );
    debug("_clean: existing files are: ", existingFileDetails);
    if (this._tooManyFiles(existingFileDetails.length)) {
      const fileNamesToRemove = existingFileDetails
        .slice(0, existingFileDetails.length - this.options.numToKeep)
        .map(f => path.format({ dir: this.fileObject.dir, base: f.filename }));
      await deleteFiles(fileNamesToRemove);
    }
  }

  _tooManyFiles(numFiles) {
    return this.options.numToKeep > 0 && numFiles > this.options.numToKeep;
  }
}

module.exports = RollingFileWriteStream;


/***/ }),

/***/ 4873:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)("streamroller:fileNameFormatter");
const path = __nccwpck_require__(6928);
const ZIP_EXT = ".gz";
const DEFAULT_FILENAME_SEP = ".";

module.exports = ({
  file,
  keepFileExt,
  needsIndex,
  alwaysIncludeDate,
  compress,
  fileNameSep
}) => {
  let FILENAME_SEP = fileNameSep || DEFAULT_FILENAME_SEP;
  const dirAndName = path.join(file.dir, file.name);

  const ext = f => f + file.ext;

  const index = (f, i, d) =>
    (needsIndex || !d) && i ? f + FILENAME_SEP + i : f;

  const date = (f, i, d) => {
    return (i > 0 || alwaysIncludeDate) && d ? f + FILENAME_SEP + d : f;
  };

  const gzip = (f, i) => (i && compress ? f + ZIP_EXT : f);

  const parts = keepFileExt
    ? [date, index, ext, gzip]
    : [ext, date, index, gzip];

  return ({ date, index }) => {
    debug(`_formatFileName: date=${date}, index=${index}`);
    return parts.reduce(
      (filename, part) => part(filename, index, date),
      dirAndName
    );
  };
};


/***/ }),

/***/ 332:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)("streamroller:fileNameParser");
const ZIP_EXT = ".gz";
const format = __nccwpck_require__(876);
const DEFAULT_FILENAME_SEP = ".";

module.exports = ({ file, keepFileExt, pattern, fileNameSep }) => {
  let FILENAME_SEP = fileNameSep || DEFAULT_FILENAME_SEP;
  // All these functions take two arguments: f, the filename, and p, the result placeholder
  // They return the filename with any matching parts removed.
  // The "zip" function, for instance, removes the ".gz" part of the filename (if present)
  const zip = (f, p) => {
    if (f.endsWith(ZIP_EXT)) {
      debug("it is gzipped");
      p.isCompressed = true;
      return f.slice(0, -1 * ZIP_EXT.length);
    }
    return f;
  };

  const __NOT_MATCHING__ = "__NOT_MATCHING__";

  const extAtEnd = f => {
    if (f.startsWith(file.name) && f.endsWith(file.ext)) {
      debug("it starts and ends with the right things");
      return f.slice(file.name.length + 1, -1 * file.ext.length);
    }
    return __NOT_MATCHING__;
  };

  const extInMiddle = f => {
    if (f.startsWith(file.base)) {
      debug("it starts with the right things");
      return f.slice(file.base.length + 1);
    }
    return __NOT_MATCHING__;
  };

  const dateAndIndex = (f, p) => {
    const items = f.split(FILENAME_SEP);
    let indexStr = items[items.length - 1];
    debug("items: ", items, ", indexStr: ", indexStr);
    let dateStr = f;
    if (indexStr !== undefined && indexStr.match(/^\d+$/)) {
      dateStr = f.slice(0, -1 * (indexStr.length + 1));
      debug(`dateStr is ${dateStr}`);
      if (pattern && !dateStr) {
        dateStr = indexStr;
        indexStr = "0";
      }
    } else {
      indexStr = "0";
    }

    try {
      // Two arguments for new Date() are intentional. This will set other date
      // components to minimal values in the current timezone instead of UTC,
      // as new Date(0) will do.
      const date = format.parse(pattern, dateStr, new Date(0, 0));
      if (format.asString(pattern, date) !== dateStr) return f;
      p.index = parseInt(indexStr, 10);
      p.date = dateStr;
      p.timestamp = date.getTime();
      return "";
    } catch (e) {
      //not a valid date, don't panic.
      debug(`Problem parsing ${dateStr} as ${pattern}, error was: `, e);
      return f;
    }
  };

  const index = (f, p) => {
    if (f.match(/^\d+$/)) {
      debug("it has an index");
      p.index = parseInt(f, 10);
      return "";
    }
    return f;
  };

  let parts = [
    zip,
    keepFileExt ? extAtEnd : extInMiddle,
    pattern ? dateAndIndex : index
  ];

  return filename => {
    let result = { filename, index: 0, isCompressed: false };
    // pass the filename through each of the file part parsers
    let whatsLeftOver = parts.reduce(
      (remains, part) => part(remains, result),
      filename
    );
    // if there's anything left after parsing, then it wasn't a valid filename
    return whatsLeftOver ? null : result;
  };
};


/***/ }),

/***/ 248:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

module.exports = {
  RollingFileWriteStream: __nccwpck_require__(440),
  RollingFileStream: __nccwpck_require__(1723),
  DateRollingFileStream: __nccwpck_require__(4431)
};


/***/ }),

/***/ 8162:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const debug = __nccwpck_require__(2830)('streamroller:moveAndMaybeCompressFile');
const fs = __nccwpck_require__(2136);
const zlib = __nccwpck_require__(3106);

const _parseOption = function(rawOptions){
  const defaultOptions = {
    mode: parseInt("0600", 8),
    compress: false,
  };
  const options = Object.assign({}, defaultOptions, rawOptions);
  debug(`_parseOption: moveAndMaybeCompressFile called with option=${JSON.stringify(options)}`);
  return options;
};

const moveAndMaybeCompressFile = async (
  sourceFilePath,
  targetFilePath,
  options
) => {
  options = _parseOption(options);

  if (sourceFilePath === targetFilePath) {
    debug(`moveAndMaybeCompressFile: source and target are the same, not doing anything`);
    return;
  }

  if (await fs.pathExists(sourceFilePath)) {
    debug(
      `moveAndMaybeCompressFile: moving file from ${sourceFilePath} to ${targetFilePath} ${
        options.compress ? "with" : "without"
      } compress`
    );
    if (options.compress) {
      await new Promise((resolve, reject) => {
        let isCreated = false;
        // to avoid concurrency, the forked process which can create the file will proceed (using flags wx)
        const writeStream = fs.createWriteStream(targetFilePath, { mode: options.mode, flags: "wx" })
          // wait until writable stream is valid before proceeding to read
          .on("open", () => {
            isCreated = true;
            const readStream = fs.createReadStream(sourceFilePath)
              // wait until readable stream is valid before piping
              .on("open", () => {
                readStream.pipe(zlib.createGzip()).pipe(writeStream);
              })
              .on("error", (e) => {
                debug(`moveAndMaybeCompressFile: error reading ${sourceFilePath}`, e);
                // manually close writable: https://nodejs.org/api/stream.html#readablepipedestination-options
                writeStream.destroy(e);
              });
          })
          .on("finish", () => {
            debug(`moveAndMaybeCompressFile: finished compressing ${targetFilePath}, deleting ${sourceFilePath}`);
            // delete sourceFilePath
            fs.unlink(sourceFilePath)
              .then(resolve)
              .catch((e) => {
                debug(`moveAndMaybeCompressFile: error deleting ${sourceFilePath}, truncating instead`, e);
                // fallback to truncate
                fs.truncate(sourceFilePath)
                  .then(resolve)
                  .catch((e) => {
                    debug(`moveAndMaybeCompressFile: error truncating ${sourceFilePath}`, e);
                    reject(e);
                  });
              });
          })
          .on("error", (e) => {
            if (!isCreated) {
              debug(`moveAndMaybeCompressFile: error creating ${targetFilePath}`, e);
              // do not do anything if handled by another forked process
              reject(e);
            } else {
              debug(`moveAndMaybeCompressFile: error writing ${targetFilePath}, deleting`, e);
              // delete targetFilePath (taking as nothing happened)
              fs.unlink(targetFilePath)
                .then(() => { reject(e); })
                .catch((e) => {
                  debug(`moveAndMaybeCompressFile: error deleting ${targetFilePath}`, e);
                  reject(e);
                });
            }
          });
      }).catch(() => {});
    } else {
      debug(`moveAndMaybeCompressFile: renaming ${sourceFilePath} to ${targetFilePath}`);
      try {
        await fs.move(sourceFilePath, targetFilePath, { overwrite: true });
      } catch (e) {
        debug(`moveAndMaybeCompressFile: error renaming ${sourceFilePath} to ${targetFilePath}`, e);
        /* istanbul ignore else: no need to do anything if file does not exist */
        if (e.code !== "ENOENT") {
          debug(`moveAndMaybeCompressFile: trying copy+truncate instead`);
          try {
            await fs.copy(sourceFilePath, targetFilePath, { overwrite: true });
            await fs.truncate(sourceFilePath);
          } catch (e) {
            debug(`moveAndMaybeCompressFile: error copy+truncate`, e);
          }
        }
      }
    }
  }
};

module.exports = moveAndMaybeCompressFile;


/***/ }),

/***/ 9548:
/***/ ((module) => {

// allows us to inject a mock date in tests
module.exports = () => new Date();


/***/ }),

/***/ 1450:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";

const os = __nccwpck_require__(857);
const tty = __nccwpck_require__(2018);
const hasFlag = __nccwpck_require__(3813);

const {env} = process;

let forceColor;
if (hasFlag('no-color') ||
	hasFlag('no-colors') ||
	hasFlag('color=false') ||
	hasFlag('color=never')) {
	forceColor = 0;
} else if (hasFlag('color') ||
	hasFlag('colors') ||
	hasFlag('color=true') ||
	hasFlag('color=always')) {
	forceColor = 1;
}

if ('FORCE_COLOR' in env) {
	if (env.FORCE_COLOR === 'true') {
		forceColor = 1;
	} else if (env.FORCE_COLOR === 'false') {
		forceColor = 0;
	} else {
		forceColor = env.FORCE_COLOR.length === 0 ? 1 : Math.min(parseInt(env.FORCE_COLOR, 10), 3);
	}
}

function translateLevel(level) {
	if (level === 0) {
		return false;
	}

	return {
		level,
		hasBasic: true,
		has256: level >= 2,
		has16m: level >= 3
	};
}

function supportsColor(haveStream, streamIsTTY) {
	if (forceColor === 0) {
		return 0;
	}

	if (hasFlag('color=16m') ||
		hasFlag('color=full') ||
		hasFlag('color=truecolor')) {
		return 3;
	}

	if (hasFlag('color=256')) {
		return 2;
	}

	if (haveStream && !streamIsTTY && forceColor === undefined) {
		return 0;
	}

	const min = forceColor || 0;

	if (env.TERM === 'dumb') {
		return min;
	}

	if (process.platform === 'win32') {
		// Windows 10 build 10586 is the first Windows release that supports 256 colors.
		// Windows 10 build 14931 is the first release that supports 16m/TrueColor.
		const osRelease = os.release().split('.');
		if (
			Number(osRelease[0]) >= 10 &&
			Number(osRelease[2]) >= 10586
		) {
			return Number(osRelease[2]) >= 14931 ? 3 : 2;
		}

		return 1;
	}

	if ('CI' in env) {
		if (['TRAVIS', 'CIRCLECI', 'APPVEYOR', 'GITLAB_CI', 'GITHUB_ACTIONS', 'BUILDKITE'].some(sign => sign in env) || env.CI_NAME === 'codeship') {
			return 1;
		}

		return min;
	}

	if ('TEAMCITY_VERSION' in env) {
		return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(env.TEAMCITY_VERSION) ? 1 : 0;
	}

	if (env.COLORTERM === 'truecolor') {
		return 3;
	}

	if ('TERM_PROGRAM' in env) {
		const version = parseInt((env.TERM_PROGRAM_VERSION || '').split('.')[0], 10);

		switch (env.TERM_PROGRAM) {
			case 'iTerm.app':
				return version >= 3 ? 3 : 2;
			case 'Apple_Terminal':
				return 2;
			// No default
		}
	}

	if (/-256(color)?$/i.test(env.TERM)) {
		return 2;
	}

	if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(env.TERM)) {
		return 1;
	}

	if ('COLORTERM' in env) {
		return 1;
	}

	return min;
}

function getSupportLevel(stream) {
	const level = supportsColor(stream, stream && stream.isTTY);
	return translateLevel(level);
}

module.exports = {
	supportsColor: getSupportLevel,
	stdout: translateLevel(supportsColor(true, tty.isatty(1))),
	stderr: translateLevel(supportsColor(true, tty.isatty(2)))
};


/***/ }),

/***/ 5077:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


exports.S = function (fn) {
  return Object.defineProperty(function () {
    if (typeof arguments[arguments.length - 1] === 'function') fn.apply(this, arguments)
    else {
      return new Promise((resolve, reject) => {
        arguments[arguments.length] = (err, res) => {
          if (err) return reject(err)
          resolve(res)
        }
        arguments.length++
        fn.apply(this, arguments)
      })
    }
  }, 'name', { value: fn.name })
}

exports.z = function (fn) {
  return Object.defineProperty(function () {
    const cb = arguments[arguments.length - 1]
    if (typeof cb !== 'function') return fn.apply(this, arguments)
    else fn.apply(this, arguments).then(r => cb(null, r), cb)
  }, 'name', { value: fn.name })
}


/***/ }),

/***/ 7739:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const crypto = __nccwpck_require__(6982);
const https = __nccwpck_require__(5692);

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
    // host 前缀/域名收敛到集中配置（#10 方案 B），按 region 动态拼
    const { CODEARTS_HOST_PREFIX, CODEARTS_API_DOMAIN } = __nccwpck_require__(3242);
    this.host = `${CODEARTS_HOST_PREFIX}.${region}.${CODEARTS_API_DOMAIN}`;
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

/***/ 3242:
/***/ ((module) => {

/**
 * 业务功能性端点集中配置（安全整改 #10 方案 B：集中配置化）。
 *
 * - 默认值与原硬编码值完全一致（等价变换，不改任何对外行为）；
 * - 环境切换只改本文件（或通过同名环境变量覆盖），不改业务源码；
 * - 同名环境变量优先级高于本文件默认值（如 OIDC_PROD_BASE）。
 */
module.exports = {
  // OIDC 回调网关（prod 正式环境 / beta 测试环境）
  // beta 域名说明：beta.apig.openlibing.com 已确认 DNS 指向华为云 APIG，但证书尚未
  // 绑定该域名（TLS 握手返回 *.apic.cn-southwest-2.huaweicloudapis.com 默认证书）。
  // 当前临时使用已发布 /action-api 接口的 APIG 域名，保证链路可测；平台绑定证书后应切回。
  OIDC_PROD_BASE: 'https://apig.openlibing.com',
  OIDC_BETA_BASE: 'https://174e1b821a8446f38998a67186ba766e.apic.cn-southwest-2.huaweicloudapis.com',

  // OBS：通用 SARIF 结果统一存放（后端 SarifParseServiceImpl 匿名 HTTP GET 下载）
  // 上传端点 server 由 OIDC SDK configure 动态返回 region，不在此写死
  OBS_BUCKET: 'openlibing-gitcode-action',
  OBS_READ_ENDPOINT: 'https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com',

  // CodeArts Check API host（按 region 动态拼：{HOST_PREFIX}.{region}.{API_DOMAIN}）
  CODEARTS_HOST_PREFIX: 'codecheck-ext',
  CODEARTS_API_DOMAIN: 'myhuaweicloud.com',

  // 结果解析查看页（回调成功后的 console 提示链接，prod / beta）
  RESULT_VIEW_BASE: 'https://www.openlibing.com/apps/codeCheck',
  RESULT_VIEW_BASE_BETA: 'https://beta.openlibing.com/apps/codeCheck'
};


/***/ }),

/***/ 9147:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(9896);

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

/***/ 9069:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const { buildPrimaryLocationLineHash } = __nccwpck_require__(4414);

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

/***/ 5301:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(9896);
const { buildPrimaryLocationLineHash } = __nccwpck_require__(4414);

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

/***/ 3389:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const fs = __nccwpck_require__(9896);
const { buildPrimaryLocationLineHash } = __nccwpck_require__(4414);

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

/***/ 7849:
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

const http = __nccwpck_require__(8611);
const https = __nccwpck_require__(5692);

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

/***/ 4414:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

"use strict";


const crypto = __nccwpck_require__(6982);

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

/***/ 8337:
/***/ ((module) => {

module.exports = eval("require")("undici");


/***/ }),

/***/ 2613:
/***/ ((module) => {

"use strict";
module.exports = require("assert");

/***/ }),

/***/ 5317:
/***/ ((module) => {

"use strict";
module.exports = require("child_process");

/***/ }),

/***/ 9907:
/***/ ((module) => {

"use strict";
module.exports = require("cluster");

/***/ }),

/***/ 9140:
/***/ ((module) => {

"use strict";
module.exports = require("constants");

/***/ }),

/***/ 6982:
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ 4434:
/***/ ((module) => {

"use strict";
module.exports = require("events");

/***/ }),

/***/ 9896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 8611:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 5692:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 9278:
/***/ ((module) => {

"use strict";
module.exports = require("net");

/***/ }),

/***/ 857:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ }),

/***/ 6928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ }),

/***/ 932:
/***/ ((module) => {

"use strict";
module.exports = require("process");

/***/ }),

/***/ 2203:
/***/ ((module) => {

"use strict";
module.exports = require("stream");

/***/ }),

/***/ 2018:
/***/ ((module) => {

"use strict";
module.exports = require("tty");

/***/ }),

/***/ 7016:
/***/ ((module) => {

"use strict";
module.exports = require("url");

/***/ }),

/***/ 9023:
/***/ ((module) => {

"use strict";
module.exports = require("util");

/***/ }),

/***/ 3106:
/***/ ((module) => {

"use strict";
module.exports = require("zlib");

/***/ }),

/***/ 8686:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

/// <reference types="../types/index.d.ts" />

// (c) 2020-present Andrea Giammarchi

const {parse: $parse, stringify: $stringify} = JSON;
const {keys} = Object;

const Primitive = String;   // it could be Number
const primitive = 'string'; // it could be 'number'

const ignore = {};
const object = 'object';

const noop = (_, value) => value;

const primitives = value => (
  value instanceof Primitive ? Primitive(value) : value
);

const Primitives = (_, value) => (
  typeof value === primitive ? new Primitive(value) : value
);

const resolver = (input, lazy, parsed, $) => output => {
  for (let ke = keys(output), {length} = ke, y = 0; y < length; y++) {
    const k = ke[y];
    const value = output[k];
    if (value instanceof Primitive) {
      const tmp = input[+value];
      if (typeof tmp === object && !parsed.has(tmp)) {
        parsed.add(tmp);
        output[k] = ignore;
        lazy.push({ o: output, k, r: tmp });
      }
      else
        output[k] = $.call(output, k, tmp);
    }
    else if (output[k] !== ignore)
      output[k] = $.call(output, k, value);
  }
  return output;
};

const set = (known, input, value) => {
  const index = Primitive(input.push(value) - 1);
  known.set(value, index);
  return index;
};

/**
 * Converts a specialized flatted string into a JS value.
 * @param {string} text
 * @param {(this: any, key: string, value: any) => any} [reviver]
 * @returns {any}
 */
const parse = (text, reviver) => {
  const input = $parse(text, Primitives).map(primitives);
  const $ = reviver || noop;

  let value = input[0];

  if (typeof value === object && value) {
    const lazy = [];
    const revive = resolver(input, lazy, new Set, $);
    value = revive(value);

    let i = 0;
    while (i < lazy.length) {
      // it could be a lazy.shift() but that's costly
      const {o, k, r} = lazy[i++];
      o[k] = $.call(o, k, revive(r));
    }
  }

  return $.call({'': value}, '', value);
};
exports.parse = parse;

/**
 * Converts a JS value into a specialized flatted string.
 * @param {any} value
 * @param {((this: any, key: string, value: any) => any) | (string | number)[] | null | undefined} [replacer]
 * @param {string | number | undefined} [space]
 * @returns {string}
 */
const stringify = (value, replacer, space) => {
  const $ = replacer && typeof replacer === object ?
            (k, v) => (k === '' || -1 < replacer.indexOf(k) ? v : void 0) :
            (replacer || noop);
  const known = new Map;
  const input = [];
  const output = [];
  let i = +set(known, input, $.call({'': value}, '', value));
  let firstRun = !i;
  while (i < input.length) {
    firstRun = true;
    output[i] = $stringify(input[i++], replace, space);
  }
  return '[' + output.join(',') + ']';
  function replace(key, value) {
    if (firstRun) {
      firstRun = !firstRun;
      return value;
    }
    const after = $.call(this, key, value);
    switch (typeof after) {
      case object:
        if (after === null) return after;
      case primitive:
        return known.get(after) || set(known, input, after);
    }
    return after;
  }
};
exports.stringify = stringify;

/**
 * Converts a generic value into a JSON serializable object without losing recursion.
 * @param {any} value
 * @returns {any}
 */
const toJSON = value => $parse(stringify(value));
exports.toJSON = toJSON;

/**
 * Converts a previously serialized object with recursion into a recursive one.
 * @param {any} value
 * @returns {any}
 */
const fromJSON = value => parse($stringify(value));
exports.fromJSON = fromJSON;


/***/ }),

/***/ 591:
/***/ ((module) => {

(()=>{"use strict";var t={d:(e,n)=>{for(var i in n)t.o(n,i)&&!t.o(e,i)&&Object.defineProperty(e,i,{enumerable:!0,get:n[i]})},o:(t,e)=>Object.prototype.hasOwnProperty.call(t,e),r:t=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})}},e={};t.r(e),t.d(e,{XMLBuilder:()=>pt,XMLParser:()=>st,XMLValidator:()=>xt});const n=":A-Za-z_\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD",i=new RegExp("^["+n+"]["+n+"\\-.\\d\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$");function s(t,e){const n=[];let i=e.exec(t);for(;i;){const s=[];s.startIndex=e.lastIndex-i[0].length;const r=i.length;for(let t=0;t<r;t++)s.push(i[t]);n.push(s),i=e.exec(t)}return n}const r=function(t){return!(null==i.exec(t))},o={allowBooleanAttributes:!1,unpairedTags:[]};function a(t,e){e=Object.assign({},o,e);const n=[];let i=!1,s=!1;"\ufeff"===t[0]&&(t=t.substr(1));for(let r=0;r<t.length;r++)if("<"===t[r]&&"?"===t[r+1]){if(r+=2,r=u(t,r),r.err)return r}else{if("<"!==t[r]){if(l(t[r]))continue;return m("InvalidChar","char '"+t[r]+"' is not expected.",N(t,r))}{let o=r;if(r++,"!"===t[r]){r=h(t,r);continue}{let a=!1;"/"===t[r]&&(a=!0,r++);let d="";for(;r<t.length&&">"!==t[r]&&" "!==t[r]&&"\t"!==t[r]&&"\n"!==t[r]&&"\r"!==t[r];r++)d+=t[r];if(d=d.trim(),"/"===d[d.length-1]&&(d=d.substring(0,d.length-1),r--),!b(d)){let e;return e=0===d.trim().length?"Invalid space after '<'.":"Tag '"+d+"' is an invalid name.",m("InvalidTag",e,N(t,r))}const p=f(t,r);if(!1===p)return m("InvalidAttr","Attributes for '"+d+"' have open quote.",N(t,r));let c=p.value;if(r=p.index,"/"===c[c.length-1]){const n=r-c.length;c=c.substring(0,c.length-1);const s=g(c,e);if(!0!==s)return m(s.err.code,s.err.msg,N(t,n+s.err.line));i=!0}else if(a){if(!p.tagClosed)return m("InvalidTag","Closing tag '"+d+"' doesn't have proper closing.",N(t,r));if(c.trim().length>0)return m("InvalidTag","Closing tag '"+d+"' can't have attributes or invalid starting.",N(t,o));if(0===n.length)return m("InvalidTag","Closing tag '"+d+"' has not been opened.",N(t,o));{const e=n.pop();if(d!==e.tagName){let n=N(t,e.tagStartPos);return m("InvalidTag","Expected closing tag '"+e.tagName+"' (opened in line "+n.line+", col "+n.col+") instead of closing tag '"+d+"'.",N(t,o))}0==n.length&&(s=!0)}}else{const a=g(c,e);if(!0!==a)return m(a.err.code,a.err.msg,N(t,r-c.length+a.err.line));if(!0===s)return m("InvalidXml","Multiple possible root nodes found.",N(t,r));-1!==e.unpairedTags.indexOf(d)||n.push({tagName:d,tagStartPos:o}),i=!0}for(r++;r<t.length;r++)if("<"===t[r]){if("!"===t[r+1]){r++,r=h(t,r);continue}if("?"!==t[r+1])break;if(r=u(t,++r),r.err)return r}else if("&"===t[r]){const e=x(t,r);if(-1==e)return m("InvalidChar","char '&' is not expected.",N(t,r));r=e}else if(!0===s&&!l(t[r]))return m("InvalidXml","Extra text at the end",N(t,r));"<"===t[r]&&r--}}}return i?1==n.length?m("InvalidTag","Unclosed tag '"+n[0].tagName+"'.",N(t,n[0].tagStartPos)):!(n.length>0)||m("InvalidXml","Invalid '"+JSON.stringify(n.map(t=>t.tagName),null,4).replace(/\r?\n/g,"")+"' found.",{line:1,col:1}):m("InvalidXml","Start tag expected.",1)}function l(t){return" "===t||"\t"===t||"\n"===t||"\r"===t}function u(t,e){const n=e;for(;e<t.length;e++)if("?"==t[e]||" "==t[e]){const i=t.substr(n,e-n);if(e>5&&"xml"===i)return m("InvalidXml","XML declaration allowed only at the start of the document.",N(t,e));if("?"==t[e]&&">"==t[e+1]){e++;break}continue}return e}function h(t,e){if(t.length>e+5&&"-"===t[e+1]&&"-"===t[e+2]){for(e+=3;e<t.length;e++)if("-"===t[e]&&"-"===t[e+1]&&">"===t[e+2]){e+=2;break}}else if(t.length>e+8&&"D"===t[e+1]&&"O"===t[e+2]&&"C"===t[e+3]&&"T"===t[e+4]&&"Y"===t[e+5]&&"P"===t[e+6]&&"E"===t[e+7]){let n=1;for(e+=8;e<t.length;e++)if("<"===t[e])n++;else if(">"===t[e]&&(n--,0===n))break}else if(t.length>e+9&&"["===t[e+1]&&"C"===t[e+2]&&"D"===t[e+3]&&"A"===t[e+4]&&"T"===t[e+5]&&"A"===t[e+6]&&"["===t[e+7])for(e+=8;e<t.length;e++)if("]"===t[e]&&"]"===t[e+1]&&">"===t[e+2]){e+=2;break}return e}const d='"',p="'";function f(t,e){let n="",i="",s=!1;for(;e<t.length;e++){if(t[e]===d||t[e]===p)""===i?i=t[e]:i!==t[e]||(i="");else if(">"===t[e]&&""===i){s=!0;break}n+=t[e]}return""===i&&{value:n,index:e,tagClosed:s}}const c=new RegExp("(\\s*)([^\\s=]+)(\\s*=)?(\\s*(['\"])(([\\s\\S])*?)\\5)?","g");function g(t,e){const n=s(t,c),i={};for(let t=0;t<n.length;t++){if(0===n[t][1].length)return m("InvalidAttr","Attribute '"+n[t][2]+"' has no space in starting.",y(n[t]));if(void 0!==n[t][3]&&void 0===n[t][4])return m("InvalidAttr","Attribute '"+n[t][2]+"' is without value.",y(n[t]));if(void 0===n[t][3]&&!e.allowBooleanAttributes)return m("InvalidAttr","boolean attribute '"+n[t][2]+"' is not allowed.",y(n[t]));const s=n[t][2];if(!E(s))return m("InvalidAttr","Attribute '"+s+"' is an invalid name.",y(n[t]));if(i.hasOwnProperty(s))return m("InvalidAttr","Attribute '"+s+"' is repeated.",y(n[t]));i[s]=1}return!0}function x(t,e){if(";"===t[++e])return-1;if("#"===t[e])return function(t,e){let n=/\d/;for("x"===t[e]&&(e++,n=/[\da-fA-F]/);e<t.length;e++){if(";"===t[e])return e;if(!t[e].match(n))break}return-1}(t,++e);let n=0;for(;e<t.length;e++,n++)if(!(t[e].match(/\w/)&&n<20)){if(";"===t[e])break;return-1}return e}function m(t,e,n){return{err:{code:t,msg:e,line:n.line||n,col:n.col}}}function E(t){return r(t)}function b(t){return r(t)}function N(t,e){const n=t.substring(0,e).split(/\r?\n/);return{line:n.length,col:n[n.length-1].length+1}}function y(t){return t.startIndex+t[1].length}const T={preserveOrder:!1,attributeNamePrefix:"@_",attributesGroupName:!1,textNodeName:"#text",ignoreAttributes:!0,removeNSPrefix:!1,allowBooleanAttributes:!1,parseTagValue:!0,parseAttributeValue:!1,trimValues:!0,cdataPropName:!1,numberParseOptions:{hex:!0,leadingZeros:!0,eNotation:!0},tagValueProcessor:function(t,e){return e},attributeValueProcessor:function(t,e){return e},stopNodes:[],alwaysCreateTextNode:!1,isArray:()=>!1,commentPropName:!1,unpairedTags:[],processEntities:!0,htmlEntities:!1,ignoreDeclaration:!1,ignorePiTags:!1,transformTagName:!1,transformAttributeName:!1,updateTag:function(t,e,n){return t},captureMetaData:!1};function w(t){return"boolean"==typeof t?{enabled:t,maxEntitySize:1e4,maxExpansionDepth:10,maxTotalExpansions:1e3,maxExpandedLength:1e5,allowedTags:null,tagFilter:null}:"object"==typeof t&&null!==t?{enabled:!1!==t.enabled,maxEntitySize:t.maxEntitySize??1e4,maxExpansionDepth:t.maxExpansionDepth??10,maxTotalExpansions:t.maxTotalExpansions??1e3,maxExpandedLength:t.maxExpandedLength??1e5,allowedTags:t.allowedTags??null,tagFilter:t.tagFilter??null}:w(!0)}const v=function(t){const e=Object.assign({},T,t);return e.processEntities=w(e.processEntities),e};let I;I="function"!=typeof Symbol?"@@xmlMetadata":Symbol("XML Node Metadata");class O{constructor(t){this.tagname=t,this.child=[],this[":@"]={}}add(t,e){"__proto__"===t&&(t="#__proto__"),this.child.push({[t]:e})}addChild(t,e){"__proto__"===t.tagname&&(t.tagname="#__proto__"),t[":@"]&&Object.keys(t[":@"]).length>0?this.child.push({[t.tagname]:t.child,":@":t[":@"]}):this.child.push({[t.tagname]:t.child}),void 0!==e&&(this.child[this.child.length-1][I]={startIndex:e})}static getMetaDataSymbol(){return I}}class P{constructor(t){this.suppressValidationErr=!t,this.options=t}readDocType(t,e){const n={};if("O"!==t[e+3]||"C"!==t[e+4]||"T"!==t[e+5]||"Y"!==t[e+6]||"P"!==t[e+7]||"E"!==t[e+8])throw new Error("Invalid Tag instead of DOCTYPE");{e+=9;let i=1,s=!1,r=!1,o="";for(;e<t.length;e++)if("<"!==t[e]||r)if(">"===t[e]){if(r?"-"===t[e-1]&&"-"===t[e-2]&&(r=!1,i--):i--,0===i)break}else"["===t[e]?s=!0:o+=t[e];else{if(s&&S(t,"!ENTITY",e)){let i,s;if(e+=7,[i,s,e]=this.readEntityExp(t,e+1,this.suppressValidationErr),-1===s.indexOf("&")){const t=i.replace(/[.\-+*:]/g,"\\.");n[i]={regx:RegExp(`&${t};`,"g"),val:s}}}else if(s&&S(t,"!ELEMENT",e)){e+=8;const{index:n}=this.readElementExp(t,e+1);e=n}else if(s&&S(t,"!ATTLIST",e))e+=8;else if(s&&S(t,"!NOTATION",e)){e+=9;const{index:n}=this.readNotationExp(t,e+1,this.suppressValidationErr);e=n}else{if(!S(t,"!--",e))throw new Error("Invalid DOCTYPE");r=!0}i++,o=""}if(0!==i)throw new Error("Unclosed DOCTYPE")}return{entities:n,i:e}}readEntityExp(t,e){e=A(t,e);let n="";for(;e<t.length&&!/\s/.test(t[e])&&'"'!==t[e]&&"'"!==t[e];)n+=t[e],e++;if(C(n),e=A(t,e),!this.suppressValidationErr){if("SYSTEM"===t.substring(e,e+6).toUpperCase())throw new Error("External entities are not supported");if("%"===t[e])throw new Error("Parameter entities are not supported")}let i="";if([e,i]=this.readIdentifierVal(t,e,"entity"),!1!==this.options.enabled&&this.options.maxEntitySize&&i.length>this.options.maxEntitySize)throw new Error(`Entity "${n}" size (${i.length}) exceeds maximum allowed size (${this.options.maxEntitySize})`);return[n,i,--e]}readNotationExp(t,e){e=A(t,e);let n="";for(;e<t.length&&!/\s/.test(t[e]);)n+=t[e],e++;!this.suppressValidationErr&&C(n),e=A(t,e);const i=t.substring(e,e+6).toUpperCase();if(!this.suppressValidationErr&&"SYSTEM"!==i&&"PUBLIC"!==i)throw new Error(`Expected SYSTEM or PUBLIC, found "${i}"`);e+=i.length,e=A(t,e);let s=null,r=null;if("PUBLIC"===i)[e,s]=this.readIdentifierVal(t,e,"publicIdentifier"),'"'!==t[e=A(t,e)]&&"'"!==t[e]||([e,r]=this.readIdentifierVal(t,e,"systemIdentifier"));else if("SYSTEM"===i&&([e,r]=this.readIdentifierVal(t,e,"systemIdentifier"),!this.suppressValidationErr&&!r))throw new Error("Missing mandatory system identifier for SYSTEM notation");return{notationName:n,publicIdentifier:s,systemIdentifier:r,index:--e}}readIdentifierVal(t,e,n){let i="";const s=t[e];if('"'!==s&&"'"!==s)throw new Error(`Expected quoted string, found "${s}"`);for(e++;e<t.length&&t[e]!==s;)i+=t[e],e++;if(t[e]!==s)throw new Error(`Unterminated ${n} value`);return[++e,i]}readElementExp(t,e){e=A(t,e);let n="";for(;e<t.length&&!/\s/.test(t[e]);)n+=t[e],e++;if(!this.suppressValidationErr&&!r(n))throw new Error(`Invalid element name: "${n}"`);let i="";if("E"===t[e=A(t,e)]&&S(t,"MPTY",e))e+=4;else if("A"===t[e]&&S(t,"NY",e))e+=2;else if("("===t[e]){for(e++;e<t.length&&")"!==t[e];)i+=t[e],e++;if(")"!==t[e])throw new Error("Unterminated content model")}else if(!this.suppressValidationErr)throw new Error(`Invalid Element Expression, found "${t[e]}"`);return{elementName:n,contentModel:i.trim(),index:e}}readAttlistExp(t,e){e=A(t,e);let n="";for(;e<t.length&&!/\s/.test(t[e]);)n+=t[e],e++;C(n),e=A(t,e);let i="";for(;e<t.length&&!/\s/.test(t[e]);)i+=t[e],e++;if(!C(i))throw new Error(`Invalid attribute name: "${i}"`);e=A(t,e);let s="";if("NOTATION"===t.substring(e,e+8).toUpperCase()){if(s="NOTATION","("!==t[e=A(t,e+=8)])throw new Error(`Expected '(', found "${t[e]}"`);e++;let n=[];for(;e<t.length&&")"!==t[e];){let i="";for(;e<t.length&&"|"!==t[e]&&")"!==t[e];)i+=t[e],e++;if(i=i.trim(),!C(i))throw new Error(`Invalid notation name: "${i}"`);n.push(i),"|"===t[e]&&(e++,e=A(t,e))}if(")"!==t[e])throw new Error("Unterminated list of notations");e++,s+=" ("+n.join("|")+")"}else{for(;e<t.length&&!/\s/.test(t[e]);)s+=t[e],e++;const n=["CDATA","ID","IDREF","IDREFS","ENTITY","ENTITIES","NMTOKEN","NMTOKENS"];if(!this.suppressValidationErr&&!n.includes(s.toUpperCase()))throw new Error(`Invalid attribute type: "${s}"`)}e=A(t,e);let r="";return"#REQUIRED"===t.substring(e,e+8).toUpperCase()?(r="#REQUIRED",e+=8):"#IMPLIED"===t.substring(e,e+7).toUpperCase()?(r="#IMPLIED",e+=7):[e,r]=this.readIdentifierVal(t,e,"ATTLIST"),{elementName:n,attributeName:i,attributeType:s,defaultValue:r,index:e}}}const A=(t,e)=>{for(;e<t.length&&/\s/.test(t[e]);)e++;return e};function S(t,e,n){for(let i=0;i<e.length;i++)if(e[i]!==t[n+i+1])return!1;return!0}function C(t){if(r(t))return t;throw new Error(`Invalid entity name ${t}`)}const $=/^[-+]?0x[a-fA-F0-9]+$/,V=/^([\-\+])?(0*)([0-9]*(\.[0-9]*)?)$/,D={hex:!0,leadingZeros:!0,decimalPoint:".",eNotation:!0};const L=/^([-+])?(0*)(\d*(\.\d*)?[eE][-\+]?\d+)$/;function F(t){return"function"==typeof t?t:Array.isArray(t)?e=>{for(const n of t){if("string"==typeof n&&e===n)return!0;if(n instanceof RegExp&&n.test(e))return!0}}:()=>!1}class j{constructor(t){if(this.options=t,this.currentNode=null,this.tagsNodeStack=[],this.docTypeEntities={},this.lastEntities={apos:{regex:/&(apos|#39|#x27);/g,val:"'"},gt:{regex:/&(gt|#62|#x3E);/g,val:">"},lt:{regex:/&(lt|#60|#x3C);/g,val:"<"},quot:{regex:/&(quot|#34|#x22);/g,val:'"'}},this.ampEntity={regex:/&(amp|#38|#x26);/g,val:"&"},this.htmlEntities={space:{regex:/&(nbsp|#160);/g,val:" "},cent:{regex:/&(cent|#162);/g,val:"¢"},pound:{regex:/&(pound|#163);/g,val:"£"},yen:{regex:/&(yen|#165);/g,val:"¥"},euro:{regex:/&(euro|#8364);/g,val:"€"},copyright:{regex:/&(copy|#169);/g,val:"©"},reg:{regex:/&(reg|#174);/g,val:"®"},inr:{regex:/&(inr|#8377);/g,val:"₹"},num_dec:{regex:/&#([0-9]{1,7});/g,val:(t,e)=>Q(e,10,"&#")},num_hex:{regex:/&#x([0-9a-fA-F]{1,6});/g,val:(t,e)=>Q(e,16,"&#x")}},this.addExternalEntities=M,this.parseXml=R,this.parseTextData=_,this.resolveNameSpace=k,this.buildAttributesMap=B,this.isItStopNode=z,this.replaceEntitiesValue=G,this.readStopNodeData=Z,this.saveTextToParentTag=X,this.addChild=Y,this.ignoreAttributesFn=F(this.options.ignoreAttributes),this.entityExpansionCount=0,this.currentExpandedLength=0,this.options.stopNodes&&this.options.stopNodes.length>0){this.stopNodesExact=new Set,this.stopNodesWildcard=new Set;for(let t=0;t<this.options.stopNodes.length;t++){const e=this.options.stopNodes[t];"string"==typeof e&&(e.startsWith("*.")?this.stopNodesWildcard.add(e.substring(2)):this.stopNodesExact.add(e))}}}}function M(t){const e=Object.keys(t);for(let n=0;n<e.length;n++){const i=e[n],s=i.replace(/[.\-+*:]/g,"\\.");this.lastEntities[i]={regex:new RegExp("&"+s+";","g"),val:t[i]}}}function _(t,e,n,i,s,r,o){if(void 0!==t&&(this.options.trimValues&&!i&&(t=t.trim()),t.length>0)){o||(t=this.replaceEntitiesValue(t,e,n));const i=this.options.tagValueProcessor(e,t,n,s,r);return null==i?t:typeof i!=typeof t||i!==t?i:this.options.trimValues||t.trim()===t?K(t,this.options.parseTagValue,this.options.numberParseOptions):t}}function k(t){if(this.options.removeNSPrefix){const e=t.split(":"),n="/"===t.charAt(0)?"/":"";if("xmlns"===e[0])return"";2===e.length&&(t=n+e[1])}return t}const U=new RegExp("([^\\s=]+)\\s*(=\\s*(['\"])([\\s\\S]*?)\\3)?","gm");function B(t,e,n){if(!0!==this.options.ignoreAttributes&&"string"==typeof t){const i=s(t,U),r=i.length,o={};for(let t=0;t<r;t++){const s=this.resolveNameSpace(i[t][1]);if(this.ignoreAttributesFn(s,e))continue;let r=i[t][4],a=this.options.attributeNamePrefix+s;if(s.length)if(this.options.transformAttributeName&&(a=this.options.transformAttributeName(a)),"__proto__"===a&&(a="#__proto__"),void 0!==r){this.options.trimValues&&(r=r.trim()),r=this.replaceEntitiesValue(r,n,e);const t=this.options.attributeValueProcessor(s,r,e);o[a]=null==t?r:typeof t!=typeof r||t!==r?t:K(r,this.options.parseAttributeValue,this.options.numberParseOptions)}else this.options.allowBooleanAttributes&&(o[a]=!0)}if(!Object.keys(o).length)return;if(this.options.attributesGroupName){const t={};return t[this.options.attributesGroupName]=o,t}return o}}const R=function(t){t=t.replace(/\r\n?/g,"\n");const e=new O("!xml");let n=e,i="",s="";this.entityExpansionCount=0,this.currentExpandedLength=0;const r=new P(this.options.processEntities);for(let o=0;o<t.length;o++)if("<"===t[o])if("/"===t[o+1]){const e=W(t,">",o,"Closing Tag is not closed.");let r=t.substring(o+2,e).trim();if(this.options.removeNSPrefix){const t=r.indexOf(":");-1!==t&&(r=r.substr(t+1))}this.options.transformTagName&&(r=this.options.transformTagName(r)),n&&(i=this.saveTextToParentTag(i,n,s));const a=s.substring(s.lastIndexOf(".")+1);if(r&&-1!==this.options.unpairedTags.indexOf(r))throw new Error(`Unpaired tag can not be used as closing tag: </${r}>`);let l=0;a&&-1!==this.options.unpairedTags.indexOf(a)?(l=s.lastIndexOf(".",s.lastIndexOf(".")-1),this.tagsNodeStack.pop()):l=s.lastIndexOf("."),s=s.substring(0,l),n=this.tagsNodeStack.pop(),i="",o=e}else if("?"===t[o+1]){let e=q(t,o,!1,"?>");if(!e)throw new Error("Pi Tag is not closed.");if(i=this.saveTextToParentTag(i,n,s),this.options.ignoreDeclaration&&"?xml"===e.tagName||this.options.ignorePiTags);else{const t=new O(e.tagName);t.add(this.options.textNodeName,""),e.tagName!==e.tagExp&&e.attrExpPresent&&(t[":@"]=this.buildAttributesMap(e.tagExp,s,e.tagName)),this.addChild(n,t,s,o)}o=e.closeIndex+1}else if("!--"===t.substr(o+1,3)){const e=W(t,"--\x3e",o+4,"Comment is not closed.");if(this.options.commentPropName){const r=t.substring(o+4,e-2);i=this.saveTextToParentTag(i,n,s),n.add(this.options.commentPropName,[{[this.options.textNodeName]:r}])}o=e}else if("!D"===t.substr(o+1,2)){const e=r.readDocType(t,o);this.docTypeEntities=e.entities,o=e.i}else if("!["===t.substr(o+1,2)){const e=W(t,"]]>",o,"CDATA is not closed.")-2,r=t.substring(o+9,e);i=this.saveTextToParentTag(i,n,s);let a=this.parseTextData(r,n.tagname,s,!0,!1,!0,!0);null==a&&(a=""),this.options.cdataPropName?n.add(this.options.cdataPropName,[{[this.options.textNodeName]:r}]):n.add(this.options.textNodeName,a),o=e+2}else{let r=q(t,o,this.options.removeNSPrefix),a=r.tagName;const l=r.rawTagName;let u=r.tagExp,h=r.attrExpPresent,d=r.closeIndex;if(this.options.transformTagName){const t=this.options.transformTagName(a);u===a&&(u=t),a=t}n&&i&&"!xml"!==n.tagname&&(i=this.saveTextToParentTag(i,n,s,!1));const p=n;p&&-1!==this.options.unpairedTags.indexOf(p.tagname)&&(n=this.tagsNodeStack.pop(),s=s.substring(0,s.lastIndexOf("."))),a!==e.tagname&&(s+=s?"."+a:a);const f=o;if(this.isItStopNode(this.stopNodesExact,this.stopNodesWildcard,s,a)){let e="";if(u.length>0&&u.lastIndexOf("/")===u.length-1)"/"===a[a.length-1]?(a=a.substr(0,a.length-1),s=s.substr(0,s.length-1),u=a):u=u.substr(0,u.length-1),o=r.closeIndex;else if(-1!==this.options.unpairedTags.indexOf(a))o=r.closeIndex;else{const n=this.readStopNodeData(t,l,d+1);if(!n)throw new Error(`Unexpected end of ${l}`);o=n.i,e=n.tagContent}const i=new O(a);a!==u&&h&&(i[":@"]=this.buildAttributesMap(u,s,a)),e&&(e=this.parseTextData(e,a,s,!0,h,!0,!0)),s=s.substr(0,s.lastIndexOf(".")),i.add(this.options.textNodeName,e),this.addChild(n,i,s,f)}else{if(u.length>0&&u.lastIndexOf("/")===u.length-1){if("/"===a[a.length-1]?(a=a.substr(0,a.length-1),s=s.substr(0,s.length-1),u=a):u=u.substr(0,u.length-1),this.options.transformTagName){const t=this.options.transformTagName(a);u===a&&(u=t),a=t}const t=new O(a);a!==u&&h&&(t[":@"]=this.buildAttributesMap(u,s,a)),this.addChild(n,t,s,f),s=s.substr(0,s.lastIndexOf("."))}else{const t=new O(a);this.tagsNodeStack.push(n),a!==u&&h&&(t[":@"]=this.buildAttributesMap(u,s,a)),this.addChild(n,t,s,f),n=t}i="",o=d}}else i+=t[o];return e.child};function Y(t,e,n,i){this.options.captureMetaData||(i=void 0);const s=this.options.updateTag(e.tagname,n,e[":@"]);!1===s||("string"==typeof s?(e.tagname=s,t.addChild(e,i)):t.addChild(e,i))}const G=function(t,e,n){if(-1===t.indexOf("&"))return t;const i=this.options.processEntities;if(!i.enabled)return t;if(i.allowedTags&&!i.allowedTags.includes(e))return t;if(i.tagFilter&&!i.tagFilter(e,n))return t;for(let e in this.docTypeEntities){const n=this.docTypeEntities[e],s=t.match(n.regx);if(s){if(this.entityExpansionCount+=s.length,i.maxTotalExpansions&&this.entityExpansionCount>i.maxTotalExpansions)throw new Error(`Entity expansion limit exceeded: ${this.entityExpansionCount} > ${i.maxTotalExpansions}`);const e=t.length;if(t=t.replace(n.regx,n.val),i.maxExpandedLength&&(this.currentExpandedLength+=t.length-e,this.currentExpandedLength>i.maxExpandedLength))throw new Error(`Total expanded content size exceeded: ${this.currentExpandedLength} > ${i.maxExpandedLength}`)}}if(-1===t.indexOf("&"))return t;for(let e in this.lastEntities){const n=this.lastEntities[e];t=t.replace(n.regex,n.val)}if(-1===t.indexOf("&"))return t;if(this.options.htmlEntities)for(let e in this.htmlEntities){const n=this.htmlEntities[e];t=t.replace(n.regex,n.val)}return t.replace(this.ampEntity.regex,this.ampEntity.val)};function X(t,e,n,i){return t&&(void 0===i&&(i=0===e.child.length),void 0!==(t=this.parseTextData(t,e.tagname,n,!1,!!e[":@"]&&0!==Object.keys(e[":@"]).length,i))&&""!==t&&e.add(this.options.textNodeName,t),t=""),t}function z(t,e,n,i){return!(!e||!e.has(i))||!(!t||!t.has(n))}function W(t,e,n,i){const s=t.indexOf(e,n);if(-1===s)throw new Error(i);return s+e.length-1}function q(t,e,n,i=">"){const s=function(t,e,n=">"){let i,s="";for(let r=e;r<t.length;r++){let e=t[r];if(i)e===i&&(i="");else if('"'===e||"'"===e)i=e;else if(e===n[0]){if(!n[1])return{data:s,index:r};if(t[r+1]===n[1])return{data:s,index:r}}else"\t"===e&&(e=" ");s+=e}}(t,e+1,i);if(!s)return;let r=s.data;const o=s.index,a=r.search(/\s/);let l=r,u=!0;-1!==a&&(l=r.substring(0,a),r=r.substring(a+1).trimStart());const h=l;if(n){const t=l.indexOf(":");-1!==t&&(l=l.substr(t+1),u=l!==s.data.substr(t+1))}return{tagName:l,tagExp:r,closeIndex:o,attrExpPresent:u,rawTagName:h}}function Z(t,e,n){const i=n;let s=1;for(;n<t.length;n++)if("<"===t[n])if("/"===t[n+1]){const r=W(t,">",n,`${e} is not closed`);if(t.substring(n+2,r).trim()===e&&(s--,0===s))return{tagContent:t.substring(i,n),i:r};n=r}else if("?"===t[n+1])n=W(t,"?>",n+1,"StopNode is not closed.");else if("!--"===t.substr(n+1,3))n=W(t,"--\x3e",n+3,"StopNode is not closed.");else if("!["===t.substr(n+1,2))n=W(t,"]]>",n,"StopNode is not closed.")-2;else{const i=q(t,n,">");i&&((i&&i.tagName)===e&&"/"!==i.tagExp[i.tagExp.length-1]&&s++,n=i.closeIndex)}}function K(t,e,n){if(e&&"string"==typeof t){const e=t.trim();return"true"===e||"false"!==e&&function(t,e={}){if(e=Object.assign({},D,e),!t||"string"!=typeof t)return t;let n=t.trim();if(void 0!==e.skipLike&&e.skipLike.test(n))return t;if("0"===t)return 0;if(e.hex&&$.test(n))return function(t){if(parseInt)return parseInt(t,16);if(Number.parseInt)return Number.parseInt(t,16);if(window&&window.parseInt)return window.parseInt(t,16);throw new Error("parseInt, Number.parseInt, window.parseInt are not supported")}(n);if(n.includes("e")||n.includes("E"))return function(t,e,n){if(!n.eNotation)return t;const i=e.match(L);if(i){let s=i[1]||"";const r=-1===i[3].indexOf("e")?"E":"e",o=i[2],a=s?t[o.length+1]===r:t[o.length]===r;return o.length>1&&a?t:1!==o.length||!i[3].startsWith(`.${r}`)&&i[3][0]!==r?n.leadingZeros&&!a?(e=(i[1]||"")+i[3],Number(e)):t:Number(e)}return t}(t,n,e);{const s=V.exec(n);if(s){const r=s[1]||"",o=s[2];let a=(i=s[3])&&-1!==i.indexOf(".")?("."===(i=i.replace(/0+$/,""))?i="0":"."===i[0]?i="0"+i:"."===i[i.length-1]&&(i=i.substring(0,i.length-1)),i):i;const l=r?"."===t[o.length+1]:"."===t[o.length];if(!e.leadingZeros&&(o.length>1||1===o.length&&!l))return t;{const i=Number(n),s=String(i);if(0===i)return i;if(-1!==s.search(/[eE]/))return e.eNotation?i:t;if(-1!==n.indexOf("."))return"0"===s||s===a||s===`${r}${a}`?i:t;let l=o?a:n;return o?l===s||r+l===s?i:t:l===s||l===r+s?i:t}}return t}var i}(t,n)}return void 0!==t?t:""}function Q(t,e,n){const i=Number.parseInt(t,e);return i>=0&&i<=1114111?String.fromCodePoint(i):n+t+";"}const J=O.getMetaDataSymbol();function H(t,e){return tt(t,e)}function tt(t,e,n){let i;const s={};for(let r=0;r<t.length;r++){const o=t[r],a=et(o);let l="";if(l=void 0===n?a:n+"."+a,a===e.textNodeName)void 0===i?i=o[a]:i+=""+o[a];else{if(void 0===a)continue;if(o[a]){let t=tt(o[a],e,l);const n=it(t,e);void 0!==o[J]&&(t[J]=o[J]),o[":@"]?nt(t,o[":@"],l,e):1!==Object.keys(t).length||void 0===t[e.textNodeName]||e.alwaysCreateTextNode?0===Object.keys(t).length&&(e.alwaysCreateTextNode?t[e.textNodeName]="":t=""):t=t[e.textNodeName],void 0!==s[a]&&s.hasOwnProperty(a)?(Array.isArray(s[a])||(s[a]=[s[a]]),s[a].push(t)):e.isArray(a,l,n)?s[a]=[t]:s[a]=t}}}return"string"==typeof i?i.length>0&&(s[e.textNodeName]=i):void 0!==i&&(s[e.textNodeName]=i),s}function et(t){const e=Object.keys(t);for(let t=0;t<e.length;t++){const n=e[t];if(":@"!==n)return n}}function nt(t,e,n,i){if(e){const s=Object.keys(e),r=s.length;for(let o=0;o<r;o++){const r=s[o];i.isArray(r,n+"."+r,!0,!0)?t[r]=[e[r]]:t[r]=e[r]}}}function it(t,e){const{textNodeName:n}=e,i=Object.keys(t).length;return 0===i||!(1!==i||!t[n]&&"boolean"!=typeof t[n]&&0!==t[n])}class st{constructor(t){this.externalEntities={},this.options=v(t)}parse(t,e){if("string"!=typeof t&&t.toString)t=t.toString();else if("string"!=typeof t)throw new Error("XML data is accepted in String or Bytes[] form.");if(e){!0===e&&(e={});const n=a(t,e);if(!0!==n)throw Error(`${n.err.msg}:${n.err.line}:${n.err.col}`)}const n=new j(this.options);n.addExternalEntities(this.externalEntities);const i=n.parseXml(t);return this.options.preserveOrder||void 0===i?i:H(i,this.options)}addEntity(t,e){if(-1!==e.indexOf("&"))throw new Error("Entity value can't have '&'");if(-1!==t.indexOf("&")||-1!==t.indexOf(";"))throw new Error("An entity must be set without '&' and ';'. Eg. use '#xD' for '&#xD;'");if("&"===e)throw new Error("An entity with value '&' is not permitted");this.externalEntities[t]=e}static getMetaDataSymbol(){return O.getMetaDataSymbol()}}function rt(t,e){let n="";return e.format&&e.indentBy.length>0&&(n="\n"),ot(t,e,"",n)}function ot(t,e,n,i){let s="",r=!1;for(let o=0;o<t.length;o++){const a=t[o],l=at(a);if(void 0===l)continue;let u="";if(u=0===n.length?l:`${n}.${l}`,l===e.textNodeName){let t=a[l];ut(u,e)||(t=e.tagValueProcessor(l,t),t=ht(t,e)),r&&(s+=i),s+=t,r=!1;continue}if(l===e.cdataPropName){r&&(s+=i),s+=`<![CDATA[${a[l][0][e.textNodeName]}]]>`,r=!1;continue}if(l===e.commentPropName){s+=i+`\x3c!--${a[l][0][e.textNodeName]}--\x3e`,r=!0;continue}if("?"===l[0]){const t=lt(a[":@"],e),n="?xml"===l?"":i;let o=a[l][0][e.textNodeName];o=0!==o.length?" "+o:"",s+=n+`<${l}${o}${t}?>`,r=!0;continue}let h=i;""!==h&&(h+=e.indentBy);const d=i+`<${l}${lt(a[":@"],e)}`,p=ot(a[l],e,u,h);-1!==e.unpairedTags.indexOf(l)?e.suppressUnpairedNode?s+=d+">":s+=d+"/>":p&&0!==p.length||!e.suppressEmptyNode?p&&p.endsWith(">")?s+=d+`>${p}${i}</${l}>`:(s+=d+">",p&&""!==i&&(p.includes("/>")||p.includes("</"))?s+=i+e.indentBy+p+i:s+=p,s+=`</${l}>`):s+=d+"/>",r=!0}return s}function at(t){const e=Object.keys(t);for(let n=0;n<e.length;n++){const i=e[n];if(t.hasOwnProperty(i)&&":@"!==i)return i}}function lt(t,e){let n="";if(t&&!e.ignoreAttributes)for(let i in t){if(!t.hasOwnProperty(i))continue;let s=e.attributeValueProcessor(i,t[i]);s=ht(s,e),!0===s&&e.suppressBooleanAttributes?n+=` ${i.substr(e.attributeNamePrefix.length)}`:n+=` ${i.substr(e.attributeNamePrefix.length)}="${s}"`}return n}function ut(t,e){let n=(t=t.substr(0,t.length-e.textNodeName.length-1)).substr(t.lastIndexOf(".")+1);for(let i in e.stopNodes)if(e.stopNodes[i]===t||e.stopNodes[i]==="*."+n)return!0;return!1}function ht(t,e){if(t&&t.length>0&&e.processEntities)for(let n=0;n<e.entities.length;n++){const i=e.entities[n];t=t.replace(i.regex,i.val)}return t}const dt={attributeNamePrefix:"@_",attributesGroupName:!1,textNodeName:"#text",ignoreAttributes:!0,cdataPropName:!1,format:!1,indentBy:"  ",suppressEmptyNode:!1,suppressUnpairedNode:!0,suppressBooleanAttributes:!0,tagValueProcessor:function(t,e){return e},attributeValueProcessor:function(t,e){return e},preserveOrder:!1,commentPropName:!1,unpairedTags:[],entities:[{regex:new RegExp("&","g"),val:"&amp;"},{regex:new RegExp(">","g"),val:"&gt;"},{regex:new RegExp("<","g"),val:"&lt;"},{regex:new RegExp("'","g"),val:"&apos;"},{regex:new RegExp('"',"g"),val:"&quot;"}],processEntities:!0,stopNodes:[],oneListGroup:!1};function pt(t){this.options=Object.assign({},dt,t),!0===this.options.ignoreAttributes||this.options.attributesGroupName?this.isAttribute=function(){return!1}:(this.ignoreAttributesFn=F(this.options.ignoreAttributes),this.attrPrefixLen=this.options.attributeNamePrefix.length,this.isAttribute=gt),this.processTextOrObjNode=ft,this.options.format?(this.indentate=ct,this.tagEndChar=">\n",this.newLine="\n"):(this.indentate=function(){return""},this.tagEndChar=">",this.newLine="")}function ft(t,e,n,i){const s=this.j2x(t,n+1,i.concat(e));return void 0!==t[this.options.textNodeName]&&1===Object.keys(t).length?this.buildTextValNode(t[this.options.textNodeName],e,s.attrStr,n):this.buildObjectNode(s.val,e,s.attrStr,n)}function ct(t){return this.options.indentBy.repeat(t)}function gt(t){return!(!t.startsWith(this.options.attributeNamePrefix)||t===this.options.textNodeName)&&t.substr(this.attrPrefixLen)}pt.prototype.build=function(t){return this.options.preserveOrder?rt(t,this.options):(Array.isArray(t)&&this.options.arrayNodeName&&this.options.arrayNodeName.length>1&&(t={[this.options.arrayNodeName]:t}),this.j2x(t,0,[]).val)},pt.prototype.j2x=function(t,e,n){let i="",s="";const r=n.join(".");for(let o in t)if(Object.prototype.hasOwnProperty.call(t,o))if(void 0===t[o])this.isAttribute(o)&&(s+="");else if(null===t[o])this.isAttribute(o)||o===this.options.cdataPropName?s+="":"?"===o[0]?s+=this.indentate(e)+"<"+o+"?"+this.tagEndChar:s+=this.indentate(e)+"<"+o+"/"+this.tagEndChar;else if(t[o]instanceof Date)s+=this.buildTextValNode(t[o],o,"",e);else if("object"!=typeof t[o]){const n=this.isAttribute(o);if(n&&!this.ignoreAttributesFn(n,r))i+=this.buildAttrPairStr(n,""+t[o]);else if(!n)if(o===this.options.textNodeName){let e=this.options.tagValueProcessor(o,""+t[o]);s+=this.replaceEntitiesValue(e)}else s+=this.buildTextValNode(t[o],o,"",e)}else if(Array.isArray(t[o])){const i=t[o].length;let r="",a="";for(let l=0;l<i;l++){const i=t[o][l];if(void 0===i);else if(null===i)"?"===o[0]?s+=this.indentate(e)+"<"+o+"?"+this.tagEndChar:s+=this.indentate(e)+"<"+o+"/"+this.tagEndChar;else if("object"==typeof i)if(this.options.oneListGroup){const t=this.j2x(i,e+1,n.concat(o));r+=t.val,this.options.attributesGroupName&&i.hasOwnProperty(this.options.attributesGroupName)&&(a+=t.attrStr)}else r+=this.processTextOrObjNode(i,o,e,n);else if(this.options.oneListGroup){let t=this.options.tagValueProcessor(o,i);t=this.replaceEntitiesValue(t),r+=t}else r+=this.buildTextValNode(i,o,"",e)}this.options.oneListGroup&&(r=this.buildObjectNode(r,o,a,e)),s+=r}else if(this.options.attributesGroupName&&o===this.options.attributesGroupName){const e=Object.keys(t[o]),n=e.length;for(let s=0;s<n;s++)i+=this.buildAttrPairStr(e[s],""+t[o][e[s]])}else s+=this.processTextOrObjNode(t[o],o,e,n);return{attrStr:i,val:s}},pt.prototype.buildAttrPairStr=function(t,e){return e=this.options.attributeValueProcessor(t,""+e),e=this.replaceEntitiesValue(e),this.options.suppressBooleanAttributes&&"true"===e?" "+t:" "+t+'="'+e+'"'},pt.prototype.buildObjectNode=function(t,e,n,i){if(""===t)return"?"===e[0]?this.indentate(i)+"<"+e+n+"?"+this.tagEndChar:this.indentate(i)+"<"+e+n+this.closeTag(e)+this.tagEndChar;{let s="</"+e+this.tagEndChar,r="";return"?"===e[0]&&(r="?",s=""),!n&&""!==n||-1!==t.indexOf("<")?!1!==this.options.commentPropName&&e===this.options.commentPropName&&0===r.length?this.indentate(i)+`\x3c!--${t}--\x3e`+this.newLine:this.indentate(i)+"<"+e+n+r+this.tagEndChar+t+this.indentate(i)+s:this.indentate(i)+"<"+e+n+r+">"+t+s}},pt.prototype.closeTag=function(t){let e="";return-1!==this.options.unpairedTags.indexOf(t)?this.options.suppressUnpairedNode||(e="/"):e=this.options.suppressEmptyNode?"/":`></${t}`,e},pt.prototype.buildTextValNode=function(t,e,n,i){if(!1!==this.options.cdataPropName&&e===this.options.cdataPropName)return this.indentate(i)+`<![CDATA[${t}]]>`+this.newLine;if(!1!==this.options.commentPropName&&e===this.options.commentPropName)return this.indentate(i)+`\x3c!--${t}--\x3e`+this.newLine;if("?"===e[0])return this.indentate(i)+"<"+e+n+"?"+this.tagEndChar;{let s=this.options.tagValueProcessor(e,t);return s=this.replaceEntitiesValue(s),""===s?this.indentate(i)+"<"+e+n+this.closeTag(e)+this.tagEndChar:this.indentate(i)+"<"+e+n+">"+s+"</"+e+this.tagEndChar}},pt.prototype.replaceEntitiesValue=function(t){if(t&&t.length>0&&this.options.processEntities)for(let e=0;e<this.options.entities.length;e++){const n=this.options.entities[e];t=t.replace(n.regex,n.val)}return t};const xt={validate:a};module.exports=e})();

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
/******/ 	var __webpack_exports__ = __nccwpck_require__(6136);
/******/ 	module.exports = __webpack_exports__;
/******/
/******/ })()
;
