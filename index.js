'use strict';

const { installFetchPolyfill } = require('./src/util/fetchPolyfill');
// GitCode 插件 runtime 为 node16，无全局 fetch；注入最小 polyfill，否则
// OIDC SDK 会回退 require('undici') 导致 "Cannot find module 'undici'"。
installFetchPolyfill();

const { execSync, execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const ObsClient = require('esdk-obs-nodejs');

const CodeCheckReportParser = require('./src/parser/CodeCheckReportParser');
const SarifGenerator = require('./src/sarif/SarifGenerator');
const SarifNormalizer = require('./src/sarif/SarifNormalizer');
const SarifUriNormalizer = require('./src/sarif/SarifUriNormalizer');
const CodeArtsCheckApi = require('./src/api/CodeArtsCheckApi');

// OIDC 签名 SDK：APIG V11-HMAC-SHA256 签名 + HTTPS 请求 + 自包含 OIDC 换证。
// getCredentials() 通过 Actions 兼容流水线环境变量（ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN）
// 自申请 OIDC ID Token，再调用华为云 STS AssumeAgencyWithOIDC 换取临时 AK/SK/SecurityToken，
// 无需在 workflow 中额外运行 huaweicloud-oidc-auth 插件（仅需声明 permissions: id-token: write）。
let V11Signer = null;
let sendRequest = null;
let getCredentials = null;
let configure = null;
try {
  ({ V11Signer, sendRequest, getCredentials, configure } = require('@openlibing/huaweicloud-oidc-client'));
} catch (e) {
  console.log('[ERROR] @openlibing/huaweicloud-oidc-client 加载失败，请重新构建 dist 后重试');
}

// ---------- 常量 ----------

const APIG_SIGN_REGION = 'cn-southwest-2'; // APIG V11 签名区域
const OIDC_API_PREFIX = '/action-api'; // OIDC 回调路径前缀（网关 IAM 认证）
const CALLBACK_PATH = '/codescan/v1/result/receive';
// 业务功能性公网端点集中配置（#10 方案 B），默认值见 src/config/endpoints.js；
// 可通过同名环境变量覆盖（环境切换不改源码）。
const ENDPOINTS = require('./src/config/endpoints');
const OIDC_PROD_BASE = process.env.OIDC_PROD_BASE || ENDPOINTS.OIDC_PROD_BASE;
const OIDC_BETA_BASE = process.env.OIDC_BETA_BASE || ENDPOINTS.OIDC_BETA_BASE;

// OBS：通用 SARIF 结果统一存放（后端 SarifParseServiceImpl 匿名 HTTP GET 下载）
// 上传端点 server 由 OIDC SDK configure 动态返回 region，不在此写死
const OBS_KEY_ROOT = 'code-arts-check-results'; // buildToolPrefix 兜底前缀（工具名缺失时）
const OBS_BUCKET = process.env.OBS_BUCKET || ENDPOINTS.OBS_BUCKET;
const OBS_READ_ENDPOINT = process.env.OBS_READ_ENDPOINT || ENDPOINTS.OBS_READ_ENDPOINT;

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
 * 将 SARIF uri 解析为源码根目录下的真实文件路径；找不到或越出 sourceRoots 边界返回 null。
 * 依次尝试：绝对路径（file:// 或 / 开头）→ sourceRoots 直接拼接 → 按文件名递归兜底查找。
 * 所有路径统一 path.resolve 归一化后做前缀校验（阻断 ../ 越界与工作区外绝对路径）。
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
      return fs.existsSync(resolved) && fs.statSync(resolved).isFile() ? resolved : null;
    } catch (e) {
      return null;
    }
  }
  if (/^[a-zA-Z]:[\\/]/.test(p) || p.startsWith('/')) {
    const resolved = path.resolve(p);
    if (!isWithinRoots(resolved, roots)) return null;
    return fs.existsSync(resolved) && fs.statSync(resolved).isFile() ? resolved : null;
  }
  p = p.replace(/^\.\//, '').replace(/^\/+/, '');
  for (const root of roots) {
    const cand = path.resolve(root, p); // resolve 归一化，../ 被折叠为真实目标
    if (cand !== root && !cand.startsWith(root + path.sep)) continue; // 阻断 ../ 越出该根
    if (fs.existsSync(cand) && fs.statSync(cand).isFile()) return cand;
  }
  const base = path.basename(p);
  if (base) {
    for (const root of roots) {
      const found = findFirst([root, '-name', base, '-type', 'f']);
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

    // 凭证类规则判定（Ref issues #11/#12）：命中则 snippet/上下文中的字符串字面量掩码
    const isCredentialRule = CREDENTIAL_RULE_RE.test(buildRuleInfoText(r, sarifObj));
    const maskText = (text) => (isCredentialRule ? maskCredentialSnippet(text) : text);

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

if (require.main === module) {
  run().catch((err) => {
    console.error(`Action 执行失败: ${sanitizePath(err.message)}`);
    setOutput('result', 'failed');
    process.exit(1);
  });
}
