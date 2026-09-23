'use strict';

const crypto = require('crypto');
const https = require('https');

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
 * 示例:
 * https://devcloud.cn-north-4.huaweicloud.com/codechecknew/project/{projectId}/codecheck/task/{type}/{taskId}/tasklog?jobId={jobId}
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
