'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const CodeArtsCheckApi = require('../src/api/CodeArtsCheckApi');
const { signRequest } = require('../src/api/CodeArtsCheckApi');

// ---------- 签名算法 ----------

// 独立复算实现（模拟服务端校验，验证客户端签名自洽）
// 与 src/api/CodeArtsCheckApi.js 的 APIG SDK-HMAC-SHA256 规范一致
function signLocal(opts) {
  const ALGORITHM = 'SDK-HMAC-SHA256';
  const rfc3986Encode = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  const sha256Hex = (c) => crypto.createHash('sha256').update(c, 'utf8').digest('hex');
  const canonicalURI = (uri) => {
    const segments = String(uri || '/').split('/');
    const encoded = segments.map((s) => rfc3986Encode(s)).join('/');
    if (encoded.length === 0 || encoded[encoded.length - 1] !== '/') return encoded + '/';
    return encoded;
  };

  const xSdkDate = opts.xSdkDate;
  const headers = { ...opts.headers, 'x-sdk-date': xSdkDate };
  const signedHeaders = ['host', 'x-sdk-date'];
  const canonicalQuery = Object.keys(opts.query).sort()
    .map((k) => `${rfc3986Encode(k)}=${rfc3986Encode(String(opts.query[k]))}`)
    .join('&');
  const canonicalHeaders = signedHeaders
    .map((h) => `${h}:${String(headers[h] || '').trim().replace(/\s+/g, ' ')}\n`)
    .join('');
  const canonicalRequest = [opts.method, canonicalURI(opts.uri), canonicalQuery, canonicalHeaders, signedHeaders.join(';'), sha256Hex(opts.payload)].join('\n');
  const stringToSign = [ALGORITHM, xSdkDate, sha256Hex(canonicalRequest)].join('\n');
  const signature = crypto.createHmac('sha256', opts.sk).update(stringToSign, 'utf8').digest('hex');
  return `SDK-HMAC-SHA256 Access=${opts.ak}, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`;
}

test('signRequest: GET 请求签名与服务端复算一致', () => {
  const signed = signRequest({
    method: 'GET',
    uri: '/v2/p1/tasks',
    query: { page: 1, page_size: 100 },
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com', 'Content-Type': 'application/json' },
    payload: '',
    ak: 'AK1',
    sk: 'SK1'
  });
  assert.match(signed['x-sdk-date'], /^\d{8}T\d{6}Z$/);
  const expected = signLocal({
    method: 'GET',
    uri: '/v2/p1/tasks',
    query: { page: 1, page_size: 100 },
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com' },
    payload: '',
    ak: 'AK1',
    sk: 'SK1',
    region: 'cn-north-4',
    xSdkDate: signed['x-sdk-date']
  });
  assert.strictEqual(signed.Authorization, expected);
  assert.match(signed.Authorization, /^SDK-HMAC-SHA256 Access=AK1, SignedHeaders=host;x-sdk-date, Signature=[0-9a-f]{64}$/);
});

test('signRequest: POST 带 body 签名与服务端复算一致', () => {
  const payload = JSON.stringify({ taskId: 'abc123', page: 1, pageSize: 200 });
  const signed = signRequest({
    method: 'POST',
    uri: '/v1/defect/issue-list-by-filter',
    query: {},
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com', 'Content-Type': 'application/json' },
    payload,
    ak: 'AK2',
    sk: 'SK2'
  });
  const expected = signLocal({
    method: 'POST',
    uri: '/v1/defect/issue-list-by-filter',
    query: {},
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com' },
    payload,
    ak: 'AK2',
    sk: 'SK2',
    region: 'cn-north-4',
    xSdkDate: signed['x-sdk-date']
  });
  assert.strictEqual(signed.Authorization, expected);
});

test('signRequest: query 编码排序后签名与服务端复算一致（含特殊字符）', () => {
  const signed = signRequest({
    method: 'GET',
    uri: '/v2/p1/tasks',
    query: { name: '任务 A', b: '2', a: '1' },
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com' },
    payload: '',
    ak: 'AK3',
    sk: 'SK3'
  });
  const expected = signLocal({
    method: 'GET',
    uri: '/v2/p1/tasks',
    query: { name: '任务 A', b: '2', a: '1' },
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com' },
    payload: '',
    ak: 'AK3',
    sk: 'SK3',
    region: 'cn-north-4',
    xSdkDate: signed['x-sdk-date']
  });
  assert.strictEqual(signed.Authorization, expected);
});

test('CodeArtsCheckApi: 缺少 ak/sk 抛错', () => {
  assert.throws(() => new CodeArtsCheckApi({ ak: '', sk: '' }), /缺少 CodeArts Check 鉴权凭证/);
  assert.throws(() => new CodeArtsCheckApi({ ak: 'A', sk: '' }), /缺少 CodeArts Check 鉴权凭证/);
});

// ---------- codeCheck_task_url 解析 ----------

test('parseTaskUrl: 完整任务 URL 解析 project_id/task_id/jobId/region', () => {
  const parsed = CodeArtsCheckApi.parseTaskUrl(
    'https://devcloud.cn-north-4.huaweicloud.com/codechecknew/project/d36de72016bb4ab5a701ae59d9bf64e1/codecheck/task/green/13ff62475ee747ae90fbd9b64ac66a24/tasklog?jobId=6165f2b952d04d85a208f091d7757eb1'
  );
  assert.deepStrictEqual(parsed, {
    projectId: 'd36de72016bb4ab5a701ae59d9bf64e1',
    taskId: '13ff62475ee747ae90fbd9b64ac66a24',
    jobId: '6165f2b952d04d85a208f091d7757eb1',
    region: 'cn-north-4'
  });
});

test('parseTaskUrl: 无 jobId 时返回空串', () => {
  const parsed = CodeArtsCheckApi.parseTaskUrl(
    'https://devcloud.cn-north-4.huaweicloud.com/codechecknew/project/p1/codecheck/task/green/task-1/tasklog'
  );
  assert.deepStrictEqual(parsed, { projectId: 'p1', taskId: 'task-1', jobId: '', region: 'cn-north-4' });
});

test('parseTaskUrl: 无效 URL 返回 null', () => {
  assert.strictEqual(CodeArtsCheckApi.parseTaskUrl(''), null);
  assert.strictEqual(CodeArtsCheckApi.parseTaskUrl('not-a-url'), null);
  assert.strictEqual(CodeArtsCheckApi.parseTaskUrl('https://devcloud.cn-north-4.huaweicloud.com/xxx'), null);
});

// ---------- API 响应 -> 中间模型 ----------

test('buildIssueFromApiItem: 完整字段映射', () => {
  const item = {
    defectLevel: '2',
    defectType: 'Do not use System.out or System.err to log messages',
    criterionName: '记录日志应该使用Facade模式的日志框架',
    ruleId: 'G.LOG.01',
    filePath: 'java/test_java1.java',
    fileName: 'test_java1.java',
    fragment: [{
      lineNum: '6',
      lineContent: '        System.out.println("Start");',
      filePath: 'java/test_java1.java',
      description: 'Do not use System.out or System.err to log messages',
      codeContext: 'public class HelloWorld {'
    }]
  };
  const issue = CodeArtsCheckApi.buildIssueFromApiItem(item);
  assert.strictEqual(issue.ruleId, 'G.LOG.01');
  assert.strictEqual(issue.ruleName, '记录日志应该使用Facade模式的日志框架');
  assert.strictEqual(issue.message, 'Do not use System.out or System.err to log messages');
  assert.strictEqual(issue.severity, '一般');
  assert.strictEqual(issue.file, 'java/test_java1.java');
  assert.strictEqual(issue.line, 6);
  assert.strictEqual(issue.snippet, '        System.out.println("Start");');
});

test('buildIssueFromApiItem: 级别映射 0/1/2/3 -> 致命/严重/一般/提示，未知默认一般', () => {
  const cases = [
    ['0', '致命'],
    ['1', '严重'],
    ['2', '一般'],
    ['3', '提示'],
    ['99', '一般'],
    [undefined, '一般']
  ];
  cases.forEach(([lv, expect]) => {
    const issue = CodeArtsCheckApi.buildIssueFromApiItem({ defectLevel: lv, fragment: [{ lineNum: '1' }] });
    assert.strictEqual(issue.severity, expect, `defectLevel=${lv}`);
  });
});

test('buildIssueFromApiItem: ShowTaskDefectsV2 字段格式映射', () => {
  const item = {
    defect_id: 'defect-1',
    defect_level: '2',
    rule_id: 'G.LOG.01',
    rule_name: '记录日志应该使用Facade模式的日志框架',
    defect_content: 'Do not use System.out or System.err to log messages',
    file_path: 'java/test_java1.java',
    line_number: '6',
    fragment: [{
      line_num: '6',
      line_content: '        System.out.println("Start");'
    }]
  };
  const issue = CodeArtsCheckApi.buildIssueFromApiItem(item);
  assert.strictEqual(issue.ruleId, 'G.LOG.01');
  assert.strictEqual(issue.ruleName, '记录日志应该使用Facade模式的日志框架');
  assert.strictEqual(issue.message, 'Do not use System.out or System.err to log messages');
  assert.strictEqual(issue.severity, '一般');
  assert.strictEqual(issue.file, 'java/test_java1.java');
  assert.strictEqual(issue.line, 6);
  assert.strictEqual(issue.snippet, '        System.out.println("Start");');
});

test('buildIssueFromApiItem: 缺失 fragment 时字段兜底', () => {
  const item = { defectLevel: '1', defectType: 'BadThing', filePath: 'src/a.java' };
  const issue = CodeArtsCheckApi.buildIssueFromApiItem(item);
  assert.strictEqual(issue.ruleId, 'BadThing');
  assert.strictEqual(issue.file, 'src/a.java');
  assert.strictEqual(issue.line, 0);
  assert.strictEqual(issue.snippet, '');
});

test('buildIssueFromApiItem: 空输入返回 null', () => {
  assert.strictEqual(CodeArtsCheckApi.buildIssueFromApiItem(null), null);
  assert.strictEqual(CodeArtsCheckApi.buildIssueFromApiItem(undefined), null);
});

// ---------- fetchIssues 分页与集成 ----------

test('fetchIssues: 有 task_id 时正常分页拉全量', async () => {
  const api = new CodeArtsCheckApi({ ak: 'AK', sk: 'SK', region: 'cn-north-4' });
  let pageCalls = 0;
  api.listIssues = async (taskId, { page }) => {
    assert.strictEqual(taskId, 't1');
    if (page === 1) {
      return {
        total: 3,
        info: [
          { defectLevel: '0', defectType: 'D1', filePath: 'a.java', fragment: [{ lineNum: '10', lineContent: 'x' }] },
          { defectLevel: '2', criterionName: '规则B', filePath: 'b.java', fragment: [{ lineNum: '20' }] }
        ]
      };
    }
    pageCalls += 1;
    return { total: 3, info: [{ defectLevel: '3', defectType: 'D3', filePath: 'c.java', fragment: [{ lineNum: '30' }] }] };
  };

  const parsed = await api.fetchIssues({ projectId: 'p1', taskId: 't1', taskName: 'my-task' });
  assert.strictEqual(parsed.task.taskId, 't1');
  assert.strictEqual(parsed.task.taskName, 'my-task');
  assert.strictEqual(parsed.issues.length, 3);
  assert.strictEqual(parsed.issues[0].severity, '致命');
  assert.strictEqual(parsed.issues[2].severity, '提示');
  assert.strictEqual(pageCalls, 1); // 第二页只请求一次
});

test('fetchIssues: 缺 project_id 抛错', async () => {
  const api = new CodeArtsCheckApi({ ak: 'AK', sk: 'SK', region: 'cn-north-4' });
  await assert.rejects(() => api.fetchIssues({ taskId: 't1' }), /project_id/);
});

test('fetchIssues: 无 task_id 抛错', async () => {
  const api = new CodeArtsCheckApi({ ak: 'AK', sk: 'SK', region: 'cn-north-4' });
  await assert.rejects(() => api.fetchIssues({ projectId: 'p1' }), /缺少 task_id/);
});

test('CodeArtsCheckApi: 带 SecurityToken 时请求头包含 X-Security-Token', async () => {
  const https = require('https');
  const original = https.request;
  let captured;
  const { EventEmitter } = require('events');
  https.request = (options, callback) => {
    captured = options;
    const res = new EventEmitter();
    res.statusCode = 200;
    res.headers = { 'content-type': 'application/json' };
    process.nextTick(() => {
      callback(res);
      res.emit('end');
    });
    return { on: () => {}, write: () => {}, end: () => {}, setTimeout: () => {} };
  };
  try {
    const api = new CodeArtsCheckApi({ ak: 'AK', sk: 'SK', token: 'TOKEN-1', region: 'cn-north-4' });
    await api.request('GET', '/v2/p1/tasks', {});
  } finally {
    https.request = original;
  }
  assert.strictEqual(captured.headers['X-Security-Token'], 'TOKEN-1');
});
