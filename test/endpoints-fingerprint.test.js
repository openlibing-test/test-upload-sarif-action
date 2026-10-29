const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const endpoints = require('../src/config/endpoints');
const { buildPrimaryLocationLineHash } = require('../src/util/fingerprint');
const { signRequest, parseTaskUrl } = require('../src/api/CodeArtsCheckApi');

// ============================================================
// endpoints：#10 方案 B 集中配置，默认值与原硬编码逐字一致（等价变换）
// ============================================================
test('endpoints: 必备键齐全且值为 https URL（不含尾斜杠）', () => {
  const requiredKeys = [
    'OIDC_PROD_BASE',
    'OIDC_BETA_BASE',
    'OBS_BUCKET',
    'OBS_READ_ENDPOINT',
    'CODEARTS_HOST_PREFIX',
    'CODEARTS_API_DOMAIN'
  ];
  for (const key of requiredKeys) {
    assert.ok(key in endpoints, `缺少配置键 ${key}`);
  }
});

test('endpoints: OIDC/OBS 地址均为 https 且无尾斜杠', () => {
  for (const key of ['OIDC_PROD_BASE', 'OIDC_BETA_BASE', 'OBS_READ_ENDPOINT']) {
    assert.ok(endpoints[key].startsWith('https://'), `${key} 应为 https`);
    assert.ok(!endpoints[key].endsWith('/'), `${key} 不应有尾斜杠`);
  }
});

test('endpoints: OBS_BUCKET 为非空桶名（不含协议与路径）', () => {
  assert.ok(endpoints.OBS_BUCKET.length > 0);
  assert.ok(!endpoints.OBS_BUCKET.includes('/'));
  assert.ok(!endpoints.OBS_BUCKET.includes(':'));
});

// ============================================================
// fingerprint：primaryLocationLineHash（后端入库依赖，必须稳定）
// ============================================================
test('fingerprint: 有 snippet 时对行内容取 SHA-256 前 32 位 hex', () => {
  const snippet = 'const password = "hunter2";';
  const expected = crypto
    .createHash('sha256')
    .update(snippet, 'utf-8')
    .digest('hex')
    .slice(0, 32);
  const actual = buildPrimaryLocationLineHash('src/a.js', 10, snippet);
  assert.equal(actual, expected);
  assert.match(actual, /^[0-9a-f]{32}$/);
});

test('fingerprint: 无 snippet 时对 uri|startLine 取 hash', () => {
  const expected = crypto
    .createHash('sha256')
    .update('src/a.js|42', 'utf-8')
    .digest('hex')
    .slice(0, 32);
  assert.equal(buildPrimaryLocationLineHash('src/a.js', 42), expected);
});

test('fingerprint: 行号偏移不影响有 snippet 时的指纹（稳定优先）', () => {
  const withLine10 = buildPrimaryLocationLineHash('src/a.js', 10, 'int x = 1;');
  const withLine11 = buildPrimaryLocationLineHash('src/a.js', 11, 'int x = 1;');
  assert.equal(withLine10, withLine11);
});

test('fingerprint: 不同 uri 或行号产生不同指纹（无 snippet 场景）', () => {
  const a = buildPrimaryLocationLineHash('src/a.js', 1);
  const b = buildPrimaryLocationLineHash('src/b.js', 1);
  const c = buildPrimaryLocationLineHash('src/a.js', 2);
  assert.notEqual(a, b);
  assert.notEqual(a, c);
});

test('fingerprint: uri/startLine 缺省时仍输出 32 位 hex（不抛错）', () => {
  const h = buildPrimaryLocationLineHash();
  assert.match(h, /^[0-9a-f]{32}$/);
});

// ============================================================
// signRequest：华为云 SDK-HMAC-SHA256（APIG 规范）
// ============================================================
test('signRequest: 返回 x-sdk-date 与 Authorization 头', () => {
  const signed = signRequest({
    method: 'GET',
    uri: '/v2/0abcd1234/tasks',
    query: { page: '1' },
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com' },
    payload: '',
    ak: 'TEST_AK',
    sk: 'TEST_SK'
  });
  assert.match(signed['x-sdk-date'], /^\d{8}T\d{6}Z$/);
  assert.match(
    signed.Authorization,
    /^SDK-HMAC-SHA256 Access=TEST_AK, SignedHeaders=host;x-sdk-date, Signature=[0-9a-f]{64}$/
  );
});

test('signRequest: 签名可复现（相同输入与日期）— 独立计算校验', () => {
  const opts = {
    method: 'POST',
    uri: '/v2/0abcd1234/task/12345/result',
    query: {},
    headers: { host: 'codecheck-ext.cn-north-4.myhuaweicloud.com' },
    payload: '{"k":"v"}',
    ak: 'AK',
    sk: 'SK'
  };
  const signed = signRequest(opts);
  // 按相同算法独立重算，验证 Authorization 与 x-sdk-date 绑定正确
  const xSdkDate = signed['x-sdk-date'];
  const rfc3986 = (s) =>
    encodeURIComponent(s).replace(
      /[!'()*]/g,
      (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
    );
  const sha256Hex = (c) =>
    crypto.createHash('sha256').update(c, 'utf8').digest('hex');
  const canonical = [
    'POST',
    '/v2/0abcd1234/task/12345/result/',
    '',
    `host:codecheck-ext.cn-north-4.myhuaweicloud.com\nx-sdk-date:${xSdkDate}\n`,
    'host;x-sdk-date',
    sha256Hex('{"k":"v"}')
  ].join('\n');
  const stringToSign = ['SDK-HMAC-SHA256', xSdkDate, sha256Hex(canonical)].join('\n');
  const expectedSig = crypto
    .createHmac('sha256', 'SK')
    .update(stringToSign, 'utf8')
    .digest('hex');
  assert.ok(
    signed.Authorization.endsWith(`Signature=${expectedSig}`),
    `签名应与独立重算一致：${signed.Authorization}`
  );
});

// ============================================================
// parseTaskUrl：codeCheck_task_url 参数解析
// ============================================================
test('parseTaskUrl: 解析 projectId/taskId/jobId/region', () => {
  const url = 'https://devcloud.cn-north-4.huaweicloud.com/codechecknew/project/0abcd1234/codecheck/task/normal/67890/tasklog?jobId=111222';
  const parsed = parseTaskUrl(url);
  assert.equal(parsed.projectId, '0abcd1234');
  assert.equal(parsed.taskId, '67890');
  assert.equal(parsed.jobId, '111222');
  assert.equal(parsed.region, 'cn-north-4');
});

test('parseTaskUrl: 非法输入返回 null（空串/非字符串/非 URL/缺 project 与 task 段）', () => {
  assert.equal(parseTaskUrl(''), null);
  assert.equal(parseTaskUrl(null), null);
  assert.equal(parseTaskUrl(undefined), null);
  assert.equal(parseTaskUrl('not a url'), null);
  assert.equal(parseTaskUrl('https://example.com/no/segments'), null);
});

test('parseTaskUrl: 仅含 project 段也有效，jobId 可缺省', () => {
  const parsed = parseTaskUrl(
    'https://devcloud.cn-southwest-2.huaweicloud.com/codechecknew/project/abc123/overview'
  );
  assert.equal(parsed.projectId, 'abc123');
  assert.equal(parsed.taskId, '');
  assert.equal(parsed.jobId, '');
  assert.equal(parsed.region, 'cn-southwest-2');
});
