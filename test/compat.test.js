const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');

const { convertReportFile } = require('../index.js');

const FIXTURE = path.join(
  __dirname,
  'fixtures',
  'step_summary_80e9d9ec-928d-4965-9f16-feb8547b5a16.md'
);

/**
 * 模拟 openlibing-codecheck 的 CodeQlSarifParser 关键读取路径：
 * - SarifParserFactory 按 tool.driver.name 路由（"CodeArtsCheck" 命中）
 * - buildRuleMap 读取 rules[].id
 * - extractRuleName 读取 rule.properties.name
 * - extractRawLevel 优先 rule.defaultConfiguration.level
 * - extractLocationHash 读取 result.partialFingerprints.primaryLocationLineHash
 * - StaticAlarmSeverityEnum.mapFromCodeQL: error->High, warning->Medium, note->Low
 */
function simulateCodeQlParser(sarif) {
  const run = sarif.runs[0];

  // SarifParserFactory / ISarifParser.supportedTool()（后端需支持 CodeArtsCheck 工具名路由）
  assert.equal(run.tool.driver.name, 'CodeArtsCheck', 'tool.driver.name 必须为 CodeArtsCheck');

  // buildRuleMap
  const ruleMap = new Map();
  for (const rule of run.tool.driver.rules) {
    ruleMap.set(rule.id, rule);
  }

  // parseIssues
  const issues = [];
  for (const result of run.results) {
    if (!result.ruleId) {
      throw new Error('result 缺少 ruleId');
    }
    const rule = ruleMap.get(result.ruleId);
    if (!rule) {
      throw new Error(`rules 中缺少 rule: ${result.ruleId}`);
    }
    // extractLocationHash：取 partialFingerprints.primaryLocationLineHash，缺失为空串
    const locationHashRaw =
      (result.partialFingerprints && result.partialFingerprints.primaryLocationLineHash) || '';
    assert.ok(locationHashRaw, 'partialFingerprints.primaryLocationLineHash 不能为空');
    const level = rule.defaultConfiguration.level || result.level || 'warning';
    const mapped = level === 'error' ? 'High' : level === 'warning' ? 'Medium' : 'Low';
    issues.push({
      ruleId: result.ruleId,
      ruleName: rule.properties.name,
      message: result.message.text,
      severity: mapped,
      filePath: result.locations[0].physicalLocation.artifactLocation.uri,
      startLine: result.locations[0].physicalLocation.region.startLine,
      locationHashRaw
    });
  }
  return issues;
}

/** 模拟 SarifParseServiceImpl.buildFingerprintKey：MD5(tool|ruleId|filePath|locationHashRaw) */
function buildFingerprintKey(tool, issue) {
  const crypto = require('crypto');
  return crypto
    .createHash('md5')
    .update([tool, issue.ruleId, issue.filePath, issue.locationHashRaw].join('|'), 'utf-8')
    .digest('hex');
}

test('转换样例报告: 生成 SARIF 且被 CodeQlSarifParser 逻辑消费', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-'));
  const { outPath, issueCount } = convertReportFile(FIXTURE, outDir);
  assert.equal(issueCount, 13);

  const sarif = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  assert.equal(sarif.version, '2.1.0');

  const issues = simulateCodeQlParser(sarif);
  assert.equal(issues.length, 13);
});

test('兼容级别分布: 一般(warning)->Medium x5, 提示(note)->Low x8', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-sev-'));
  const { outPath } = convertReportFile(FIXTURE, outDir);
  const sarif = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  const issues = simulateCodeQlParser(sarif);

  const bySeverity = issues.reduce((acc, it) => {
    acc[it.severity] = (acc[it.severity] || 0) + 1;
    return acc;
  }, {});
  assert.deepEqual(bySeverity, { Medium: 5, Low: 8 });
});

test('兼容字段: 文件/行号/消息/规则名完整', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-fields-'));
  const { outPath } = convertReportFile(FIXTURE, outDir);
  const sarif = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  const issues = simulateCodeQlParser(sarif);

  for (const issue of issues) {
    assert.ok(issue.ruleId, 'ruleId 非空');
    assert.ok(issue.ruleName, 'ruleName 非空');
    assert.ok(issue.message, 'message 非空');
    assert.ok(issue.filePath, 'filePath 非空');
    assert.ok(Number.isInteger(issue.startLine), 'startLine 为整数');
  }

  const logIssues = issues.filter((it) => it.ruleId === 'G.LOG.01');
  assert.equal(logIssues.length, 3);
  assert.equal(logIssues[0].filePath, 'java/test_java1.java');
  assert.deepEqual(
    logIssues.map((it) => it.startLine),
    [6, 18, 29]
  );
});

test('rules 去重后与 result 引用一致', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-rules-'));
  const { outPath } = convertReportFile(FIXTURE, outDir);
  const sarif = JSON.parse(fs.readFileSync(outPath, 'utf-8'));

  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.equal(new Set(ruleIds).size, ruleIds.length, 'rule id 不应重复');
  const resultRuleIds = new Set(sarif.runs[0].results.map((r) => r.ruleId));
  for (const id of resultRuleIds) {
    assert.ok(ruleIds.includes(id), `result 引用的 rule ${id} 必须存在`);
  }
});

test('指纹键唯一性: MD5(tool|ruleId|filePath|locationHashRaw) 无重复', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-fp-'));
  const { outPath } = convertReportFile(FIXTURE, outDir);
  const sarif = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  const issues = simulateCodeQlParser(sarif);
  const keys = issues.map((issue) => buildFingerprintKey('CodeArtsCheck', issue));
  assert.equal(new Set(keys).size, keys.length, 'fingerprintKey 不应重复');
});

test('转换输出: 不同目录同名报告输出文件名不冲突', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-name-'));
  const moduleA = path.join(outDir, 'module-a');
  const moduleB = path.join(outDir, 'module-b');
  fs.mkdirSync(moduleA, { recursive: true });
  fs.mkdirSync(moduleB, { recursive: true });
  const reportA = path.join(moduleA, 'report.md');
  const reportB = path.join(moduleB, 'report.md');
  fs.copyFileSync(FIXTURE, reportA);
  fs.copyFileSync(FIXTURE, reportB);

  const { outPath: outA } = convertReportFile(reportA, outDir);
  const { outPath: outB } = convertReportFile(reportB, outDir);
  assert.notEqual(path.basename(outA), path.basename(outB), '同名报告输出文件名应含父目录区分');
  assert.ok(fs.existsSync(outA) && fs.existsSync(outB), '两份转换结果都应落盘，互不覆盖');
});

test('真实 CodeArts Check SARIF: 规范化后被 CodeQlSarifParser 逻辑消费', () => {
  const fixture = path.join(__dirname, 'fixtures', 'codearts-check.sarif');
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compat-ca-'));
  const { outPath, issueCount } = convertReportFile(fixture, outDir);
  assert.equal(issueCount, 13);

  const sarif = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  assert.equal(sarif.version, '2.1.0');
  const issues = simulateCodeQlParser(sarif);
  assert.equal(issues.length, 13);

  const keys = issues.map((issue) => buildFingerprintKey('CodeArtsCheck', issue));
  assert.equal(new Set(keys).size, keys.length, 'fingerprintKey 不应重复');
});
