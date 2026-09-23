const { test } = require('node:test');
const assert = require('node:assert/strict');

const SarifGenerator = require('../src/sarif/SarifGenerator');

function sampleParsed() {
  return {
    task: { name: 'task-1', branch: 'b1', gateResult: '不通过' },
    issues: [
      {
        severity: '致命',
        ruleId: 'G.SEC.01',
        ruleName: '安全漏洞规则',
        message: 'critical issue',
        file: 'a.java',
        line: 1,
        snippet: 'int x = 1;'
      },
      {
        severity: '严重',
        ruleId: 'G.SEC.02',
        ruleName: '严重问题规则',
        message: 'high issue',
        file: 'a.java',
        line: 2,
        snippet: ''
      },
      {
        severity: '一般',
        ruleId: 'G.LOG.01',
        ruleName: '日志规则',
        message: 'medium issue',
        file: 'b.java',
        line: 3,
        snippet: ''
      },
      {
        severity: '提示',
        ruleId: 'G.FMT.01',
        ruleName: '格式规则',
        message: 'low issue',
        file: 'b.java',
        line: 4,
        snippet: 'import x;'
      }
    ],
    warnings: []
  };
}

test('生成 SARIF 2.1.0 顶层结构', () => {
  const sarif = SarifGenerator.generate(sampleParsed());
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.ok(Array.isArray(sarif.runs));
  assert.equal(sarif.runs.length, 1);
});

test('tool.driver.name 写实际工具名 CodeArtsCheck（无空格）', () => {
  const sarif = SarifGenerator.generate(sampleParsed());
  assert.equal(sarif.runs[0].tool.driver.name, 'CodeArtsCheck');
  assert.ok(Array.isArray(sarif.runs[0].tool.driver.rules));
});

test('级别映射: 致命/严重->error, 一般->warning, 提示->note', () => {
  const sarif = SarifGenerator.generate(sampleParsed());
  const results = sarif.runs[0].results;
  const levels = results.map((r) => r.level);
  assert.deepEqual(levels, ['error', 'error', 'warning', 'note']);
});

test('规则按 ruleId 去重', () => {
  const parsed = sampleParsed();
  parsed.issues.push({
    severity: '提示',
    ruleId: 'G.LOG.01',
    ruleName: '日志规则',
    message: 'another log issue',
    file: 'b.java',
    line: 9,
    snippet: ''
  });
  const sarif = SarifGenerator.generate(parsed);
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.equal(ruleIds.filter((id) => id === 'G.LOG.01').length, 1);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 4);
  assert.equal(sarif.runs[0].results.length, 5);
});

test('result 携带规则信息与位置信息', () => {
  const sarif = SarifGenerator.generate(sampleParsed());
  const first = sarif.runs[0].results[0];
  assert.equal(first.ruleId, 'G.SEC.01');
  assert.equal(first.message.text, 'critical issue');
  const physical = first.locations[0].physicalLocation;
  assert.equal(physical.artifactLocation.uri, 'a.java');
  assert.equal(physical.region.startLine, 1);
  assert.equal(physical.region.snippet.text, 'int x = 1;');
});

test('rule 定义含 properties.name 与 defaultConfiguration.level', () => {
  const sarif = SarifGenerator.generate(sampleParsed());
  const logRule = sarif.runs[0].tool.driver.rules.find((r) => r.id === 'G.LOG.01');
  assert.equal(logRule.properties.name, '日志规则');
  assert.equal(logRule.defaultConfiguration.level, 'warning');
});

test('无问题时不输出 rules/results 字段', () => {
  const sarif = SarifGenerator.generate({
    task: { name: '', branch: '', gateResult: '' },
    issues: [],
    warnings: []
  });
  const run = sarif.runs[0];
  assert.ok(run.results === undefined || run.results.length === 0);
  assert.ok(run.tool.driver.rules === undefined || run.tool.driver.rules.length === 0);
});
