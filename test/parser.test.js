const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');

const CodeCheckReportParser = require('../src/parser/CodeCheckReportParser');

const FIXTURE = path.join(
  __dirname,
  'fixtures',
  'step_summary_80e9d9ec-928d-4965-9f16-feb8547b5a16.md'
);

test('解析样例报告: 提取 13 条问题(一般 5 + 提示 8)', () => {
  const result = CodeCheckReportParser.parseFile(FIXTURE);
  assert.equal(result.issues.length, 13);
  const bySeverity = result.issues.reduce((acc, it) => {
    acc[it.severity] = (acc[it.severity] || 0) + 1;
    return acc;
  }, {});
  assert.equal(bySeverity['一般'], 5);
  assert.equal(bySeverity['提示'], 8);
});

test('解析样例报告: 任务摘要元信息', () => {
  const result = CodeCheckReportParser.parseFile(FIXTURE);
  assert.equal(result.task.name, 'openlibing-cicd-test-20260901163323');
  assert.equal(result.task.branch, 'test-thq-1');
  assert.equal(result.task.gateResult, '不通过');
});

test('解析样例报告: 单条问题字段完整', () => {
  const result = CodeCheckReportParser.parseFile(FIXTURE);
  const first = result.issues[0];
  assert.equal(first.ruleId, 'G.CTL.01');
  assert.equal(
    first.ruleName,
    '不要在控制性条件表达式中执行赋值操作或执行复杂的条件判断'
  );
  assert.equal(first.message, "Do not compare expression with 'true'");
  assert.equal(first.file, 'java/test_java1.java');
  assert.equal(first.line, 28);
  assert.equal(first.severity, '一般');
});

test('解析样例报告: 规则ID与规则名拆分正确', () => {
  const result = CodeCheckReportParser.parseFile(FIXTURE);
  const names = new Set(result.issues.map((it) => it.ruleId));
  assert.ok(names.has('G.LOG.01'));
  assert.ok(names.has('G.FMT.12'));
  const log01 = result.issues.find((it) => it.ruleId === 'G.LOG.01');
  assert.equal(log01.ruleName, '记录日志应该使用Facade模式的日志框架');
});

test('解析样例报告: 从第 3 章回填代码片段(snippet)', () => {
  const result = CodeCheckReportParser.parseFile(FIXTURE);
  const log01Line6 = result.issues.find(
    (it) => it.ruleId === 'G.LOG.01' && it.line === 6
  );
  assert.ok(log01Line6, '应存在 G.LOG.01 line 6 的问题');
  assert.ok(log01Line6.snippet, '该问题应回填代码片段');
  assert.ok(log01Line6.snippet.includes('import java.util.*'));
});

test('容错: 报告缺少 2.5 详细问题列表章节时报错', () => {
  const md = '# 报告\n\n## 2 扫描结果概述\n\n### 2.4 扫描结果详情\n\n无问题\n';
  assert.throws(() => CodeCheckReportParser.parse(md), /2\.5|详细问题列表/);
});

test('容错: 解析到异常行时跳过并记录警告', () => {
  const md = [
    '### 2.5 详细问题列表',
    '',
    '| 严重程度 | 规则名称 | 问题描述 | 代码文件 | 代码行 |',
    '| --- | --- | --- | --- | --- |',
    '| 一般 | G.LOG.01 记录日志 | desc | a.java | 1 |',
    '| 这是坏行缺少列 |',
    '| 提示 | G.FMT.01 格式 | desc2 | b.java | 2 |',
    ''
  ].join('\n');
  const result = CodeCheckReportParser.parse(md);
  assert.equal(result.issues.length, 2);
  assert.ok(result.warnings.length >= 1);
});

test('输入为空文件时返回空问题列表', () => {
  const result = CodeCheckReportParser.parse('');
  assert.equal(result.issues.length, 0);
});
