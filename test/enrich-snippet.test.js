'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { enrichRegionSnippet } = require('../index.js');

/** 构造 10 行源码 + 单 result SARIF，uri 相对 sourceRoot */
function setup(fileContentLines, startLine, extra = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'enrich-snippet-'));
  const file = path.join(root, 'a.java');
  fs.writeFileSync(file, fileContentLines.join('\n'), 'utf-8');
  const region = { startLine };
  if (extra.endLine) region.endLine = extra.endLine;
  if (extra.hasSnippet) region.snippet = { text: 'existing' };
  const sarif = {
    version: '2.1.0',
    runs: [{
      results: [{
        ruleId: 'R1',
        locations: [{ physicalLocation: { artifactLocation: { uri: 'a.java' }, region } }]
      }]
    }]
  };
  return { sarif, root };
}

test('snippet 补充: 问题行上下各 2 行（共 5 行窗口），问题行居中', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 5);
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet.text, 'l3\nl4\nl5\nl6\nl7');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('snippet 补充: 首行问题裁剪上面（窗口从第 1 行开始）', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 1);
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet.text, 'l1\nl2\nl3');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('snippet 补充: 末尾行问题裁剪下面（窗口截至文件末行）', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 10);
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet.text, 'l8\nl9\nl10');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('snippet 补充: 多行范围（endLine）保留范围并上下各加 2 行', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 4, { endLine: 6 });
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet.text, 'l2\nl3\nl4\nl5\nl6\nl7\nl8');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('snippet 补充: 已有 snippet 的 result 跳过（不覆盖）', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 5, { hasSnippet: true });
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 0);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet.text, 'existing');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('snippet 补充: 源码文件不存在时静默跳过', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'enrich-snippet-'));
  try {
    const sarif = {
      version: '2.1.0',
      runs: [{
        results: [{
          ruleId: 'R1',
          locations: [{ physicalLocation: { artifactLocation: { uri: 'missing.java' }, region: { startLine: 3 } } }]
        }]
      }]
    };
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 0);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet, undefined);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
