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
  if (extra.problemSnippet) region.snippet = { text: 'l5' };
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

test('补充: region.snippet 对齐为问题行本身，contextRegion 为上下各 2 行窗口', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 5);
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.snippet.text, 'l5');
    assert.equal(loc.contextRegion.startLine, 3);
    assert.equal(loc.contextRegion.endLine, 7);
    assert.equal(loc.contextRegion.snippet.text, 'l3\nl4\nl5\nl6\nl7');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('补充: 首行问题窗口从第 1 行开始，region.snippet 为首行', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 1);
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.snippet.text, 'l1');
    assert.equal(loc.contextRegion.startLine, 1);
    assert.equal(loc.contextRegion.snippet.text, 'l1\nl2\nl3');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('补充: 末尾行问题窗口截至文件末行，region.snippet 为末行', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 10);
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.snippet.text, 'l10');
    assert.equal(loc.contextRegion.startLine, 8);
    assert.equal(loc.contextRegion.snippet.text, 'l8\nl9\nl10');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('补充: 多行范围（endLine）region.snippet 为问题范围，contextRegion 上下各加 2 行', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 4, { endLine: 6 });
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.snippet.text, 'l4\nl5\nl6');
    assert.equal(loc.contextRegion.startLine, 2);
    assert.equal(loc.contextRegion.endLine, 8);
    assert.equal(loc.contextRegion.snippet.text, 'l2\nl3\nl4\nl5\nl6\nl7\nl8');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('补充: 已有 snippet 与问题行一致时不重复覆盖，只补 contextRegion', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 5, { problemSnippet: true });
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.snippet.text, 'l5');
    assert.equal(loc.contextRegion.snippet.text, 'l3\nl4\nl5\nl6\nl7');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('补充: 已有 snippet 与问题行不一致时对齐为文件实际内容（CodeArts 场景）', () => {
  const lines = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10'];
  const { sarif, root } = setup(lines, 5, { hasSnippet: true });
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.snippet.text, 'l5');
    assert.equal(loc.contextRegion.snippet.text, 'l3\nl4\nl5\nl6\nl7');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('补充: 源码文件不存在时静默跳过', () => {
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
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.equal(loc.region.snippet, undefined);
    assert.equal(loc.contextRegion, undefined);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
