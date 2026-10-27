'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { resolveSourceFile, enrichRegionSnippet } = require('../index.js');

// ============================================================
// 回归缺口 1：符号链接绕过 sourceRoots 边界（#18/#16 补齐）
// resolveSourceFile 只做词法前缀校验时，界内路径的 symlink 指向界外也能读到。
// 修复后必须经 realpath 终裁：越界 symlink 返回 null。
// Windows 无管理员权限无法创建 symlink，用 try/skip 兼容本机跑测试。
// ============================================================
function canCreateSymlink() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-probe-'));
  const target = path.join(dir, 't.txt');
  const link = path.join(dir, 'l.txt');
  fs.writeFileSync(target, 'x');
  try {
    fs.symlinkSync(target, link);
    return true;
  } catch (e) {
    return false;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('symlink: 指向 sourceRoots 边界外的符号链接被拒绝（realpath 终裁）', { skip: !canCreateSymlink() }, () => {
  const outer = fs.mkdtempSync(path.join(os.tmpdir(), 'outer-secret-'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-root-'));
  try {
    fs.writeFileSync(path.join(outer, 'secret.c'), 'char* password = "hunter2";\n');
    // 界内路径 link.c -> 界外 secret.c：词法前缀校验通过，但 realpath 在 root 外
    fs.symlinkSync(path.join(outer, 'secret.c'), path.join(root, 'link.c'));
    assert.equal(resolveSourceFile('link.c', [root]), null,
      '指向边界外的 symlink 应被 realpath 终裁拒绝');
    assert.equal(resolveSourceFile(path.join(root, 'link.c'), [root]), null,
      '绝对路径形式的越界 symlink 同样被拒绝');
  } finally {
    fs.rmSync(outer, { recursive: true, force: true });
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('symlink: 指向 sourceRoots 边界内的符号链接仍可解析（正常兼容不受影响）', { skip: !canCreateSymlink() }, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-root-'));
  try {
    const real = path.join(root, 'real.c');
    fs.writeFileSync(real, 'int x = 1;\n');
    fs.symlinkSync(real, path.join(root, 'alias.c'));
    const resolved = resolveSourceFile('alias.c', [root]);
    assert.ok(resolved, '界内 symlink 应正常解析');
    assert.equal(fs.readFileSync(resolved, 'utf-8'), 'int x = 1;\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('symlink: 无 symlink 的正常文件路径解析不受影响（realpath 归一化）', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-root-'));
  try {
    const file = path.join(root, 'plain.c');
    fs.writeFileSync(file, 'int y = 2;\n');
    assert.equal(resolveSourceFile('plain.c', [root]), fs.realpathSync(file));
    assert.equal(resolveSourceFile(file, [root]), fs.realpathSync(file));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================
// 回归缺口 2：result.message.text 未掩码（#11/#12 补齐）
// bandit 等工具把明文口令写进消息文本（如 B105），随 SARIF 上传留存。
// 修复后：凭证类规则的 message.text 中字符串字面量掩码。
// ============================================================
function setupCredentialCase() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'enrich-msg-'));
  const file = path.join(root, 'a.py');
  fs.writeFileSync(file, 'pwd = "hunter2"\nflag = 1\nother = "ok"\n', 'utf-8');
  const sarif = {
    version: '2.1.0',
    runs: [{
      tool: { driver: { rules: [{ id: 'B105', name: 'hardcoded_password_string',
        shortDescription: { text: 'hardcoded password string comparison' } }] } },
      results: [{
        ruleId: 'B105',
        ruleIndex: 0,
        message: { text: 'comparison to "hunter2" seems insecure' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'a.py' }, region: { startLine: 1 } } }]
      }]
    }]
  };
  return { sarif, root };
}

test('message: 凭证类规则的 result.message.text 字符串字面量被掩码', () => {
  const { sarif, root } = setupCredentialCase();
  try {
    enrichRegionSnippet(sarif, [root]);
    const msg = sarif.runs[0].results[0].message.text;
    assert.ok(!msg.includes('hunter2'), `message 不应保留明文口令：${msg}`);
    assert.ok(msg.includes('***'), `message 中的字面量应被掩码：${msg}`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('message: 非凭证类规则的 result.message.text 保持原样', () => {
  const { sarif, root } = setupCredentialCase();
  sarif.runs[0].results[0].ruleId = 'E999';
  sarif.runs[0].results[0].ruleIndex = 0;
  sarif.runs[0].tool.driver.rules[0] = { id: 'E999', name: 'some-other-rule',
    shortDescription: { text: 'unrelated style issue' } };
  try {
    enrichRegionSnippet(sarif, [root]);
    const msg = sarif.runs[0].results[0].message.text;
    assert.equal(msg, 'comparison to "hunter2" seems insecure',
      '非凭证类规则的 message 不应被掩码');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('message: 无 message.text 的 result 正常处理（不抛错）', () => {
  const { sarif, root } = setupCredentialCase();
  delete sarif.runs[0].results[0].message;
  try {
    const n = enrichRegionSnippet(sarif, [root]);
    assert.equal(n, 1, 'snippet 补齐应正常计数');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
