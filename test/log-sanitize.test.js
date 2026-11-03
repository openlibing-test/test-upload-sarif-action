'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { sanitizeLogValue, cleanupConvertFiles } = require('../index.js');

// ============================================================
// #31 日志注入：外部可控内容拼进日志行时可携带 \r\n 伪造日志行。
// 整改为在 console 出口统一清洗控制字符，正常单行内容保持不变。
// ============================================================
test('sanitizeLogValue: 剔除换行与不可见控制字符', () => {
  assert.equal(sanitizeLogValue('a\r\nb'), 'ab', 'CR/LF 必须被剔除');
  assert.equal(sanitizeLogValue('a\n[INFO] forged'), 'a[INFO] forged', '换行不得产生伪造日志行');
  assert.equal(sanitizeLogValue('a\u0000b\u0007c\u001bd\u007fe'), 'abcde', 'NUL/BEL/ESC/DEL 等控制字符必须被剔除');
});

test('sanitizeLogValue: 正常单行内容与多字节字符不变', () => {
  assert.equal(sanitizeLogValue('/tmp/reports/summary.md'), '/tmp/reports/summary.md');
  assert.equal(sanitizeLogValue('预热完成 100%'), '预热完成 100%');
  assert.equal(sanitizeLogValue(''), '');
});

test('sanitizeLogValue: 非字符串入参按字符串处理', () => {
  assert.equal(sanitizeLogValue(123), '123');
  assert.equal(sanitizeLogValue(null), 'null');
});

test('console.log: 注入内容输出被压成单行', () => {
  const chunks = [];
  const origWrite = process.stdout.write;
  process.stdout.write = (chunk) => {
    chunks.push(String(chunk));
    return true;
  };
  try {
    console.log('[INFO] 输入为目录: /tmp/a\n[INFO] forged line');
  } finally {
    process.stdout.write = origWrite;
  }
  const out = chunks.join('');
  assert.ok(!out.includes('\n\n'), `不应出现伪造换行：${JSON.stringify(out)}`);
  assert.equal(out.split('\n').filter(Boolean).length, 1, `应只输出一行：${JSON.stringify(out)}`);
  assert.ok(out.includes('[INFO] 输入为目录: /tmp/a[INFO] forged line'));
});

// ============================================================
// #27 临时产物治理：只清理本次运行创建的文件，目录非空时不强制删除。
// ============================================================
test('cleanupConvertFiles: 删除传入文件并移除空目录', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'convert-out-'));
  const a = path.join(dir, 'a.sarif');
  const b = path.join(dir, 'b.sarif');
  fs.writeFileSync(a, '{}');
  fs.writeFileSync(b, '{}');
  const files = new Set([a, b]);
  cleanupConvertFiles(files, dir);
  assert.equal(fs.existsSync(a), false);
  assert.equal(fs.existsSync(b), false);
  assert.equal(fs.existsSync(dir), false, '空目录应被移除');
  assert.equal(files.size, 0, '集合应被清空');
});

test('cleanupConvertFiles: 目录非空时保留他人产物，不递归删除', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'convert-out-'));
  const mine = path.join(dir, 'mine.sarif');
  const others = path.join(dir, 'others.sarif');
  fs.writeFileSync(mine, '{}');
  fs.writeFileSync(others, '{}');
  cleanupConvertFiles(new Set([mine]), dir);
  assert.equal(fs.existsSync(mine), false);
  assert.equal(fs.existsSync(others), true, '非本次创建的文件必须保留');
  assert.equal(fs.existsSync(dir), true, '非空目录必须保留');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('cleanupConvertFiles: 单个文件删除失败不影响其余清理', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'convert-out-'));
  const nestedDir = path.join(dir, 'nested');
  fs.mkdirSync(nestedDir);
  const file = path.join(dir, 'ok.sarif');
  fs.writeFileSync(file, '{}');
  // 传入目录（非 recursive 删除会抛错）验证单个失败被吞掉，后续清理继续
  assert.doesNotThrow(() => cleanupConvertFiles(new Set([nestedDir, file]), dir));
  assert.equal(fs.existsSync(file), false, '失败项之后的文件仍应被清理');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('cleanupConvertFiles: 文件已不存在或目录已删除时不抛错', () => {
  const dir = path.join(os.tmpdir(), `not-exists-${Date.now()}`);
  assert.doesNotThrow(() => cleanupConvertFiles(new Set([path.join(dir, 'x.sarif')]), dir));
});
