const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { resolveReportFiles } = require('../index.js');

test('目录模式: 扫描目录下所有 .md/.markdown', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-dir-'));
  fs.writeFileSync(path.join(dir, 'a.md'), '### 2.5 详细问题列表\n');
  fs.writeFileSync(path.join(dir, 'b.txt'), 'x');
  const r = resolveReportFiles(dir, os.tmpdir());
  assert.equal(r.kind, 'dir');
  assert.equal(r.files.length, 1);
  assert.ok(r.files[0].endsWith('a.md'));
});

test('通配符: 匹配 step_summary_*.md（UUID 每次不同）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-pat-'));
  fs.writeFileSync(
    path.join(dir, 'step_summary_80e9d9ec-928d-4965-9f16-feb8547b5a16.md'),
    '### 2.5 详细问题列表\n'
  );
  fs.writeFileSync(path.join(dir, 'step_summary_another-uuid.md'), 'x');
  fs.writeFileSync(path.join(dir, 'other.md'), 'y');
  const r = resolveReportFiles(path.join(dir, 'step_summary_*.md'), os.tmpdir());
  assert.equal(r.kind, 'glob');
  assert.equal(r.files.length, 2);
  assert.ok(r.files.every((f) => f.endsWith('.md')));
});

test('通配符: ? 匹配单个字符', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-q-'));
  fs.writeFileSync(path.join(dir, 'step_summary_x.md'), 'x');
  fs.writeFileSync(path.join(dir, 'step_summary_xx.md'), 'y');
  const r = resolveReportFiles(path.join(dir, 'step_summary_?.md'), os.tmpdir());
  assert.equal(r.kind, 'glob');
  assert.equal(r.files.length, 1);
});

test('直接文件路径: 返回该文件', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-file-'));
  const f = path.join(dir, 'report.md');
  fs.writeFileSync(f, 'x');
  const r = resolveReportFiles(f, os.tmpdir());
  assert.equal(r.kind, 'file');
  assert.equal(r.files.length, 1);
  assert.equal(r.files[0], f);
});

test('通配符: .sarif 为合法输入可匹配，.txt 不匹配', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-ext-'));
  fs.writeFileSync(path.join(dir, 'step_summary_a.sarif'), '{}');
  fs.writeFileSync(path.join(dir, 'step_summary_b.txt'), 'x');
  const r = resolveReportFiles(path.join(dir, 'step_summary_*'), os.tmpdir());
  assert.equal(r.kind, 'glob');
  assert.equal(r.files.length, 1);
  assert.ok(r.files[0].endsWith('.sarif'));
});

test('无任何匹配时返回 null', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glob-none-'));
  const r = resolveReportFiles(path.join(dir, 'nomatch_*.md'), os.tmpdir());
  assert.equal(r, null);
});
