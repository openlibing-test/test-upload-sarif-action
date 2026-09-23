const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeSlashes,
  stripFileScheme,
  isAbsoluteLike,
  isUnderRepoRoot,
  toRepoRelative,
  normalizeSarifUris
} = require('../src/sarif/SarifUriNormalizer');
const { buildPrimaryLocationLineHash } = require('../src/util/fingerprint');

/** 构造单 result SARIF：uri + 可选 snippet，指纹按原 uri 预置 */
function makeSarif(uri, snippetText) {
  const region = { startLine: 3 };
  if (snippetText) region.snippet = { text: snippetText };
  return {
    runs: [{
      tool: { driver: { name: 'x' } },
      results: [{
        ruleId: 'R1',
        locations: [{ physicalLocation: { artifactLocation: { uri }, region } }],
        partialFingerprints: { primaryLocationLineHash: buildPrimaryLocationLineHash(uri, 3, snippetText) }
      }]
    }]
  };
}

test('归一化: POSIX 绝对路径剥离仓库根前缀', () => {
  const root = '/home/runner/work/repo/repo';
  const uri = '/home/runner/work/repo/repo/src/a.java';
  const sarif = makeSarif(uri);
  const changed = normalizeSarifUris(sarif, root);
  assert.equal(changed, 1);
  const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uri, 'src/a.java');
});

test('归一化: file:// 绝对路径解码并剥离仓库根前缀', () => {
  const root = '/home/runner/work/repo/repo';
  const uri = 'file:///home/runner/work/repo/repo/src/a.java';
  const sarif = makeSarif(uri);
  const changed = normalizeSarifUris(sarif, root);
  assert.equal(changed, 1);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/a.java');
});

test('归一化: Windows 盘符路径剥离仓库根前缀（任意平台可运行）', () => {
  const root = 'D:\\workspace\\repo';
  const uri = 'D:\\workspace\\repo\\src\\a.java';
  const sarif = makeSarif(uri);
  const changed = normalizeSarifUris(sarif, root);
  assert.equal(changed, 1);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/a.java');
});

test('归一化: 相对路径保持不变', () => {
  const sarif = makeSarif('src/a.java');
  const changed = normalizeSarifUris(sarif, '/repo');
  assert.equal(changed, 0);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/a.java');
});

test('归一化: ./ 前缀剥离', () => {
  const sarif = makeSarif('./src/a.java');
  const changed = normalizeSarifUris(sarif, '/repo');
  assert.equal(changed, 1);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/a.java');
});

test('归一化: 仓库外的绝对路径保持不变', () => {
  const sarif = makeSarif('/opt/other/a.java');
  const changed = normalizeSarifUris(sarif, '/home/runner/work/repo/repo');
  assert.equal(changed, 0);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, '/opt/other/a.java');
});

test('归一化: 无 snippet 时指纹随 uri 重算（消除机器路径影响）', () => {
  const root = '/home/runner/work/repo/repo';
  const sarif = makeSarif('/home/runner/work/repo/repo/src/a.java');
  normalizeSarifUris(sarif, root);
  const result = sarif.runs[0].results[0];
  assert.equal(
    result.partialFingerprints.primaryLocationLineHash,
    buildPrimaryLocationLineHash('src/a.java', 3, undefined)
  );
});

test('归一化: 有 snippet 时指纹重算结果不变（hash 与 uri 无关）', () => {
  const root = '/home/runner/work/repo/repo';
  const sarif = makeSarif('/home/runner/work/repo/repo/src/a.java', 'int x;');
  normalizeSarifUris(sarif, root);
  const result = sarif.runs[0].results[0];
  assert.equal(
    result.partialFingerprints.primaryLocationLineHash,
    buildPrimaryLocationLineHash('/home/runner/work/repo/repo/src/a.java', 3, 'int x;')
  );
});

test('归一化: 幂等（二次归一化无变更）', () => {
  const root = '/home/runner/work/repo/repo';
  const sarif = makeSarif('/home/runner/work/repo/repo/src/a.java');
  assert.equal(normalizeSarifUris(sarif, root), 1);
  assert.equal(normalizeSarifUris(sarif, root), 0);
});

test('辅助: stripFileScheme 处理 file:///C:/ 盘符', () => {
  assert.equal(stripFileScheme('file:///C:/repo/src/a.java'), 'C:/repo/src/a.java');
  assert.equal(stripFileScheme('file:///home/r/a.java'), '/home/r/a.java');
  assert.equal(stripFileScheme('src/a.java'), 'src/a.java');
});

test('辅助: isUnderRepoRoot 忽略大小写与分隔符', () => {
  assert.equal(isUnderRepoRoot('/Repo/src/a.java', '/repo'), true);
  assert.equal(isUnderRepoRoot('D:\\REPO\\src\\a.java', 'd:/repo'), true);
  assert.equal(isUnderRepoRoot('/etc/passwd', '/repo'), false);
});

test('辅助: toRepoRelative 相对路径保留、绝对路径剥离', () => {
  assert.equal(toRepoRelative('src/a.java', '/repo'), 'src/a.java');
  assert.equal(toRepoRelative('./src/a.java', '/repo'), 'src/a.java');
  assert.equal(toRepoRelative('/repo/src/a.java', '/repo'), 'src/a.java');
  assert.equal(toRepoRelative('/other/src/a.java', '/repo'), null);
  assert.equal(normalizeSlashes('src\\a.java'), 'src/a.java');
  assert.equal(isAbsoluteLike('C:\\a\\b'), true);
  assert.equal(isAbsoluteLike('/a/b'), true);
  assert.equal(isAbsoluteLike('a/b'), false);
});
