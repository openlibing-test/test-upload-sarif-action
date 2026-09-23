const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const os = require('os');

const SarifNormalizer = require('../src/sarif/SarifNormalizer');
const { buildPrimaryLocationLineHash } = require('../src/util/fingerprint');

/** CodeArts Check 原生 SARIF 最小样例（工具名带空格 "CodeArts Check"、无 partialFingerprints） */
function sampleCodeArtsSarif() {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeArts Check',
            rules: [
              {
                id: 'R1',
                properties: { name: '规则一' },
                defaultConfiguration: { level: 'warning' }
              }
            ]
          }
        },
        results: [
          {
            ruleId: 'R1',
            level: 'warning',
            message: { text: '问题一' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'a.java' },
                  region: { startLine: 3, snippet: { text: 'int x;' } }
                }
              }
            ]
          }
        ]
      }
    ]
  };
}

test('规范化: tool.driver.name 统一为无空格 CodeArtsCheck（原生带空格）', () => {
  const { sarif } = SarifNormalizer.normalize(sampleCodeArtsSarif());
  assert.equal(sarif.runs[0].tool.driver.name, 'CodeArtsCheck');
});

test('规范化: 第三方工具名不被改写（如 gitleaks）', () => {
  const sarif = sampleCodeArtsSarif();
  sarif.runs[0].tool.driver.name = 'gitleaks';
  const { sarif: normalized } = SarifNormalizer.normalize(sarif);
  assert.equal(normalized.runs[0].tool.driver.name, 'gitleaks');
});

test('规范化: 已是无空格 CodeArtsCheck 时保持原样', () => {
  const sarif = sampleCodeArtsSarif();
  sarif.runs[0].tool.driver.name = 'CodeArtsCheck';
  const { sarif: normalized } = SarifNormalizer.normalize(sarif);
  assert.equal(normalized.runs[0].tool.driver.name, 'CodeArtsCheck');
});

test('规范化: 为缺失指纹的结果补齐 primaryLocationLineHash(32 位 hex)', () => {
  const { sarif } = SarifNormalizer.normalize(sampleCodeArtsSarif());
  const result = sarif.runs[0].results[0];
  const expected = buildPrimaryLocationLineHash('a.java', 3, 'int x;');
  assert.equal(result.partialFingerprints.primaryLocationLineHash, expected);
  assert.match(result.partialFingerprints.primaryLocationLineHash, /^[0-9a-f]{32}$/);
});

test('规范化: 已有指纹的结果不被覆盖', () => {
  const sarif = sampleCodeArtsSarif();
  sarif.runs[0].results[0].partialFingerprints = { primaryLocationLineHash: 'existing-hash' };
  const { sarif: normalized } = SarifNormalizer.normalize(sarif);
  assert.equal(normalized.runs[0].results[0].partialFingerprints.primaryLocationLineHash, 'existing-hash');
});

test('规范化: 无 snippet 时指纹回退 uri|startLine', () => {
  const sarif = sampleCodeArtsSarif();
  delete sarif.runs[0].results[0].locations[0].physicalLocation.region.snippet;
  const { sarif: normalized } = SarifNormalizer.normalize(sarif);
  const result = normalized.runs[0].results[0];
  assert.equal(
    result.partialFingerprints.primaryLocationLineHash,
    buildPrimaryLocationLineHash('a.java', 3, undefined)
  );
});

test('规范化: 无 ruleId 的结果跳过且不计入 issueCount', () => {
  const sarif = sampleCodeArtsSarif();
  sarif.runs[0].results.push({ message: { text: '缺 ruleId' } });
  const { issueCount } = SarifNormalizer.normalize(sarif);
  assert.equal(issueCount, 1);
});

test('规范化: 缺 runs 抛错', () => {
  assert.throws(() => SarifNormalizer.normalize({ version: '2.1.0' }), /缺少 runs/);
});

test('规范化: 缺 tool.driver 抛错', () => {
  assert.throws(
    () => SarifNormalizer.normalize({ version: '2.1.0', runs: [{ results: [] }] }),
    /缺少 tool\.driver/
  );
});

test('真实样例: codearts-check.sarif 规范化为 13 条问题且每条结果含指纹', () => {
  const fixture = path.join(__dirname, 'fixtures', 'codearts-check.sarif');
  const { sarif, issueCount } = SarifNormalizer.normalizeFile(fixture);
  assert.equal(issueCount, 13);
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'CodeArtsCheck');
  assert.equal(run.results.length, 13);
  for (const result of run.results) {
    assert.match(result.partialFingerprints.primaryLocationLineHash, /^[0-9a-f]{32}$/);
    assert.ok(result.ruleId);
    assert.ok(result.locations && result.locations[0].physicalLocation.artifactLocation.uri);
  }
});

test('真实样例: 经 convertReportFile 输出文件可被后端路径消费', () => {
  const { convertReportFile } = require('../index.js');
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'normalizer-'));
  const fixture = path.join(__dirname, 'fixtures', 'codearts-check.sarif');
  const { outPath, issueCount } = convertReportFile(fixture, outDir);
  assert.equal(issueCount, 13);
  const sarif = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  assert.equal(sarif.runs[0].tool.driver.name, 'CodeArtsCheck');
  assert.equal(sarif.runs[0].results.length, 13);
});
