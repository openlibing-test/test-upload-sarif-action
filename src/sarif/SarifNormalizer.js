'use strict';

const fs = require('fs');
const { buildPrimaryLocationLineHash } = require('../util/fingerprint');

/**
 * 将华为云 CodeArts Check 原生 SARIF 规范化为 openlibing-codecheck 可消费的标准 SARIF。
 *
 * 需适配的差异（CodeArts Check 原生导出 vs 后端解析要求）：
 * - tool.driver.name 原生通常为 "CodeArts Check"（带空格），后端 SarifParserFactory 按
 *   工具名精确路由 → 统一改写为无空格 "CodeArtsCheck"；
 * - results 不含 partialFingerprints，后端 extractLocationHash 取不到 primaryLocationLineHash，
 *   导致 buildFingerprintKey 抛异常跳过问题 → 为每条 result 补齐；
 * - 规则名在 rules[].properties.name（中文规则名），与 CodeQlSarifParser.extractRuleName 读取路径
 *   一致，保留即可；级别（error/warning/note）映射后端已按 SARIF level 语义处理。
 *
 * 规范化对任何第三方 SARIF 同样有效（只要可解析出 runs/tool.driver/results）。
 */
class SarifNormalizer {
  /**
   * 规范化 CodeArts Check 原生 SARIF 文件。
   *
   * @param {string} filePath SARIF 文件路径
   * @returns {{sarif: object, issueCount: number, warnings: string[]}}
   */
  static normalizeFile(filePath) {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    return SarifNormalizer.normalize(raw);
  }

  /**
   * 规范化 SARIF 2.1.0 对象。
   *
   * @param {object} sarif SARIF 2.1.0 对象
   * @returns {{sarif: object, issueCount: number, warnings: string[]}}
   */
  static normalize(sarif) {
    const warnings = [];
    if (!sarif || !Array.isArray(sarif.runs) || sarif.runs.length === 0) {
      throw new Error('非法 SARIF：缺少 runs');
    }
    const run = sarif.runs[0];
    if (!run.tool || !run.tool.driver) {
      throw new Error('非法 SARIF：缺少 tool.driver');
    }

    // 后端 SarifParserFactory 按工具名精确路由：原生 "CodeArts Check"（带空格）统一为无空格 "CodeArtsCheck"
    const originalTool = run.tool.driver.name;
    const normalizedTool = 'CodeArtsCheck';
    if (originalTool !== normalizedTool) {
      run.tool.driver.name = normalizedTool;
    }

    const results = Array.isArray(run.results) ? run.results : [];
    let issueCount = 0;
    for (const result of results) {
      if (!result || !result.ruleId) {
        continue;
      }
      issueCount += 1;
      const { uri, startLine, snippetText } = SarifNormalizer.extractLocation(result);
      // 原生 SARIF 未携带指纹时补齐，保证后端 buildFingerprintKey 非空、问题可入库
      result.partialFingerprints = result.partialFingerprints || {};
      if (!result.partialFingerprints.primaryLocationLineHash) {
        result.partialFingerprints.primaryLocationLineHash = buildPrimaryLocationLineHash(
          uri,
          startLine,
          snippetText
        );
      }
    }
    console.log(`[INFO] SARIF 规范化: tool.driver.name "${originalTool}" -> "${normalizedTool}"`);
    return { sarif, issueCount, warnings };
  }

  /**
   * 提取 result 的物理位置字段。
   *
   * @param {object} result SARIF result
   * @returns {{uri: string|undefined, startLine: number|undefined, snippetText: string|undefined}}
   */
  static extractLocation(result) {
    const loc = result.locations && result.locations[0] && result.locations[0].physicalLocation;
    if (!loc) {
      return { uri: undefined, startLine: undefined, snippetText: undefined };
    }
    const uri = loc.artifactLocation && loc.artifactLocation.uri;
    const region = loc.region || {};
    return {
      uri,
      startLine: region.startLine,
      snippetText: region.snippet && region.snippet.text
    };
  }
}

module.exports = SarifNormalizer;
