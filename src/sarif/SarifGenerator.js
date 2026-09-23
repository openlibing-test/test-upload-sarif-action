'use strict';

const { buildPrimaryLocationLineHash } = require('../util/fingerprint');

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';

/** 实际工具名：华为云 CodeArts Check（无空格，后端 SarifParserFactory 按此精确路由） */
const TOOL_NAME = 'CodeArtsCheck';

/**
 * 华为云代码检查级别 -> SARIF 2.1.0 level
 * 致命/严重 -> error，一般 -> warning，提示 -> note；未知默认 warning。
 */
const LEVEL_MAP = {
  致命: 'error',
  严重: 'error',
  一般: 'warning',
  提示: 'note'
};

const DEFAULT_LEVEL = 'warning';

/**
 * 将华为云代码检查报告中间模型生成为 SARIF 2.1.0 对象。
 *
 * 与 openlibing-codecheck 现有解析器(CodeQlSarifParser)对齐：
 * - tool.driver.name 写实际工具名 "CodeArtsCheck"（无空格），后端 SarifParserFactory 按此路由；
 * - 规则名放在 rule.properties.name（CodeQlSarifParser 从此处读取）。
 */
class SarifGenerator {
  /**
   * @param {{task: object, issues: Array}} parsed 报告解析器输出的中间模型
   * @returns {object} SARIF 2.1.0 对象
   */
  static generate(parsed) {
    const rules = [];
    const ruleIndex = new Map();
    const results = [];

    for (const issue of parsed.issues || []) {
      if (!issue || !issue.ruleId) {
        continue;
      }
      if (!ruleIndex.has(issue.ruleId)) {
        const rule = {
          id: issue.ruleId,
          properties: { name: issue.ruleName || issue.ruleId },
          defaultConfiguration: { level: this.mapLevel(issue.severity) },
          fullDescription: { text: issue.message || '' }
        };
        ruleIndex.set(issue.ruleId, rule);
        rules.push(rule);
      }

      const region = { startLine: issue.line };
      if (issue.snippet) {
        region.snippet = { text: issue.snippet };
      }

      results.push({
        ruleId: issue.ruleId,
        level: this.mapLevel(issue.severity),
        message: { text: issue.message || '' },
        // 后端 CodeQlSarifParser 从 partialFingerprints.primaryLocationLineHash 读取
        // locationHashRaw，缺失会导致 buildFingerprintKey 跳过问题、不入库
        partialFingerprints: {
          primaryLocationLineHash: buildPrimaryLocationLineHash(
            issue.file,
            issue.line,
            issue.snippet
          )
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: issue.file || '' },
              region
            }
          }
        ]
      });
    }

    const driver = {
      name: TOOL_NAME, // 实际工具名：华为云 CodeArts Check（无空格）
      semanticVersion: ''
    };
    if (rules.length > 0) {
      driver.rules = rules;
    }

    const run = {
      tool: { driver }
    };
    if (results.length > 0) {
      run.results = results;
    }

    return {
      $schema: SARIF_SCHEMA,
      version: SARIF_VERSION,
      runs: [run]
    };
  }

  /**
   * 华为云代码检查级别映射为 SARIF level
   * @param {string} severity 原始级别（致命/严重/一般/提示）
   * @returns {string} SARIF level
   */
  static mapLevel(severity) {
    return LEVEL_MAP[severity] || DEFAULT_LEVEL;
  }
}

module.exports = SarifGenerator;
