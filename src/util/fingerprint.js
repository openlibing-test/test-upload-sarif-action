'use strict';

const crypto = require('crypto');

/**
 * 计算 SARIF result 的主位置行 hash（partialFingerprints.primaryLocationLineHash）。
 *
 * 与 openlibing-codecheck 后端对齐：CodeQlSarifParser 从
 * result.partialFingerprints.primaryLocationLineHash 读取 locationHashRaw，
 * buildFingerprintKey 要求该值非空，否则问题会被跳过、不入库。
 *
 * 策略（稳定优先）：
 * - 有行内容 snippet 时，对行内容取 SHA-256（前 32 位 hex），行号偏移不影响指纹；
 * - 无 snippet 时，对 uri|startLine 取 SHA-256（前 32 位 hex）。
 *
 * @param {string} uri 文件路径
 * @param {number|string|undefined} startLine 起始行
 * @param {string|undefined} snippetText 行内容（可选）
 * @returns {string} 32 位小写 hex
 */
function buildPrimaryLocationLineHash(uri, startLine, snippetText) {
  const raw =
    snippetText && snippetText.length > 0
      ? snippetText
      : `${uri || ''}|${startLine == null ? '' : startLine}`;
  return crypto.createHash('sha256').update(raw, 'utf-8').digest('hex').slice(0, 32);
}

module.exports = { buildPrimaryLocationLineHash };
