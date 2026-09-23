'use strict';

const fs = require('fs');
const { buildPrimaryLocationLineHash } = require('../util/fingerprint');

/**
 * SARIF artifactLocation.uri 归一化：将以仓库根目录为前缀的机器绝对路径
 * 转换为相对仓库根的路径（统一正斜杠分隔），相对路径保持原样。
 *
 * 背景：不同工具产出的 uri 形态不一——部分工具（如 spotbugs）输出 runner 机器的
 * 绝对路径（/home/runner/work/repo/repo/src/Foo.java），部分工具（如 gitleaks）
 * 输出相对路径（src/Foo.java）。绝对路径会造成：
 *  1. 后端告警展示路径带机器前缀，不可读；
 *  2. 无 snippet 时指纹 sha256(uri|startLine) 含机器绝对路径，同一告警在不同
 *     runner 上指纹不同，后端去重失效。
 *
 * 归一化只处理"以仓库根为前缀"的绝对路径；指向仓库外的绝对路径无法映射，原样保留。
 */

/** 路径分隔符统一为正斜杠（兼容 Windows 反斜杠路径） */
function normalizeSlashes(p) {
  return String(p || '').replace(/\\/g, '/');
}

/** 剥离 file:// 前缀并做 URL 解码；非 file:// 原样返回 */
function stripFileScheme(uri) {
  if (!/^file:\/\//i.test(uri)) return uri;
  let stripped = uri.replace(/^file:\/\//i, '');
  try {
    stripped = decodeURIComponent(stripped);
  } catch (e) {
    // 解码失败保留原样
  }
  // file:///C:/... -> C:/...（去掉盘符前的斜杠）
  stripped = stripped.replace(/^\/+([a-zA-Z]:)/, '$1');
  return stripped;
}

/** 是否绝对路径（POSIX / 或 Windows 盘符），兼容任意平台运行 */
function isAbsoluteLike(p) {
  return p.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(p);
}

/** 判断 uri（已去 file://）是否位于 repoRoot 之下（忽略大小写与分隔符差异） */
function isUnderRepoRoot(uri, repoRoot) {
  const u = normalizeSlashes(uri);
  const r = normalizeSlashes(repoRoot).replace(/\/+$/, '');
  if (!r) return false;
  if (u === r) return true;
  return u.toLowerCase().startsWith(`${r.toLowerCase()}/`);
}

/**
 * 将单个 uri 归一化为相对仓库根路径。
 * @param {string} uri 原始 uri
 * @param {string} repoRoot 仓库根目录绝对路径
 * @returns {string|null} 归一化后的相对路径；null 表示无需变更
 */
function toRepoRelative(uri, repoRoot) {
  if (!uri || !repoRoot) return null;
  const decoded = stripFileScheme(uri);
  if (!decoded) return null;
  if (isAbsoluteLike(decoded)) {
    if (!isUnderRepoRoot(decoded, repoRoot)) return null;
    // 统一为正斜杠后手动剥离仓库根前缀，不依赖平台 path.relative：
    // path.relative 在 Windows/Linux 上对盘符路径行为不一致，会造成跨平台结果差异。
    const u = normalizeSlashes(decoded);
    const r = normalizeSlashes(repoRoot).replace(/\/+$/, '');
    if (u.length > r.length) {
      return u.slice(r.length + 1);
    }
    return '';
  }
  // 相对路径：剥离 ./ 前缀并统一分隔符（相对仓库根即当前工作目录）
  return normalizeSlashes(decoded).replace(/^\.\//, '');
}

/**
 * 归一化 SARIF 对象中全部 result 的 artifactLocation.uri。
 * uri 变化时同步重算 partialFingerprints.primaryLocationLineHash：
 * snippet 存在时 hash 与 uri 无关（重算结果不变），无 snippet 时消除机器路径对指纹的影响。
 * @param {object} sarifObj SARIF 2.1.0 对象（原地修改）
 * @param {string} repoRoot 仓库根目录绝对路径
 * @returns {number} uri 发生变化的 result 数量
 */
function normalizeSarifUris(sarifObj, repoRoot) {
  const results = sarifObj && sarifObj.runs && sarifObj.runs[0] && sarifObj.runs[0].results;
  if (!Array.isArray(results) || !repoRoot) return 0;
  let changed = 0;
  for (const r of results) {
    const loc = r && r.locations && r.locations[0] && r.locations[0].physicalLocation;
    if (!loc || !loc.artifactLocation) continue;
    const rel = toRepoRelative(loc.artifactLocation.uri, repoRoot);
    if (rel === null || rel === loc.artifactLocation.uri) continue;
    loc.artifactLocation.uri = rel;
    changed += 1;
    // uri 变化时重算指纹，保证 uri 与指纹一致
    if (r.partialFingerprints && r.partialFingerprints.primaryLocationLineHash) {
      const region = loc.region || {};
      r.partialFingerprints.primaryLocationLineHash = buildPrimaryLocationLineHash(
        rel,
        region.startLine,
        region.snippet && region.snippet.text
      );
    }
  }
  return changed;
}

/** 归一化一批 SARIF 文件（原地写回），返回发生变更的文件数 */
function normalizeSarifFiles(sarifFiles, repoRoot) {
  let changedFiles = 0;
  for (const f of sarifFiles || []) {
    let sarifObj;
    try {
      sarifObj = JSON.parse(fs.readFileSync(f, 'utf-8'));
    } catch (e) {
      continue;
    }
    const n = normalizeSarifUris(sarifObj, repoRoot);
    if (n > 0) {
      fs.writeFileSync(f, JSON.stringify(sarifObj, null, 2), 'utf-8');
      changedFiles += 1;
    }
  }
  return changedFiles;
}

module.exports = {
  normalizeSlashes,
  stripFileScheme,
  isAbsoluteLike,
  isUnderRepoRoot,
  toRepoRelative,
  normalizeSarifUris,
  normalizeSarifFiles
};
