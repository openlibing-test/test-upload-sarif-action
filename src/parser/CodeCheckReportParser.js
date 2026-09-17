'use strict';

const fs = require('fs');

const SECTION_DETAIL = '### 2.5 详细问题列表';

/**
 * 华为云 CodeArts Check 报告(Markdown step_summary)解析器
 *
 * 主数据源为 "### 2.5 详细问题列表" 表格（每行一条问题），
 * "## 3 问题详细分析" 章节的代码块用于回填问题行的代码片段。
 * 输出中间模型 { task, issues, warnings }。
 */
class CodeCheckReportParser {
  /**
   * 从文件读取并解析报告
   * @param {string} filePath 报告文件路径
   * @returns {{task: object, issues: Array, warnings: Array}}
   */
  static parseFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    return CodeCheckReportParser.parse(content);
  }

  /**
   * 解析报告内容
   * @param {string} markdown 报告内容
   * @returns {{task: {name: string, branch: string, gateResult: string}, issues: Array, warnings: Array}}
   */
  static parse(markdown) {
    const warnings = [];
    const task = { name: '', branch: '', gateResult: '' };
    const issues = [];
    const snippetMap = {};

    if (typeof markdown !== 'string' || markdown.trim() === '') {
      return { task, issues, warnings };
    }

    const lines = markdown.split(/\r?\n/);

    this.parseTask(lines, task);
    this.collectSnippets(lines, snippetMap);
    this.parseDetailTable(lines, issues, snippetMap, warnings, markdown);

    return { task, issues, warnings };
  }

  /**
   * 解析 "## 1 任务摘要" 表格（可选元信息）
   * @param {string[]} lines 报告行
   * @param {object} task 输出对象
   */
  static parseTask(lines, task) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.includes('任务名称') || !line.includes('分支名称')) {
        continue;
      }
      // 表头行后的第一个非空行即为数据行
      for (let j = i + 1; j < lines.length; j++) {
        const dataLine = lines[j].trim();
        if (dataLine === '' || dataLine.startsWith('|')) {
          if (dataLine === '' || /^\|[\s\-|]*\|$/.test(dataLine)) {
            continue;
          }
          const cells = this.splitTableRow(dataLine);
          if (cells.length >= 3) {
            task.name = cells[0];
            task.branch = cells[1];
            task.gateResult = cells[2];
          }
          return;
        }
      }
      return;
    }
  }

  /**
   * 从 "## 3 问题详细分析" 章节收集代码片段，映射为 `${file}:${line}` -> snippet
   * @param {string[]} lines 报告行
   * @param {Record<string, string>} snippetMap 输出映射
   */
  static collectSnippets(lines, snippetMap) {
    let inAnalysis = false;
    let currentKey = null;
    let collecting = false;
    let buffer = [];

    const flush = () => {
      if (currentKey && buffer.length > 0) {
        snippetMap[currentKey] = buffer.join('\n');
      }
      buffer = [];
      currentKey = null;
      collecting = false;
    };

    for (const rawLine of lines) {
      const line = rawLine.trimEnd();
      if (/^### \d+\.\d+ /.test(line)) {
        inAnalysis = true;
        continue;
      }
      if (!inAnalysis) {
        continue;
      }
      const keyMatch = line.match(/^\*\*问题代码\d+\*\*:\s*(.+?):(\d+)\s*$/);
      if (keyMatch) {
        flush();
        currentKey = `${keyMatch[1]}:${keyMatch[2]}`;
        continue;
      }
      if (line.trimStart().startsWith('```')) {
        if (!collecting) {
          // 代码块开始（可能带语言标记，如 ```JAVA）
          collecting = true;
          buffer = [];
        } else {
          flush();
        }
        continue;
      }
      if (collecting) {
        buffer.push(line);
      }
    }
    flush();
  }

  /**
   * 解析 "### 2.5 详细问题列表" 表格，生成问题列表
   * @param {string[]} lines 报告行
   * @param {Array} issues 输出问题列表
   * @param {Record<string, string>} snippetMap 代码片段映射
   * @param {Array} warnings 输出警告列表
   * @param {string} markdown 原始内容（用于判断是否应报错）
   */
  static parseDetailTable(lines, issues, snippetMap, warnings, markdown) {
    const startIdx = lines.findIndex((l) => l.includes(SECTION_DETAIL));
    if (startIdx < 0) {
      // 有内容但缺少主章节：明确报错，避免静默产出空结果
      if (markdown.trim() !== '') {
        throw new Error(`报告缺少 "${SECTION_DETAIL}" 章节，无法解析问题`);
      }
      return;
    }

    for (let i = startIdx + 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line.startsWith('|')) {
        // 遇到下一个章节标题或非表格行即结束
        if (/^#{1,6} /.test(line)) {
          break;
        }
        continue;
      }
      const cells = this.splitTableRow(line);
      if (cells.length < 5) {
        warnings.push(`跳过无法解析的报告行: ${line}`);
        continue;
      }
      const severity = cells[0];
      const ruleColumn = cells[1];
      const message = cells[2];
      const file = cells[3];
      const lineNo = parseInt(cells[4], 10);

      // 跳过表头与分隔行
      if (severity === '严重程度' || /^-+$/.test(severity)) {
        continue;
      }
      if (Number.isNaN(lineNo)) {
        warnings.push(`跳过行号非法的报告行: ${line}`);
        continue;
      }

      const ruleParts = ruleColumn.split(/\s+/);
      const ruleId = ruleParts[0] || '';
      const ruleName = ruleParts.slice(1).join(' ');
      const key = `${file}:${lineNo}`;
      issues.push({
        severity,
        ruleId,
        ruleName,
        message,
        file,
        line: lineNo,
        snippet: snippetMap[key] || ''
      });
    }
  }

  /**
   * 将 Markdown 表格行按 `|` 拆分为单元格数组（去除首尾空）
   * @param {string} row 表格行
   * @returns {string[]} 单元格
   */
  static splitTableRow(row) {
    return row
      .split('|')
      .map((s) => s.trim())
      .filter((s) => s !== '');
  }
}

module.exports = CodeCheckReportParser;
