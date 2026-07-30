const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

function getInput(name) {
  const val = process.env[`INPUT_${name.toUpperCase()}`] || '';
  return val.trim();
}

function setOutput(key, value) {
  const stepOutput = process.env.STEP_OUTPUT;
  if (!stepOutput) {
    console.log(`[WARN] STEP_OUTPUT env not set, skip output: ${key}=${value}`);
    return;
  }

  let filePath;
  try {
    const stat = fs.statSync(stepOutput);
    if (stat.isDirectory()) {
      filePath = path.join(stepOutput, 'output');
    } else {
      filePath = stepOutput;
    }
  } catch (e) {
    const parentDir = path.dirname(stepOutput);
    if (fs.existsSync(parentDir) && fs.statSync(parentDir).isDirectory()) {
      filePath = stepOutput;
    } else {
      console.log(`[WARN] STEP_OUTPUT path is invalid, skip output: ${key}=${value}`);
      return;
    }
  }

  const line = `${key}=${value}\n`;
  fs.appendFileSync(filePath, line, 'utf-8');
  console.log(`[OUTPUT] ${key}=${value}`);
}

function exec(cmd) {
  console.log(`> ${cmd}`);
  execSync(cmd, { stdio: 'inherit', shell: '/bin/bash' });
}

function sanitizePath(pathStr) {
  return pathStr.replace(/(\d+\.\d+\.\d+\.\d+)/g, '[IP_ADDRESS]');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data, 'utf-8').digest('hex');
}

function hmacSha256Hex(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf-8').digest('hex');
}

function apigTwoChar(s) {
  return s >= 10 ? '' + s : '0' + s;
}

function apigGetTime() {
  const date = new Date();
  return '' + date.getUTCFullYear() + apigTwoChar(date.getUTCMonth() + 1) + apigTwoChar(date.getUTCDate()) +
    'T' + apigTwoChar(date.getUTCHours()) + apigTwoChar(date.getUTCMinutes()) + apigTwoChar(date.getUTCSeconds()) + 'Z';
}

function apigUrlEncode(str) {
  return encodeURIComponent(String(str)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function apigFindHeader(headers, header) {
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === header.toLowerCase()) {
      return headers[k];
    }
  }
  return null;
}

function apigCanonicalURI(uri) {
  const segments = uri.split('/');
  const encoded = segments.map(s => apigUrlEncode(s)).join('/');
  if (encoded.length === 0 || encoded[encoded.length - 1] !== '/') {
    return encoded + '/';
  }
  return encoded;
}

function apigCanonicalQueryString(query) {
  if (!query) return '';
  const params = query.split('&').filter(Boolean);
  const kvPairs = params.map(p => {
    const idx = p.indexOf('=');
    if (idx < 0) return { key: p, value: '' };
    return { key: p.substring(0, idx), value: p.substring(idx + 1) };
  });
  kvPairs.sort((a, b) => a.key < b.key ? -1 : (a.key > b.key ? 1 : 0));
  return kvPairs.map(kv => apigUrlEncode(kv.key) + '=' + apigUrlEncode(kv.value)).join('&');
}

function apigSignedHeaders(headers) {
  return Object.keys(headers).map(k => k.toLowerCase()).sort();
}

function apigCanonicalHeaders(headers, signedHeaderKeys) {
  const lower = {};
  for (const k of Object.keys(headers)) {
    lower[k.toLowerCase()] = headers[k];
  }
  return signedHeaderKeys.map(k => k + ':' + String(lower[k]).trim()).join('\n') + '\n';
}

function signApigRequest(method, url, headers, body, ak, sk) {
  const urlObj = new URL(url);
  const query = urlObj.search ? urlObj.search.substring(1) : '';

  if (apigFindHeader(headers, 'host') === null) {
    headers['host'] = urlObj.host;
  }
  if (apigFindHeader(headers, 'X-Sdk-Date') === null) {
    headers['X-Sdk-Date'] = apigGetTime();
  }
  if (apigFindHeader(headers, 'x-sdk-content-sha256') === null) {
    headers['x-sdk-content-sha256'] = sha256Hex(body || '');
  }

  const signedHeaderKeys = apigSignedHeaders(headers);
  const signedHeaders = signedHeaderKeys.join(';');

  const canonicalRequest = [
    method.toUpperCase(),
    apigCanonicalURI(urlObj.pathname || '/'),
    apigCanonicalQueryString(query),
    apigCanonicalHeaders(headers, signedHeaderKeys),
    signedHeaders,
    sha256Hex(body || '')
  ].join('\n');

  const stringToSign = [
    'SDK-HMAC-SHA256',
    apigFindHeader(headers, 'X-Sdk-Date'),
    sha256Hex(canonicalRequest)
  ].join('\n');

  const signature = hmacSha256Hex(sk, stringToSign);

  headers['Authorization'] = `SDK-HMAC-SHA256 Access=${ak}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return headers;
}

function sendCallback(url, payload, apigAppKey, apigAppSecret) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const data = JSON.stringify(payload);

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data, 'utf-8')
    };

    if (apigAppKey && apigAppSecret) {
      signApigRequest('POST', url, headers, data, apigAppKey, apigAppSecret);
    }

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: headers,
      timeout: 30000
    };

    const transport = urlObj.protocol === 'https:' ? https : http;
    const req = transport.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const resData = JSON.parse(body);
            if (resData.code === 200 || resData.code === 0) {
              resolve(resData);
            } else {
              reject(new Error(`API 业务错误: code=${resData.code}, msg=${resData.msg || resData.message || 'unknown'}`));
            }
          } catch (e) {
            resolve(body);
          }
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
        }
      });
    });

    req.on('error', (e) => { reject(e); });
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout after 30000ms')); });
    req.write(data);
    req.end();
  });
}

function execCapture(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf-8', shell: '/bin/bash' }).trim();
  } catch (e) {
    return '';
  }
}

async function run() {
  const sarifFile = getInput('sarif_file');
  const obsKeyRoot = 'codeql-results';

  const obsBucket = 'openlibing-codeql';
  const obsAk = getInput('obs_ak');
  const obsSk = getInput('obs_sk');
  
  const obsWriteEndpoint = 'obs.cn-southwest-2.myhuaweicloud.com';
  const obsReadEndpoint = 'https://openlibing-codeql.obs.cn-southwest-2.myhuaweicloud.com';

  const apigAppKey = getInput('apig_app_key');
  const apigAppSecret = getInput('apig_app_secret');
  const category = getInput('category');
  // workflow_run_id 由 gitcode 平台自动注入到 env
  const workflowRunId = process.env.ATOMGIT_RUN_ID || '';
  const callbackUrl = 'https://apig.openlibing.com:443/openlibing-codecheck/codescan/v1/result/receive';
  const callbackBetaUrl = 'https://174e1b821a8446f38998a67186ba766e.apic.cn-southwest-2.huaweicloudapis.com/openlibing-codecheck/codescan/v1/result/receive';

  // 根据 env_type input 显式选择回调地址，不再通过仓库 URL 推断
  const envType = (getInput('env_type') || 'prod').toLowerCase();
  const isBetaEnv = envType === 'beta';
  const finalCallbackUrl = isBetaEnv ? callbackBetaUrl : callbackUrl;
  console.log(`[INFO] 环境类型: ${isBetaEnv ? 'beta (测试环境)' : 'prod (正式环境)'}`);

  const repoName = process.env.ATOMGIT_REPOSITORY || process.env.GIT_REPOSITORY || '';
  const repoBaseName = repoName.split('/').pop() || 'unknown-repo';
  const now = new Date();
  const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}.${String(now.getHours()).padStart(2, '0')}`;
  const buildNumber = workflowRunId
    ? `${repoBaseName}/${dateStr}/${workflowRunId}`
    : `${repoBaseName}/${dateStr}`;

  console.log('===== openlibing-upload-sarif 启动 =====');

  console.log('\n===== [1] 校验参数 =====');
  if (!sarifFile) {
    console.log('[ERROR] sarif_file 参数不能为空');
    setOutput('result', 'failed');
    process.exit(1);
  }

  const missingInputs = [];
  if (!obsAk) missingInputs.push('obs_ak');
  if (!obsSk) missingInputs.push('obs_sk');
  if (missingInputs.length > 0) {
    console.log(`[ERROR] 缺少必要的参数: ${missingInputs.join(', ')}`);
    setOutput('result', 'failed');
    process.exit(1);
  }
  console.log('[OK] 参数校验通过');

  console.log('\n===== [2] 检查 SARIF 文件 =====');
  const workspace = process.env.WORKSPACE || process.cwd();
  let resolvedSarifPath = sarifFile;
  if (!fs.existsSync(resolvedSarifPath)) {
    resolvedSarifPath = path.join(workspace, sarifFile);
  }
  if (!fs.existsSync(resolvedSarifPath)) {
    const gitDir = execCapture(`find ${workspace} -maxdepth 3 -name ".git" -type d 2>/dev/null | head -1`);
    if (gitDir) {
      resolvedSarifPath = path.join(path.dirname(gitDir), sarifFile);
    }
  }
  if (!fs.existsSync(resolvedSarifPath)) {
    console.log(`[ERROR] SARIF 路径不存在: ${sarifFile}`);
    setOutput('result', 'failed');
    process.exit(1);
  }

  let sarifFiles = [];
  const isDir = fs.statSync(resolvedSarifPath).isDirectory();
  if (isDir) {
    console.log(`[INFO] 输入为目录: ${resolvedSarifPath}，扫描所有 .sarif 文件`);
    const entries = fs.readdirSync(resolvedSarifPath);
    for (const entry of entries) {
      if (entry.endsWith('.sarif')) {
        sarifFiles.push(path.join(resolvedSarifPath, entry));
      }
    }
    if (sarifFiles.length === 0) {
      console.log(`[ERROR] 目录中未找到 .sarif 文件: ${resolvedSarifPath}`);
      setOutput('result', 'failed');
      process.exit(1);
    }
    console.log(`[OK] 找到 ${sarifFiles.length} 个 SARIF 文件:`);
    sarifFiles.forEach(f => console.log(`  - ${path.basename(f)}`));
  } else {
    sarifFiles = [resolvedSarifPath];
    console.log(`[OK] SARIF 文件: ${resolvedSarifPath}`);
  }

  console.log('\n===== [3] 安装 obsutil =====');
  const tmpDir = os.tmpdir();
  exec(`wget -q https://obs-community.obs.cn-north-1.myhuaweicloud.com/obsutil/current/obsutil_linux_amd64.tar.gz -O ${tmpDir}/obsutil_linux_amd64.tar.gz 2>/dev/null || curl -sL https://obs-community.obs.cn-north-1.myhuaweicloud.com/obsutil/current/obsutil_linux_amd64.tar.gz -o ${tmpDir}/obsutil_linux_amd64.tar.gz`);
  exec(`cd ${tmpDir} && tar zxf obsutil_linux_amd64.tar.gz --strip-components=1 2>/dev/null || true`);
  exec(`chmod 755 ${tmpDir}/obsutil 2>/dev/null || true`);

  const obsutilPath = execCapture(`which obsutil 2>/dev/null || find ${tmpDir} -name "obsutil" -type f 2>/dev/null | head -1`);
  if (!obsutilPath) {
    console.log('[ERROR] obsutil 安装失败');
    setOutput('result', 'failed');
    process.exit(1);
  }
  console.log(`[OK] obsutil 路径: ${obsutilPath}`);

  console.log('\n===== [4] 构建 OBS 路径 =====');
  const obsKeyPrefix = `${obsKeyRoot}/${buildNumber}`;
  const downloadUrlPrefix = `${obsReadEndpoint}/${obsKeyPrefix}`;

  console.log('\n===== [5] 生成构建产物 JSON =====');
  const buildResultDir = path.join(tmpDir, 'codeql-analyze-output');
  if (!fs.existsSync(buildResultDir)) {
    fs.mkdirSync(buildResultDir, { recursive: true });
  }

  const sarifDownloadUrls = sarifFiles.map(f => `${downloadUrlPrefix}/${path.basename(f)}`);
  const sarifBuildings = sarifFiles.map((f, i) => {
    return {
      name: path.basename(f),
      type: 'CodeQL代码检查结果（sarif）',
      downloadUrl: sarifDownloadUrls[i]
    };
  });

  const isSingleFile = sarifFiles.length === 1;
  let buildResult = {
    type: 'build',
    buildings: isSingleFile ? sarifBuildings[0] : sarifBuildings
  };

  const buildResultPath = path.join(buildResultDir, 'build-result.json');
  fs.writeFileSync(buildResultPath, JSON.stringify(buildResult, null, 2), 'utf-8');

  console.log('\n===== [6] 上传到 OBS =====');

  console.log(`[INFO] 上传构建产物目录: ${buildResultDir}`);
  try {
    exec(`${obsutilPath} cp "${buildResultDir}" "obs://${obsBucket}/${obsKeyPrefix}/" -r -f -acl=public-read -e="${obsWriteEndpoint}" -i="${obsAk}" -k="${obsSk}" -flat=true`);
  } catch (e1) {
    console.log(`[WARN] 构建产物目录上传失败: ${e1.message}`);
  }

  for (let i = 0; i < sarifFiles.length; i++) {
    const sarifFile = sarifFiles[i];
    const sarifName = path.basename(sarifFile);
    console.log(`[INFO] 上传 SARIF 文件 (${i + 1}/${sarifFiles.length}): ${sarifName}`);
    try {
      exec(`${obsutilPath} cp "${sarifFile}" "obs://${obsBucket}/${obsKeyPrefix}/" -f -acl=public-read -e="${obsWriteEndpoint}" -i="${obsAk}" -k="${obsSk}"`);
    } catch (e2) {
      console.log(`[ERROR] ${sarifName} 上传失败: ${e2.message}`);
      console.log('[INFO] 检查 obsutil 错误详情:');
      try {
        exec(`cat /home/octopus/.obsutil_output/*.log 2>/dev/null | tail -50`);
      } catch (_) {}
      setOutput('result', 'failed');
      process.exit(1);
    }
  }

  const buildResultUrl = `${downloadUrlPrefix}/build-result.json`;
  const obsUrlValue = isSingleFile ? sarifDownloadUrls[0] : sarifDownloadUrls;

  console.log('\n================================================================');
  console.log('[INFO] 上传成功');
  console.log('================================================================');

  console.log('\n===== [8] 回调通知 =====');

  // 计算 sourceRunUrl：直接采用拼接方式
  // 路径格式：https://gitcode.com/{owner}/{repo}/actions/runs/{workflow_run_id}
  let sourceRunUrl = '';
  {
    const repoUrlForRun = process.env.ATOMGIT_REPOSITORY_URL || '';
    const workflowRunIdForUrl = workflowRunId || '';
    if (repoUrlForRun && workflowRunIdForUrl) {
      // 将仓库 URL 统一转为 https 形式：
      //   git@host:owner/repo.git   → https://host/owner/repo
      //   https://host/owner/repo.git → https://host/owner/repo
      //   ssh://git@host:22/owner/repo.git → https://host/owner/repo
      let httpsBase = repoUrlForRun.trim();
      const sshStyleMatch = httpsBase.match(/^git@([^:]+):(.+)$/);
      if (sshStyleMatch) {
        httpsBase = `https://${sshStyleMatch[1]}/${sshStyleMatch[2]}`;
      } else if (/^ssh:\/\//i.test(httpsBase)) {
        httpsBase = httpsBase.replace(/^ssh:\/\/[^@/]+@?/i, 'https://');
      }
      httpsBase = httpsBase.replace(/\.git$/, '');
      sourceRunUrl = `${httpsBase}/actions/runs/${workflowRunIdForUrl}`;
    }
  }

  // PR/MR 事件时用 base 分支（目标分支），其他事件用当前 ref
  const eventName = (process.env.ATOMGIT_EVENT_NAME || '').toLowerCase();
  const isPrEvent = eventName === 'mr'
  const branch = isPrEvent
    ? (process.env.ATOMGIT_HEAD_REF || '')
    : (process.env.ATOMGIT_REF_NAME || '');

  const callbackPayload = {
    repoUrl: process.env.ATOMGIT_REPOSITORY_URL || '',
    pipelineId: process.env.ATOMGIT_PIPELINE_ID || '',
    pipelineName: process.env.PIPELINE_NAME || '',
    pipelineRunId: workflowRunId || '',
    branch: branch,
    commitId: process.env.ATOMGIT_SHA || '',
    obsUrl: obsUrlValue,
    category: category || '',
    source: 'GITCODE_ACTION',
    sourceRunUrl: sourceRunUrl || ''
  };

  const apigAuthSummary = {
    hasAppKey: !!apigAppKey,
    hasAppSecret: !!apigAppSecret
  };
  console.log(`[INFO] APIG 鉴权: ${JSON.stringify(apigAuthSummary)}`);

  try {
    console.log(`[INFO] 回调地址: ${finalCallbackUrl}`);
    const callbackResult = await sendCallback(finalCallbackUrl, callbackPayload, apigAppKey, apigAppSecret);
    console.log(`[OK] 回调通知发送成功，回调时间: ${new Date().toISOString()}`);
    console.log(`[INFO] 回调响应: ${JSON.stringify(callbackResult)}`);
    const resultViewUrl = isBetaEnv ? 'https://beta.openlibing.com/apps/codeCheck' : 'https://www.openlibing.com/apps/codeCheck';
    console.log(`查看上传结果解析: ${resultViewUrl}`);
  } catch (cbErr) {
    console.log(`[WARN] 回调通知发送失败: ${cbErr.message}`);
    console.log('[INFO] SARIF 上传已成功，回调失败不影响最终结果');
  }

  setOutput('result', 'success');
}

run().catch(err => {
  const sanitizedMessage = sanitizePath(err.message);
  console.error(`Action 执行失败: ${sanitizedMessage}`);
  setOutput('result', 'failed');
  process.exit(1);
});
