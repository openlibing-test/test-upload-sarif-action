const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');

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

function sendCallback(url, payload, apigAppKey, apigAppSecret, apigAppCode) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const data = JSON.stringify(payload);

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data, 'utf-8')
    };

    if (apigAppKey) headers['Appkey'] = apigAppKey;
    if (apigAppSecret) headers['AppSecret'] = apigAppSecret;
    if (apigAppCode) headers['X-Apig-AppCode'] = apigAppCode;

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
  const apigAppCode = getInput('apig_app_code');
  const callbackUrl = 'https://174e1b821a8446f38998a67186ba766e.apic.cn-southwest-2.huaweicloudapis.com/openlibing-codecheck/codescan/v1/result/receive';

  const repoName = process.env.ATOMGIT_REPOSITORY || process.env.GIT_REPOSITORY || '';
  const repoBaseName = repoName.split('/').pop() || 'unknown-repo';
  const now = new Date();
  const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}.${String(now.getHours()).padStart(2, '0')}`;
  const buildNumber = `${repoBaseName}/${dateStr}`;

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
    console.log(`[ERROR] SARIF 文件不存在: ${sarifFile}`);
    setOutput('result', 'failed');
    process.exit(1);
  }
  console.log(`[OK] SARIF 文件: ${resolvedSarifPath}`);

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
  console.log(`OBS 路径前缀: ${obsKeyPrefix}`);

  console.log('\n===== [5] 生成构建产物 JSON =====');
  const sarifFileName = path.basename(resolvedSarifPath);
  const sarifDownloadUrl = `${downloadUrlPrefix}/${sarifFileName}`;

  let buildResult = {
    type: 'build',
    buildings: [
      {
        name: sarifFileName,
        type: 'CodeQL代码检查结果（sarif）',
        downloadUrl: sarifDownloadUrl
      }
    ]
  };

  const buildResultDir = path.join(tmpDir, 'codeql-analyze-output');
  if (!fs.existsSync(buildResultDir)) {
    fs.mkdirSync(buildResultDir, { recursive: true });
  }
  const buildResultPath = path.join(buildResultDir, 'build-result.json');
  fs.writeFileSync(buildResultPath, JSON.stringify(buildResult, null, 2), 'utf-8');
  console.log(`[OK] 构建产物 JSON: ${buildResultPath}`);

  console.log('\n===== [6] 上传到 OBS =====');

  console.log(`[INFO] 上传构建产物目录: ${buildResultDir}`);
  try {
    exec(`${obsutilPath} cp "${buildResultDir}" "obs://${obsBucket}/${obsKeyPrefix}/" -r -f -acl=public-read -e="${obsWriteEndpoint}" -i="${obsAk}" -k="${obsSk}" -flat=true`);
  } catch (e1) {
    console.log(`[WARN] 构建产物目录上传失败: ${e1.message}`);
  }

  console.log(`[INFO] 上传 SARIF 文件: ${resolvedSarifPath}`);
  try {
    exec(`${obsutilPath} cp "${resolvedSarifPath}" "obs://${obsBucket}/${obsKeyPrefix}/" -f -acl=public-read -e="${obsWriteEndpoint}" -i="${obsAk}" -k="${obsSk}"`);
  } catch (e2) {
    console.log(`[ERROR] SARIF 文件上传失败: ${e2.message}`);
    console.log('[INFO] 检查 obsutil 错误详情:');
    try {
      exec(`cat /home/octopus/.obsutil_output/*.log 2>/dev/null | tail -50`);
    } catch (_) {}
    setOutput('result', 'failed');
    process.exit(1);
  }

  const buildResultUrl = `${downloadUrlPrefix}/build-result.json`;

  console.log('\n================================================================');
  console.log('[INFO] 上传成功');
  console.log(`构建产物 JSON: ${buildResultUrl}`);
  console.log(`SARIF 检查结果: ${sarifDownloadUrl}`);
  console.log('================================================================');

  console.log('\n===== [7] 回调通知 =====');

  const callbackPayload = {
    repoUrl: process.env.ATOMGIT_REPOSITORY_URL || '',
    pipelineId: process.env.ATOMGIT_PIPELINE_ID || '',
    pipelineName: process.env.PIPELINE_NAME || '',
    pipelineRunId: process.env.ATOMGIT_PIPELINE_RUN_ID || process.env.PIPELINE_RUN_ID || '',
    branch: process.env.ATOMGIT_REF_NAME || '',
    commitId: process.env.ATOMGIT_SHA || '',
    obsUrl: sarifDownloadUrl
  };

  const apigAuthSummary = {
    hasAppKey: !!apigAppKey,
    hasAppSecret: !!apigAppSecret,
    hasAppCode: !!apigAppCode
  };
  console.log(`[INFO] APIG 鉴权: ${JSON.stringify(apigAuthSummary)}`);
  console.log(`[INFO] 回调 payload: ${JSON.stringify(callbackPayload, null, 2)}`);

  try {
    const callbackResult = await sendCallback(callbackUrl, callbackPayload, apigAppKey, apigAppSecret, apigAppCode);
    console.log('[OK] 回调通知发送成功');
    console.log(`[INFO] 回调响应: ${JSON.stringify(callbackResult)}`);
  } catch (cbErr) {
    console.log(`[WARN] 回调通知发送失败: ${cbErr.message}`);
    console.log('[INFO] SARIF 上传已成功，回调失败不影响最终结果');
  }

  setOutput('result', 'success');
  setOutput('download_url', sarifDownloadUrl);
  setOutput('build_result_url', buildResultUrl);
}

run().catch(err => {
  const sanitizedMessage = sanitizePath(err.message);
  console.error(`Action 执行失败: ${sanitizedMessage}`);
  setOutput('result', 'failed');
  process.exit(1);
});
