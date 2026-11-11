const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const INDEX_PATH = require.resolve('../index.js');
const ENV_PATTERN = /^(GITHUB_|ATOMGIT_|INPUT_|OBS_|STEP_OUTPUT$|WORKSPACE$|GIT_REPOSITORY$|PIPELINE_NAME$)/;

/**
 * 以指定环境变量重新加载 index.js。
 * index.js 的平台判定（IS_GITHUB / SOURCE_CODE / OBS 桶）在模块加载期求值，
 * 因此每个平台场景都需要清缓存后重新 require。
 */
function loadIndex(env) {
  for (const key of Object.keys(process.env)) {
    if (ENV_PATTERN.test(key)) {
      delete process.env[key];
    }
  }
  Object.assign(process.env, env || {});
  delete require.cache[INDEX_PATH];
  return require(INDEX_PATH);
}

test('GitCode 默认平台：来源标记与 GitCode OBS 桶', () => {
  const index = loadIndex({});
  assert.equal(index.IS_GITHUB, false);
  assert.equal(index.SOURCE_CODE, 'GITCODE_ACTION');
  assert.equal(index.OBS_BUCKET, 'openlibing-gitcode-action');
  assert.equal(index.OBS_READ_ENDPOINT, 'https://openlibing-gitcode-action.obs.cn-southwest-2.myhuaweicloud.com');
});

test('GitHub 平台：来源标记为 GITHUB_ACTION 且切换独立 OBS 桶', () => {
  const index = loadIndex({ GITHUB_ACTIONS: 'true' });
  assert.equal(index.IS_GITHUB, true);
  assert.equal(index.SOURCE_CODE, 'GITHUB_ACTION');
  assert.equal(index.OBS_BUCKET, 'openlibing-github-action');
  assert.equal(index.OBS_READ_ENDPOINT, 'https://openlibing-github-action.obs.cn-southwest-2.myhuaweicloud.com');
});

test('OBS 桶与读端点支持环境变量覆盖（两个平台一致）', () => {
  const ghIndex = loadIndex({
    GITHUB_ACTIONS: 'true',
    OBS_BUCKET_GITHUB: 'custom-gh-bucket',
    OBS_READ_ENDPOINT: 'https://custom.example.com'
  });
  assert.equal(ghIndex.OBS_BUCKET, 'custom-gh-bucket');
  assert.equal(ghIndex.OBS_READ_ENDPOINT, 'https://custom.example.com');

  const gcIndex = loadIndex({ OBS_BUCKET: 'custom-gc-bucket' });
  assert.equal(gcIndex.OBS_BUCKET, 'custom-gc-bucket');
});

test('getInput 同时兼容下划线与连字符输入名', () => {
  const index = loadIndex({
    INPUT_OBS_SSL_CA_FILE: '/tmp/underscore.pem',
    'INPUT_OBS-SSL-CA-FILE': '/tmp/dash.pem',
    'INPUT_ENV-TYPE': ' beta '
  });
  assert.equal(index.getInput('obs_ssl_ca_file'), '/tmp/underscore.pem');
  assert.equal(index.getInput('env_type'), 'beta');

  const dashOnly = loadIndex({ 'INPUT_SARIF-FILE': 'a.sarif' });
  assert.equal(dashOnly.getInput('sarif_file'), 'a.sarif');
});

test('setOutput 优先写入 GITHUB_OUTPUT', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gh-output-'));
  const outputFile = path.join(dir, 'output.txt');
  const index = loadIndex({ GITHUB_OUTPUT: outputFile });
  index.setOutput('result', 'success');
  assert.equal(fs.readFileSync(outputFile, 'utf-8'), 'result=success\n');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('setOutput 在无输出环境变量时静默跳过', () => {
  const index = loadIndex({});
  assert.doesNotThrow(() => index.setOutput('result', 'success'));
});

test('buildSourceRunUrl 按平台拼装运行页链接', () => {
  const ghIndex = loadIndex({
    GITHUB_ACTIONS: 'true',
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: 'openlibing-test/upload-sarif-action',
    GITHUB_RUN_ID: '12345'
  });
  assert.equal(
    ghIndex.buildSourceRunUrl(),
    'https://github.com/openlibing-test/upload-sarif-action/actions/runs/12345'
  );

  const gcIndex = loadIndex({
    ATOMGIT_REPOSITORY_URL: 'https://gitcode.com/openlibing/upload-sarif-action',
    ATOMGIT_RUN_ID: '889'
  });
  assert.equal(
    gcIndex.buildSourceRunUrl(),
    'https://gitcode.com/openlibing/upload-sarif-action/actions/runs/889'
  );
});

test('resolveBranch 按事件类型取分支名', () => {
  const ghPr = loadIndex({
    GITHUB_ACTIONS: 'true',
    GITHUB_EVENT_NAME: 'pull_request',
    GITHUB_BASE_REF: 'main',
    GITHUB_REF_NAME: 'feat-x'
  });
  assert.equal(ghPr.resolveBranch(), 'main');

  const ghPush = loadIndex({
    GITHUB_ACTIONS: 'true',
    GITHUB_EVENT_NAME: 'push',
    GITHUB_REF_NAME: 'feat-x'
  });
  assert.equal(ghPush.resolveBranch(), 'feat-x');

  const gcMr = loadIndex({ ATOMGIT_EVENT_NAME: 'mr', ATOMGIT_HEAD_REF: 'fix-y', ATOMGIT_REF_NAME: 'ignore' });
  assert.equal(gcMr.resolveBranch(), 'fix-y');

  const gcPush = loadIndex({ ATOMGIT_EVENT_NAME: 'push', ATOMGIT_REF_NAME: 'dev' });
  assert.equal(gcPush.resolveBranch(), 'dev');
});

test('resolvePlatformContext 映射两套上下文变量', () => {
  const ghIndex = loadIndex({
    GITHUB_ACTIONS: 'true',
    GITHUB_RUN_ID: '100',
    GITHUB_JOB: 'pre-commit',
    GITHUB_WORKFLOW: 'gitleaks-precommit',
    GITHUB_SHA: 'abc123'
  });
  assert.deepEqual(ghIndex.resolvePlatformContext(), {
    pipelineRunId: '100',
    pipelineId: 'pre-commit',
    pipelineName: 'gitleaks-precommit',
    commitId: 'abc123'
  });

  const gcIndex = loadIndex({
    ATOMGIT_RUN_ID: '200',
    ATOMGIT_PIPELINE_ID: 'p-1',
    PIPELINE_NAME: '流水线',
    ATOMGIT_SHA: 'def456'
  });
  assert.deepEqual(gcIndex.resolvePlatformContext(), {
    pipelineRunId: '200',
    pipelineId: 'p-1',
    pipelineName: '流水线',
    commitId: 'def456'
  });
});

test('resolveWorkspace / resolveRepoBaseName / buildCallbackRepoUrl 跨平台取值', () => {
  const ghIndex = loadIndex({
    GITHUB_ACTIONS: 'true',
    GITHUB_WORKSPACE: '/github/workspace',
    GITHUB_REPOSITORY: 'openlibing-test/upload-sarif-action',
    GITHUB_SERVER_URL: 'https://github.com'
  });
  assert.equal(ghIndex.resolveWorkspace(), '/github/workspace');
  assert.equal(ghIndex.resolveRepoBaseName(), 'upload-sarif-action');
  assert.equal(ghIndex.buildCallbackRepoUrl(), 'https://github.com/openlibing-test/upload-sarif-action');

  const gcIndex = loadIndex({
    WORKSPACE: '/gitcode/workspace',
    ATOMGIT_REPOSITORY: 'openlibing/upload-sarif-action',
    ATOMGIT_REPOSITORY_URL: 'https://gitcode.com/openlibing/upload-sarif-action'
  });
  assert.equal(gcIndex.resolveWorkspace(), '/gitcode/workspace');
  assert.equal(gcIndex.resolveRepoBaseName(), 'upload-sarif-action');
  assert.equal(gcIndex.buildCallbackRepoUrl(), 'https://gitcode.com/openlibing/upload-sarif-action');
});

test('GitHub 缺少仓库信息时回调地址为空字符串', () => {
  const index = loadIndex({ GITHUB_ACTIONS: 'true' });
  assert.equal(index.buildCallbackRepoUrl(), '');
});
