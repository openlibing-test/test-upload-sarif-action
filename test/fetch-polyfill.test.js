'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { installFetchPolyfill } = require('../src/util/fetchPolyfill');

test('node16 无全局 fetch 时注入 polyfill，GET/POST 请求可用', async () => {
  const savedFetch = globalThis.fetch;
  globalThis.fetch = undefined; // 模拟 node16（无全局 fetch）
  try {
    installFetchPolyfill();
    assert.strictEqual(typeof globalThis.fetch, 'function');

    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ method: req.method, path: req.url, echo: body }));
      });
    });
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;
    const url = `http://127.0.0.1:${port}/oidc`;

    try {
      // GET（模拟 OIDC ID Token 申请）
      const getRes = await globalThis.fetch(url, {
        method: 'GET',
        headers: { Authorization: 'Bearer test-token' }
      });
      assert.strictEqual(getRes.status, 200);
      const getData = JSON.parse(await getRes.text());
      assert.strictEqual(getData.method, 'GET');
      assert.strictEqual(getData.path, '/oidc');

      // POST + JSON body（模拟 STS 换证 / APIG 上报）
      const postRes = await globalThis.fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ a: 1 })
      });
      assert.strictEqual(postRes.status, 200);
      const postData = JSON.parse(await postRes.text());
      assert.strictEqual(postData.method, 'POST');
      assert.strictEqual(postData.echo, '{"a":1}');
    } finally {
      server.close();
    }
  } finally {
    globalThis.fetch = savedFetch;
  }
});

test('node18+ 已有全局 fetch 时不覆盖', async () => {
  const savedFetch = globalThis.fetch;
  const marker = function markerFetch() {};
  globalThis.fetch = marker;
  try {
    installFetchPolyfill();
    assert.strictEqual(globalThis.fetch, marker);
  } finally {
    globalThis.fetch = savedFetch;
  }
});
