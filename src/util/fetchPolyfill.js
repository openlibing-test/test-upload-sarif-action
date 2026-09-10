'use strict';

/**
 * 最小 fetch polyfill（基于 Node 内置 http/https，零第三方依赖）。
 *
 * 背景：GitCode 插件 runtime 为 node16（action.yml runs.using: node16），无全局 fetch。
 * @openlibing/huaweicloud-oidc-client 的 http.js 在全局 fetch 缺失时回退 require('undici')，
 * 而 undici 未随 ncc 打包产物内联，会导致 "Cannot find module 'undici'"。
 * 此处仅在全局 fetch 缺失时注入，覆盖 SDK sendRequest 的 POST APIG 上报（JSON body）。
 * 不影响 node18+（已有全局 fetch）的环境。
 */

const http = require('http');
const https = require('https');

/** fetch 响应兼容对象：status / headers.forEach / text() */
class PolyfillHeaders {
  constructor(raw) {
    this._raw = {};
    for (const k of Object.keys(raw || {})) {
      this._raw[k.toLowerCase()] = raw[k];
    }
  }
  forEach(cb) {
    for (const k of Object.keys(this._raw)) {
      cb(this._raw[k], k);
    }
  }
}

function installFetchPolyfill() {
  if (typeof globalThis.fetch === 'function') {
    return; // node 18+ 已有全局 fetch，无需注入
  }

  globalThis.fetch = function fetchPolyfill(url, options) {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const transport = urlObj.protocol === 'https:' ? https : http;
      const method = (options && options.method) || 'GET';
      const headers = Object.assign({}, options && options.headers);
      const body = options && options.body;
      if (body) {
        headers['Content-Length'] = Buffer.byteLength(body);
      }

      const req = transport.request({
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method,
        headers,
        timeout: 30000
      }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          resolve({
            status: res.statusCode,
            headers: new PolyfillHeaders(res.headers),
            text: () => Promise.resolve(raw)
          });
        });
      });

      req.on('error', (e) => reject(new Error(`${method} ${url}: ${e.message}`)));
      req.on('timeout', () => req.destroy(new Error(`fetch polyfill timeout after 30000ms: ${method} ${url}`)));
      if (body) {
        req.write(body);
      }
      req.end();
    });
  };
}

module.exports = { installFetchPolyfill };
