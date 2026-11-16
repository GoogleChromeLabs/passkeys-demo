/*
 * @license
 * Copyright 2026 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { app, REDIRECT_URL } from './server.mjs';

/**
 * Sends a single HTTP request without following redirects.
 */
function request(port, targetPath, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: targetPath,
        method,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

describe('redirect server', () => {
  let server;
  let port;

  before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        port = server.address().port;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  for (const targetPath of [
    '/',
    '/one-button',
    '/reauth',
    '/home',
    '/unknown/route',
    '/?utm_source=test',
    '/.well-known/passkey-endpoints',
    '/index.html',
  ]) {
    it(`redirects GET ${targetPath} with 308`, async () => {
      const res = await request(port, targetPath, 'GET');
      assert.strictEqual(res.statusCode, 308);
      assert.strictEqual(res.headers.location, REDIRECT_URL);
      assert.strictEqual(res.headers['x-powered-by'], undefined);
    });
  }

  for (const method of ['HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS']) {
    it(`preserves method with 308 for ${method} /auth/username`, async () => {
      const res = await request(port, '/auth/username', method);
      assert.strictEqual(res.statusCode, 308);
      assert.strictEqual(res.headers.location, REDIRECT_URL);
    });
  }

  for (const staticPath of [
    '/client.js',
    '/components.js',
    '/components-bundle.js',
    '/components-bundle.js.LICENSE.txt',
    '/styles-bundle.js',
    '/bundle.css',
    '/style.scss',
    '/favicon.svg',
    '/favicon.ico',
    '/robots.txt',
    '/.well-known/assetlinks.json',
    '/client.js?v=123',
    '/FAVICON.ICO',
  ]) {
    it(`returns 404 for static file ${staticPath}`, async () => {
      const res = await request(port, staticPath, 'GET');
      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.headers.location, undefined);
    });
  }
});
