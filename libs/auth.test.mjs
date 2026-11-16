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

import { after, before, beforeEach, describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import express from 'express';

const collections = {
  users: new Map(),
  credentials: new Map(),
};

const fakeStore = {
  collection(name) {
    const docs = collections[name];
    assert.ok(docs, `Unexpected Firestore collection: ${name}`);
    return {
      where(field, op, value) {
        assert.strictEqual(op, '==');
        return {
          async get() {
            const matches = [];
            for (const entry of docs.values()) {
              if (entry[field] === value) {
                matches.push({ data: () => structuredClone(entry) });
              }
            }
            return matches;
          },
        };
      },
      doc(id) {
        if (!id) {
          throw new Error('Document reference requires a non-empty ID.');
        }
        return {
          async get() {
            const exists = docs.has(id);
            return {
              exists,
              data: () => (exists ? structuredClone(docs.get(id)) : undefined),
            };
          },
          async create(data) {
            if (docs.has(id)) {
              const error = new Error('Document already exists.');
              error.code = 6;
              throw error;
            }
            docs.set(id, structuredClone(data));
            return { writeTime: new Date() };
          },
          async set(data) {
            docs.set(id, structuredClone(data));
            return { writeTime: new Date() };
          },
          async delete() {
            docs.delete(id);
            return { writeTime: new Date() };
          },
        };
      },
    };
  },
};

const testConfig = {
  hostname: 'localhost',
  associated_origins: ['https://localhost:8080'],
};

mock.module('../config.js', {
  namedExports: {
    config: testConfig,
    store: fakeStore,
  },
});

const { Credentials } = await import('./db.mjs');
const authModule = await import('./auth.mjs');
const authRouter = authModule.auth ?? authModule.default;

/**
 * Minimal software passkey (ES256 / P-256) that produces a valid "none"
 * attestation payload so POST /auth/registerResponse exercises
 * `verifyRegistrationResponse()` end-to-end.
 */
class SoftwarePasskey {
  id = crypto.randomBytes(16).toString('base64url');
  #keys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  get cosePublicKey() {
    const { x = '', y = '' } = this.#keys.publicKey.export({ format: 'jwk' });
    return Buffer.concat([
      Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
      Buffer.from(x, 'base64url'),
      Buffer.from([0x22, 0x58, 0x20]),
      Buffer.from(y, 'base64url'),
    ]).toString('base64url');
  }

  register(clientData, credentialId = this.id) {
    const clientDataJSON = Buffer.from(JSON.stringify(clientData));
    const credentialIdBytes = Buffer.from(credentialId, 'base64url');
    const credentialIdLength = Buffer.alloc(2);
    credentialIdLength.writeUInt16BE(credentialIdBytes.length, 0);
    const cosePublicKeyBytes = Buffer.from(this.cosePublicKey, 'base64url');

    const authData = Buffer.concat([
      crypto.createHash('sha256').update(testConfig.hostname).digest(),
      Buffer.from([0x45]), // UP | UV | AT
      Buffer.alloc(4),
      Buffer.alloc(16), // zero AAGUID
      credentialIdLength,
      credentialIdBytes,
      cosePublicKeyBytes,
    ]);

    let bstrHeader;
    if (authData.length < 24) {
      bstrHeader = Buffer.from([0x40 | authData.length]);
    } else if (authData.length <= 0xff) {
      bstrHeader = Buffer.from([0x58, authData.length]);
    } else {
      bstrHeader = Buffer.from([
        0x59,
        authData.length >> 8,
        authData.length & 0xff,
      ]);
    }

    const attestationObject = Buffer.concat([
      Buffer.from([0xa3, 0x63]),
      Buffer.from('fmt'),
      Buffer.from([0x64]),
      Buffer.from('none'),
      Buffer.from([0x67]),
      Buffer.from('attStmt'),
      Buffer.from([0xa0, 0x68]),
      Buffer.from('authData'),
      bstrHeader,
      authData,
    ]);

    return {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        attestationObject: attestationObject.toString('base64url'),
        transports: ['internal'],
      },
    };
  }
}

describe('POST /auth/registerResponse credential ID uniqueness', () => {
  let server;
  let baseUrl;
  let mockSession;
  let currentUser;

  const victimUser = { id: 'victim-user-id', username: 'victim' };
  const attackerUser = { id: 'attacker-user-id', username: 'attacker' };
  const victimPasskey = new SoftwarePasskey();

  before(async () => {
    const app = express();
    app.use((req, res, next) => {
      req.session = mockSession;
      req.useragent = { platform: 'Linux' };
      next();
    });
    app.use('/auth', authRouter);

    await new Promise((resolve) => {
      server = http.createServer(app);
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address();
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    }
  });

  beforeEach(async () => {
    collections.users.clear();
    collections.credentials.clear();
    collections.users.set(victimUser.id, structuredClone(victimUser));
    collections.users.set(attackerUser.id, structuredClone(attackerUser));

    await Credentials.create({
      id: victimPasskey.id,
      publicKey: victimPasskey.cosePublicKey,
      name: 'Victim passkey',
      transports: ['internal'],
      aaguid: '00000000-0000-0000-0000-000000000000',
      created_on: 'Linux',
      registered: 1_700_000_000_000,
      last_used: null,
      be: true,
      user_id: victimUser.id,
    });

    currentUser = attackerUser;
    mockSession = {
      username: currentUser.username,
      'signed-in': 'yes',
      challenge: crypto.randomBytes(32).toString('base64url'),
    };
  });

  async function postRegisterResponse(payload) {
    collections.users.set(currentUser.id, structuredClone(currentUser));
    mockSession.username = currentUser.username;
    const res = await fetch(`${baseUrl}/auth/registerResponse`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: JSON.stringify(payload),
    });
    return { status: res.status, body: await res.json() };
  }

  it('registers a new passkey when the credential ID is unused', async () => {
    const freshPasskey = new SoftwarePasskey();
    const registration = freshPasskey.register({
      type: 'webauthn.create',
      challenge: mockSession.challenge,
      origin: testConfig.associated_origins[0],
    });

    const { status, body } = await postRegisterResponse(registration);

    assert.strictEqual(status, 200, JSON.stringify(body));
    assert.strictEqual(mockSession.challenge, undefined);

    const stored = await Credentials.findById(freshPasskey.id);
    assert.ok(stored);
    assert.strictEqual(stored.user_id, attackerUser.id);
    assert.strictEqual(stored.publicKey, freshPasskey.cosePublicKey);
  });

  it('rejects an attacker registering an existing credential ID from another user without overwriting it', async () => {
    const attackerPasskey = new SoftwarePasskey();
    const registration = attackerPasskey.register(
      {
        type: 'webauthn.create',
        challenge: mockSession.challenge,
        origin: testConfig.associated_origins[0],
      },
      victimPasskey.id
    );

    const { status, body } = await postRegisterResponse(registration);

    assert.strictEqual(status, 400);
    assert.strictEqual(body.message, 'Credential ID is already registered.');
    assert.strictEqual(mockSession.challenge, undefined);

    const victimStored = await Credentials.findById(victimPasskey.id);
    assert.ok(victimStored);
    assert.strictEqual(victimStored.user_id, victimUser.id);
    assert.strictEqual(victimStored.publicKey, victimPasskey.cosePublicKey);
  });

  it('rejects re-registration when the same user submits an existing credential ID', async () => {
    currentUser = victimUser;
    const replacementPasskey = new SoftwarePasskey();
    const registration = replacementPasskey.register(
      {
        type: 'webauthn.create',
        challenge: mockSession.challenge,
        origin: testConfig.associated_origins[0],
      },
      victimPasskey.id
    );

    const { status, body } = await postRegisterResponse(registration);

    assert.strictEqual(status, 400);
    assert.strictEqual(body.message, 'Credential ID is already registered.');
    assert.strictEqual(mockSession.challenge, undefined);

    const victimStored = await Credentials.findById(victimPasskey.id);
    assert.ok(victimStored);
    assert.strictEqual(victimStored.user_id, victimUser.id);
    assert.strictEqual(victimStored.publicKey, victimPasskey.cosePublicKey);
  });
});
