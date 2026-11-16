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

import { afterEach, describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';

const docs = new Map();
let nextAlreadyExistsCode = 6;

const fakeStore = {
  collection(name) {
    assert.strictEqual(name, 'credentials');
    return {
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
              error.code = nextAlreadyExistsCode;
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

mock.module('../config.js', {
  namedExports: {
    config: { hostname: 'localhost', associated_origins: ['http://localhost:8080'] },
    store: fakeStore,
  },
});

const { Credentials, CredentialAlreadyExistsError } = await import('./db.mjs');

let counter = 0;
function buildCredential(overrides = {}) {
  counter += 1;
  return {
    id: `cred-${counter}`,
    publicKey: `pubkey-${counter}`,
    name: 'Test passkey',
    transports: ['internal'],
    aaguid: '00000000-0000-0000-0000-000000000000',
    created_on: 'Linux',
    registered: 1_700_000_000_000 + counter,
    last_used: null,
    be: true,
    user_id: `user-${counter}`,
    ...overrides,
  };
}

describe('Credentials', () => {
  afterEach(() => {
    docs.clear();
    nextAlreadyExistsCode = 6;
  });

  it('creates and retrieves a credential by ID', async () => {
    const credential = buildCredential();
    await Credentials.create(credential);

    const stored = await Credentials.findById(credential.id);
    assert.deepStrictEqual(stored, credential);
  });

  it('returns undefined when looking up a missing or empty credential ID', async () => {
    assert.strictEqual(await Credentials.findById('missing-cred'), undefined);
    assert.strictEqual(await Credentials.findById(''), undefined);
    assert.strictEqual(await Credentials.findById(undefined), undefined);
  });

  it('rejects creating a credential with an empty ID', async () => {
    const credential = buildCredential({ id: '' });
    await assert.rejects(
      () => Credentials.create(credential),
      /Credential ID is required\./
    );
  });

  for (const code of [6, '6', 'already-exists']) {
    it(`rejects duplicate credential IDs (code ${JSON.stringify(code)}) and preserves the existing record`, async () => {
      nextAlreadyExistsCode = code;
      const victimCredential = buildCredential({
        user_id: 'victim-user',
        publicKey: 'victim-public-key',
        name: 'Victim passkey',
      });
      await Credentials.create(victimCredential);

      const attackerCredential = buildCredential({
        id: victimCredential.id,
        user_id: 'attacker-user',
        publicKey: 'attacker-public-key',
        name: 'Attacker passkey',
      });

      await assert.rejects(
        () => Credentials.create(attackerCredential),
        (error) => error instanceof CredentialAlreadyExistsError
      );

      const stored = await Credentials.findById(victimCredential.id);
      assert.deepStrictEqual(stored, victimCredential);
    });
  }

  it('allows only one create under concurrent writes for the same credential ID', async () => {
    const sharedId = 'race-cred';
    const first = buildCredential({
      id: sharedId,
      user_id: 'user-one',
      publicKey: 'pubkey-one',
    });
    const second = buildCredential({
      id: sharedId,
      user_id: 'user-two',
      publicKey: 'pubkey-two',
    });

    const results = await Promise.allSettled([
      Credentials.create(first),
      Credentials.create(second),
    ]);

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    assert.strictEqual(fulfilled.length, 1);
    assert.strictEqual(rejected.length, 1);
    assert.ok(rejected[0].reason instanceof CredentialAlreadyExistsError);

    const stored = await Credentials.findById(sharedId);
    assert.strictEqual(stored.user_id, 'user-one');
  });

  it('updates metadata on an existing credential without removing other fields', async () => {
    const credential = buildCredential({ name: 'Original passkey' });
    await Credentials.create(credential);

    const renamed = {
      ...credential,
      name: 'Renamed passkey',
      last_used: 1_700_000_009_999,
    };
    await Credentials.update(renamed);

    const stored = await Credentials.findById(credential.id);
    assert.deepStrictEqual(stored, renamed);
  });
});
