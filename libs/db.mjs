/*
 * @license
 * Copyright 2023 Google Inc. All rights reserved.
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
import { store } from '../config.js';

/**
 * User data schema
 * {
 *   id: string Base64URL encoded user ID,
 *   username: string username,
 *   displayName: string display name,
 * }
 **/

export const Users = {
  findById: async (user_id) => {
    const doc = await store.collection('users').doc(user_id).get();
    if (doc) {
      const credential = doc.data();
      return credential;
    } else {
      return;
    }
  },

  findByUsername: async (username) => {
    const results = [];
    const refs = await store.collection('users')
      .where('username', '==', username).get();
    if (refs) {
      refs.forEach(user => results.push(user.data()));
    }
    return results.length > 0 ? results[0] : undefined;
  },

  update: async (user) => {
    const ref = store.collection('users').doc(user.id);
      return ref.set(user);
  }
}

/**
 * User data schema
 * {
 *   id: string Base64URL encoded CredentialID,
 *   publicKey: string Base64URL encoded PublicKey,
 *   name: string name of the credential,
 *   transports: an array of transports,
 *   registered: timestamp,
 *   last_used: timestamp,
 *   user_id: string Base64URL encoded user ID of the owner,
 * }
 **/

function isFirestoreAlreadyExistsError(error) {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return false;
  }
  const { code } = error;
  return code === 6 || code === '6' || code === 'already-exists';
}

/**
 * Error thrown when attempting to register a passkey whose credential ID
 * already exists in Firestore.
 */
export class CredentialAlreadyExistsError extends Error {
  constructor(message = 'Credential ID is already registered.') {
    super(message);
    this.name = 'CredentialAlreadyExistsError';
  }
}

export const Credentials = {
  findById: async (credential_id) => {
    if (!credential_id) {
      return;
    }
    const doc = await store.collection('credentials').doc(credential_id).get();
    if (!doc.exists) {
      return;
    }
    return doc.data();
  },

  findByUserId: async (user_id) => {
    const results = [];
    const refs = await store.collection('credentials')
      .where('user_id', '==', user_id)
      .orderBy('registered', 'desc').get();
    refs.forEach(cred => results.push(cred.data()));
    return results;
  },

  /**
   * Stores a newly registered passkey credential in Firestore.
   *
   * Uses Firestore's atomic `create()` operation so an existing document with
   * the same `credential.id` can never be overwritten, even under concurrent
   * registration requests (WebAuthn Section 7.1 step 26).
   *
   * @param {object} credential The passkey credential record to store.
   * @returns {Promise<FirebaseFirestore.WriteResult>}
   * @throws {Error} When `credential.id` is empty.
   * @throws {CredentialAlreadyExistsError} When a credential with the same ID already exists.
   */
  create: async (credential) => {
    if (!credential?.id) {
      throw new Error('Credential ID is required.');
    }
    const ref = store.collection('credentials').doc(credential.id);
    try {
      return await ref.create(credential);
    } catch (error) {
      if (isFirestoreAlreadyExistsError(error)) {
        throw new CredentialAlreadyExistsError();
      }
      throw error;
    }
  },

  /**
   * Updates metadata (such as key name or `last_used`) on an existing passkey
   * credential record. Do not use this for new registrations; use
   * `Credentials.create` instead so duplicate IDs fail closed.
   */
  update: async (credential) => {
    const ref = store.collection('credentials').doc(credential.id);
    return ref.set(credential);
  },
  
  remove: async (credential_id, user_id) => {
    const ref = store.collection('credentials').doc(credential_id);
    return ref.delete();
  }
}
