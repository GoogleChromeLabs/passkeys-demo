/*
 * @license
 * Copyright 2019 Google Inc. All rights reserved.
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
export const $ = document.querySelector.bind(document);

export const _fetch = async (path, payload = '') => {
  const headers = {
    'X-Requested-With': 'XMLHttpRequest',
  };
  if (payload && !(payload instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: headers,
    body: payload,
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    throw new Error(result.error);
  }
};

class Loading {
  constructor() {
    this.progress = $('#progress');
  }
  start() {
    this.progress.indeterminate = true;    
  }
  stop() {
    this.progress.indeterminate = false;    
  }
}

export const loading = new Loading();

export const registerCredential = async (name, opts) => {
  const options = await _fetch('/auth/registerRequest', opts);

  options.user.id = base64url.decode(options.user.id);
  options.challenge = base64url.decode(options.challenge);

  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
    }
  }

  const cred = await navigator.credentials.create({
    publicKey: options,
  });

  const credential = {};
  credential.id = cred.id;
  credential.rawId = base64url.encode(cred.rawId);
  credential.type = cred.type;
  credential.name = name;

  if (cred.response) {
    const clientDataJSON =
      base64url.encode(cred.response.clientDataJSON);
    const attestationObject =
      base64url.encode(cred.response.attestationObject);
    let transports = [];
    if (cred.response.getTransports) {
      transports = cred.response.getTransports();
    }
    // If `getTransports` is not available, consider it's a platform authenticator
    if (transports.length === 0) {
      transports = ['internal'];
    }
    credential.response = {
      clientDataJSON,
      attestationObject,
      transports
    };
  }

  return await _fetch('/auth/registerResponse', credential);
};

let abortController;

export const authenticate = async (username) => {
  const opts = { username };
  const options = await _fetch('/auth/discoveryRequest', opts);
  
  if (abortController) {
    abortController.abort();
  }

  abortController = new AbortController();
  options.allowCredentials = [];
  options.challenge = base64url.decode(options.challenge);

  const cred = await navigator.credentials.get({
    publicKey: options,
    mediation: 'conditional',
    signal: abortController.signal
  });

  const credential = {};
  credential.id = cred.id;
  credential.type = cred.type;
  credential.rawId = base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON =
      base64url.encode(cred.response.clientDataJSON);
    const authenticatorData =
      base64url.encode(cred.response.authenticatorData);
    const signature =
      base64url.encode(cred.response.signature);
    const userHandle =
      base64url.encode(cred.response.userHandle);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };
  }

  return await _fetch(`/auth/discoveryResponse`, credential);
};

export const updateCredential = async (credId, newName) => {
  return _fetch(`/auth/renameKey`, { credId, newName });
}

export const unregisterCredential = async (credId) => {
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};
