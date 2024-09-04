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
export const $ = document.querySelector.bind(document);

/**
 * Sends a POST request with payload. Throws when the response is not 200.
 * @param path The endpoint path.
 * @param payload The payload JSON object.
 * @returns 
 */
export async function _fetch(path, payload = '') {
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

/**
 * Encode given buffer or decode given string with Base64URL.
 */
class base64url {
  static encode(buffer) {
    const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  static decode(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binStr = window.atob(base64);
    const bin = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bin[i] = binStr.charCodeAt(i);
    }
    return bin.buffer;
  }
}

if (PublicKeyCredential) {
  if (!PublicKeyCredential?.parseCreationOptionsFromJSON) {
    PublicKeyCredential.parseCreationOptionsFromJSON = (options) => {
      const user = {
        ...options.user,
        id: base64url.decode(options.user.id),
      };
      const challenge = base64url.decode(options.challenge);
      const excludeCredentials =
        options.excludeCredentials?.map((cred) => {
          return {
            ...cred,
            id: base64url.decode(cred.id),
          };
        }) ?? [];
      return {
        ...options,
        user,
        challenge,
        excludeCredentials,
      };
    };
  }

  if (!PublicKeyCredential?.parseRequestOptionsFromJSON) {
    PublicKeyCredential.parseRequestOptionsFromJSON = (options) => {
      const challenge = base64url.decode(options.challenge);
      const allowCredentials =
        options.allowCredentials?.map((cred) => {
          return {
            ...cred,
            id: base64url.decode(cred.id),
          };
        }) ?? [];
      return {
        ...options,
        allowCredentials,
        challenge,
      };
    };
  }

  if (!PublicKeyCredential.prototype.toJSON) {
    PublicKeyCredential.prototype.toJSON = function() {
      try {
        const id = this.id;
        const rawId = base64url.encode(this.rawId);
        const authenticatorAttachment = this.authenticatorAttachment;
        const clientExtensionResults = {};
        const type = this.type;
        // This is authentication.
        if (this.response.signature) {
          return {
            id,
            rawId,
            response: {
              authenticatorData: base64url.encode(this.response.authenticatorData),
              clientDataJSON: base64url.encode(this.response.clientDataJSON),
              signature: base64url.encode(this.response.signature),
              userHandle: base64url.encode(this.response.userHandle),
            },
            authenticatorAttachment,
            clientExtensionResults,
            type,
          };
        } else {
          return {
            id,
            rawId,
            response: {
              clientDataJSON: base64url.encode(this.response.clientDataJSON),
              attestationObject: base64url.encode(this.response.attestationObject),
              transports: this.response?.getTransports() || [],
            },
            authenticatorAttachment,
            clientExtensionResults,
            type,
          };
        }
      } catch (error) {
        console.error(error);
        throw error;
      }
    }
  }
}

/**
 * Indicate loading status using a material progress web component.
 */
class Loading {
  constructor() {
    this.progress = $('#progress');
  }
  start() {
    this.progress.indeterminate = true;
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = true);
    }
  }
  stop() {
    this.progress.indeterminate = false;
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = false);
    }
  }
}

export const loading = new Loading();

/**
 * Create and register a new passkey
 * @returns A promise that resolves with a server response.
 */
export async function registerCredential() {
  // Fetch passkey creation options from the server.
  const _options = await _fetch('/auth/registerRequest');

  // Base64URL decode some values
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(_options);

  // Use platform authenticator and discoverable credential
  options.authenticatorSelection = {
    authenticatorAttachment: 'platform',
    requireResidentKey: true
  }

  // Invoke WebAuthn create
  const cred = await navigator.credentials.create({
    publicKey: options,
  });

  const credential = cred.toJSON();

  // Obtain transports if they are available.
  const transports = cred.response.getTransports ? cred.response.getTransports() : [];
  credential.response.transports = transports;

  // Send the result to the server and return the promise.
  return await _fetch('/auth/registerResponse', credential);
};

/**
 * Authenticate with a passkey.
 * @param { boolean } conditional Set to `true` if this is for a conditional UI.
 * @returns A promise that resolves with a server response.
 */
export async function authenticate(conditional = false) {
  // Fetch passkey request options from the server.
  const _options = await _fetch('/auth/signinRequest');

  const options = PublicKeyCredential.parseRequestOptionsFromJSON(_options);

  // `allowCredentials` empty array invokes an account selector by discoverable credentials.
  options.allowCredentials = [];

  // Invoke WebAuthn get
  const cred = await navigator.credentials.get({
    publicKey: options,
    // Request a conditional UI
    mediation: conditional ? 'conditional' : 'optional'
  });

  const credential = cred.toJSON();

  // Send the result to the server and return the promise.
  return await _fetch(`/auth/signinResponse`, credential);
};

/**
 * Request to update the namme of a passkey.
 * @param { string } credId A Base64URL encoded credential ID of the passkey to unregister.
 * @param { string } newName A new name for the passkey.
 * @returns a promise that resolves with a server response.
 */
export async function updateCredential(credId, newName) {
  return _fetch(`/auth/renameKey`, { credId, newName });
}

/**
 * Request to unregister a passkey.
 * @param { string } credId A Base64URL encoded credential ID of the passkey to unregister.
 * @returns a promise that resolves with a server response.
 */
export async function unregisterCredential(credId) {
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};
