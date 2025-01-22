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
export async function post(path, payload = '') {
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
  if (res.ok) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    result.status = res.status;
    throw result;
  }
};

/**
 * Indicate loading status using a material progress web component.
 */
class Loading {
  constructor() {
    this.progress = $('#progress');
  }
  start() {
    this.progress.value = '';
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = true);
    }
  }
  stop() {
    this.progress.value = 0;
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = false);
    }
  }
}

export const loading = new Loading();
const metadata = {
  rpId: '',
  userId: '',
};

/**
 * Create and register a new passkey
 * @returns A promise that resolves with a server response.
 */
export async function registerCredential() {
  // Fetch passkey creation options from the server.
  const _options = await post('/auth/registerRequest');

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

  // Send the result to the server and return the promise.
  try {
    const result = await post('/auth/registerResponse', credential);
    return result;
  } catch (e) {
    // Detect if the credential was not found.
    if (PublicKeyCredential.signalUnknownCredential) {
      // Send a signal to delete the credential that was just created.
      await PublicKeyCredential.signalUnknownCredential({
        rpId: options.rp.id,
        credentialId: credential.id,
      });
      console.info('The passkey failed to register has been signaled to the password manager.');
    }
    throw e;
  }
};

/**
 * Authenticate with a passkey.
 * @param { boolean } conditional Set to `true` if this is for a conditional UI.
 * @returns A promise that resolves with a server response.
 */
export async function authenticate(conditional = false) {
  // Fetch passkey request options from the server.
  const _options = await post('/auth/signinRequest');

  const options = PublicKeyCredential.parseRequestOptionsFromJSON(_options);

  // Invoke WebAuthn get
  const cred = await navigator.credentials.get({
    publicKey: options,
    // Request a conditional UI
    mediation: conditional ? 'conditional' : 'optional'
  });

  const credential = cred.toJSON();

  try {
    // Send the result to the server and return the promise.
    const result = await post(`/auth/signinResponse`, credential);
    return result;
  } catch (e) {
    if (e.status === 404 && PublicKeyCredential.signalUnknownCredential) {
      await PublicKeyCredential.signalUnknownCredential({
        rpId: options.rpId,
        credentialId: credential.id,
      }).then(() => {
        console.info('The passkey associated with the credential not found has been signaled to the password manager.');
      }).catch(e => {
        console.error(e.message);
      });
    }
    throw e;
  }
};

/**
 * Request to update the namme of a passkey.
 * @param { string } credId A Base64URL encoded credential ID of the passkey to unregister.
 * @param { string } newName A new name for the passkey.
 * @returns a promise that resolves with a server response.
 */
export async function updateCredential(credId, newName) {
  return post(`/auth/renameKey`, { credId, newName });
}

/**
 * Request to unregister a passkey and signal the removed passkey so that the
 * password manager can delete it.
 * @param { string } credId A Base64URL encoded credential ID of the passkey to
 * unregister.
 * @returns a promise that resolves with undefined.
 */
export async function unregisterCredential(credId) {
  await post(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};

/**
 * Signal the list of credentials so the password manager can synchronize.
 * @param { object } credentials An array of credentials that contains a
 * Base64URL encoded credential ID.
 * @returns a promise that resolve with undefined.
 */
export async function getAllCredentials() {
  const credentials = await post('/auth/getKeys');
  if (PublicKeyCredential.signalAllAcceptedCredentials) {
    const credentialIds = credentials.map(cred => cred.id);
    await PublicKeyCredential.signalAllAcceptedCredentials({
      rpId: metadata.rpId,
      userId: metadata.userId, // base64url encoded user ID
      allAcceptedCredentialIds: credentialIds
    }).then(() => {
      console.info('Passkeys list have been signaled to the password manager.');
    }).catch(e => {
      console.error(e.message);
    });
  }
  return credentials;
}

/**
 * Signal the current user details so that password manager can synchronize passkeys' user info.
 * @param { string } rpId An RP ID string
 * @param { string } userId A Base64URL encoded user ID
 * @param { string } name A username
 * @param { string } displayName The user's display name
 * @returns a promise that resolve with undefined.
 */
export async function updateCurrentUserDetails(rpId, userId, name, displayName) {
  // This is an initialization
  metadata.rpId = rpId;
  metadata.userId = userId;
  if (PublicKeyCredential.signalCurrentUserDetails) {
    await PublicKeyCredential.signalCurrentUserDetails({
      rpId,
      userId,
      name,
      displayName,
    }).then(() => {
      console.info('User info attached to passkeys have been signaled to the password manager.');
    }).catch(e => {
      console.error(e.message);
    });
  }
}
