export const _fetch = async (path, payload = '') => {
  const headers = {
    'X-Requested-With': 'XMLHttpRequest'
  };
  if (payload && !(payload instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: headers,
    body: payload
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    throw result.error;
  }
};

export const registerCredential = async (opts) => {
  if (!window.PublicKeyCredential) {
    throw 'WebAuthn not supported on this browser.';
  }
  const UVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (!UVPAA) {
    throw 'User Verifying Platform Authenticator not available.';
  }

  const options = await _fetch('/auth/registerRequest', opts);

  options.user.id = base64url.decode(options.user.id);
  options.challenge = base64url.decode(options.challenge);

  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
    }
  }

  const cred = await navigator.credentials.create({
    publicKey: options
  });

  const credential = {};
  credential.id =     cred.id;
  credential.type =   cred.type;
  credential.rawId =  base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON =
      base64url.encode(cred.response.clientDataJSON);
    const attestationObject =
      base64url.encode(cred.response.attestationObject);
    credential.response = {
      clientDataJSON,
      attestationObject
    };
  }

  return await _fetch('/auth/registerResponse' , credential);
};

export const authenticate = async (opts) => {
  if (!window.PublicKeyCredential) {
    console.info('WebAuthn not supported on this browser.');
    return Promise.resolve(null)
  }
  const UVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (!UVPAA) {
    console.info('User Verifying Platform Authenticator not available.');
    return Promise.resolve(null);
  }

  const options = await _fetch('/auth/signinRequest', opts);

  options.challenge = base64url.decode(options.challenge);

  for (let cred of options.allowCredentials) {
    cred.id = base64url.decode(cred.id);
  }

  const cred = await navigator.credentials.get({
    publicKey: options
  });

  const credential = {};
  credential.id =     cred.id;
  credential.type =   cred.type;
  credential.rawId =  base64url.encode(cred.rawId);

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
      userHandle
    };
  }

  return await _fetch(`/auth/signinResponse`, credential);
};

export const unregisterCredential = async (credId) => {
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};
