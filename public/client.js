export const _fetch = async (path, payload = '') => {
  const headers = {
    'X-Requested-With': 'XMLHttpRequest'
  };
  if (payload && !(payload instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(payload);
  }
  try {
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
  } catch (e) {
    return Promise.reject({error: e});
  }
};

const encodeAuthenticatorAttestationResponse = (atts) => {
  const credential = {};
  if (atts.id)    credential.id =     atts.id;
  if (atts.type)  credential.type =   atts.type;
  if (atts.rawId) credential.rawId =  base64url.encode(atts.rawId);

  if (atts.response) {
    const clientDataJSON =
      base64url.encode(atts.response.clientDataJSON);
    const attestationObject =
      base64url.encode(atts.response.attestationObject);
    credential.response = {
      clientDataJSON,
      attestationObject
    };
  }
  return credential;
};

export const registerCredential = async (opts) => {
  if (!window.PublicKeyCredential) {
    console.info('WebAuthn not supported on this browser.');
    return Promise.resolve(null);
  }
  try {
    const UVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!UVPAA) {
      console.info('User Verifying Platform Authenticator not available.');
      return Promise.resolve(null);
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

    const parsedCred = await encodeAuthenticatorAttestationResponse(cred);

    return await _fetch('/auth/registerResponse' , parsedCred);
  } catch (e) {
    return Promise.reject({ error: e });
  }
};

const encodeAuthenticatorAssertionResponse = asst => {
  const credential = {};
  if (asst.id)    credential.id =     asst.id;
  if (asst.type)  credential.type =   asst.type;
  if (asst.rawId) credential.rawId =  base64url.encode(asst.rawId);

  if (asst.response) {
    const clientDataJSON =
      base64url.encode(asst.response.clientDataJSON);
    const authenticatorData =
      base64url.encode(asst.response.authenticatorData);
    const signature =
      base64url.encode(asst.response.signature);
    const userHandle =
      base64url.encode(asst.response.userHandle);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle
    };
  }
  return credential;
};

export const verifyAssertion = async (opts) => {
  if (!window.PublicKeyCredential) {
    console.info('WebAuthn not supported on this browser.');
    return Promise.resolve(null);
  }
  try {
    const UVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!UVPAA) {
      console.info('User Verifying Platform Authenticator not available.');
      return Promise.resolve(null);
    }

    const options = await _fetch('/auth/signinRequest');
    
    if (!options.challenge) {
      return;
    }

    options.challenge = base64url.decode(options.challenge);

    if (options.allowCredentials.length === 0) {
      console.info("Credential not stored on server side");
      return Promise.resolve(null);
    }
    for (let cred of options.allowCredentials) {
      cred.id = base64url.decode(cred.id);
    }

    const cred = await navigator.credentials.get({
      publicKey: options
    });

    const parsedCred = await encodeAuthenticatorAssertionResponse(cred);

    return await _fetch(`/auth/signinResponse`, parsedCred);
  } catch (e) {
    return Promise.reject({ error:'Authentication failed. Use password to sign-in.' });
  }
};

export const unregisterCredential = async (credId) => {
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};
