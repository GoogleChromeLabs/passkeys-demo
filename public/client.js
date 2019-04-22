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
      credentials: 'include',
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
    const signature =
      base64url.encode(atts.response.signature);
    const userHandle =
      base64url.encode(atts.response.userHandle);
    credential.response = {
      clientDataJSON,
      attestationObject,
      signature,
      userHandle
    };
  }
  return credential;
};

export const registerCredential = async (opts) => {
  if (!window.PublicKeyCredential) {
    throw 'WebAuthn not supported on this browser.';
  }
  try {
    const options = await _fetch('/auth/makeCred', opts);

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

    return await _fetch('/auth/regCred' , parsedCred);

  } catch (e) {
    console.error(e);
    return Promise.reject(e);
  }
};

export const verifyAssertion = async (opts) => {
};
