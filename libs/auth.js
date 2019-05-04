const express = require('express');
const router = express.Router();
const multer = require('multer');
const upload = multer();
const base64url = require('base64url');
const crypto = require('crypto');
const { Fido2Lib } = require('fido2-lib');

const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('.data/db.json');
const db = low(adapter);

const f2l = new Fido2Lib({
    timeout: 30*1000*60,
    rpId: "webauthn-codelab-resolution.glitch.me", // TODO: Auto generate
    rpName: "WebAuthn Codelab",
    challengeSize: 32,
    cryptoParams: [-7]
});
                                                                                                                              
db.defaults({
  users: []
}).write();

const coerceToBase64Url = (thing, name) => {
    name = name || "''";

    // Array to Uint8Array
    if (Array.isArray(thing)) {
        thing = Uint8Array.from(thing);
    }

    // Uint8Array, etc. to ArrayBuffer
    if (typeof thing === "object" &&
                thing.buffer instanceof ArrayBuffer &&
                !(thing instanceof Buffer)) {
        thing = thing.buffer;
    }

    // ArrayBuffer to Buffer
    if (thing instanceof ArrayBuffer && !(thing instanceof Buffer)) {
        thing = new Buffer(thing);
    }

    // Buffer to base64 string
    if (thing instanceof Buffer) {
        thing = thing.toString("base64");
    }

    if (typeof thing !== "string") {
        throw new Error(`could not coerce '${name}' to string`);
    }

    // base64 to base64url
    // NOTE: "=" at the end of challenge is optional, strip it off here so that it's compatible with client
    thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");

    return thing;
}

const coerceToArrayBuffer = (buf, name) => {
    name = name || "''";

    if (typeof buf === "string") {
        // base64url to base64
        buf = buf.replace(/-/g, "+").replace(/_/g, "/");
        // base64 to Buffer
        buf = Buffer.from(buf, "base64");
    }

    // Buffer or Array to Uint8Array
    if (buf instanceof Buffer || Array.isArray(buf)) {
        buf = new Uint8Array(buf);
    }

    // Uint8Array to ArrayBuffer
    if (buf instanceof Uint8Array) {
        buf = buf.buffer;
    }

    // error if none of the above worked
    if (!(buf instanceof ArrayBuffer)) {
        throw new TypeError(`could not coerce '${name}' to ArrayBuffer`);
    }

    return buf;
}

/**
 * Checks CSRF protection using custom header `X-Requested-With`
 * If cookie doesn't contain `username`, consider the user is not authenticated.
 **/
const sessionCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
    return;
  }
  if (!req.cookies.username) {
    res.status(401).json({error: 'not signed in.'});
    return;
  }
  next();
};

// const verifyCredential = (credential, challenge, origin) => {
//   const attestationObject = credential.attestationObject;
//   const authenticatorData = credential.authenticatorData;
//   if (!attestationObject && !authenticatorData)
//     throw 'Invalid request.';

//   const clientDataJSON = credential.clientDataJSON;
//   // const signature = credential.signature;
//   // const userHandle = credential.userHandle;
//   const clientData = JSON.parse(base64url.decode(clientDataJSON));

//   if (clientData.challenge !== challenge)
//     throw 'Wrong challenge code.';

//   if (clientData.origin !== origin)
//     throw 'Wrong origin.';

//   // Temporary workaround for inmature CBOR
//   // const buffer = base64url.toBuffer(attestationObject || authenticatorData);
//   // const response = cbor.decodeAllSync(buffer)[0];

//   const response = {};
//   response.fmt = 'none';

//   return response;
// };

/**
 * Verifies user credential and let the user sign-in.
 * No preceding registration required.
 * This only checks if `username` is not empty string and ignores the password.
 **/
router.post('/signin', upload.array(), (req, res) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
    return;
  }
  const username = req.body.username;
  // If cookie doesn't contain a username, let in as long as `username` present (Ignore password)
  if (!username) {
    // If sign-in failed, return 401.
    res.status(400).json({error: 'invalid username.'});
  // If cookie contains a username (already signed in, this is reauth), let the user sign-in
  } else {
    // See if account already exists
    let user = db.get('users')
      .find({ username: username })
      .value();
    // If user entry is not created yet, create one
    if (!user) {
      user = {
        username: username,
        id: coerceToBase64Url(crypto.randomBytes(32)),
        credentials: []
      }
      db.get('users')
        .push(user)
        .write();
    }
    res.cookie('username', username);
    // If sign-in succeeded, redirect to `/home`.
    res.status(200).json(user);
  }
  return;
});

router.get('/signout', function(req, res) {
  // Remove cookie
  res.clearCookie('username');
  // Redirect to `/`
  res.redirect(307, '/');
});

// For test purposes
// router.post('/putKey', upload.array(), sessionCheck, (req, res) => {
//   if (!req.body.credential) {
//     res.status(400).json({ error: 'invalid request' });
//     return;
//   }
//   const username = req.cookies.username;
//   const credId = req.body.credential;
//   const user = db.get('users')
//     .find({ username: username })
//     .value();
//   user.credentials.push({
//     id: credId
//   });

//   db.get('users')
//     .find({ username: username })
//     .assign({ credentials: user.credentials })
//     .write();

//   res.json(user);
// });

/**
 * Returns a credential id
 * (This server only stores one key per username.)
 * Response format:
 * ```{
 *   username: String,
 *   credential: String
 * }```
 **/
router.post('/getKey', upload.array(), sessionCheck, (req, res) => {
  const user = db.get('users')
    .find({ username: req.cookies.username })
    .value();
  res.json(user || {});
});

/**
 * Removes a credential id attached to the user
 * Responds with empty JSON `{}`
 **/
router.post('/removeKey', upload.array(), sessionCheck, (req, res) => {
  const credId = req.query.credId;
  const username = req.cookies.username;
  const user = db.get('users')
    .find({ username: username })
    .value();

  const newCreds = user.credentials.filter(cred => {
    // Leave credential ids that do not match
    return cred.id !== credId;
  });

  db.get('users')
    .find({ username: username })
    .assign({ credentials: newCreds })
    .write();

  res.json({});
});

router.get('/resetDB', upload.array(), (req, res) => {
  db.set('users', [])
    .write();
  console.log('db reset');
  const users = db.get('users')
    .value();
  console.log(users);
  res.json(users);  
});

/**
 * Respond with required information to call navigator.credential.create()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     rp: {
       id: String,
       name: String
     },
     user: {
       displayName: String,
       id: String,
       name: String
     },
     publicKeyCredParams: [{  // @herrjemand
       type: 'public-key', alg: -7
     }],
     timeout: Number,
     challenge: String,
     excludeCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 * }```
 **/
router.post('/registerRequest', sessionCheck, async (req, res) => {
  const username = req.cookies.username;
  const user = db.get('users')
    .find({ username: username })
    .value();
  
  try {
    const response = await f2l.attestationOptions();
    
    response.user = {
      displayName: 'No name',
      id: user.id,
      name: user.username
    };
    response.challenge = coerceToBase64Url(response.challenge);
    res.cookie('challenge', response.challenge);
    response.excludeCredentials = [];

    if (user.credentials.length > 0) {
      for (let cred of user.credentials) {
        response.excludeCredentials.push({
          id: cred.id,
          type: 'public-key',
          transports: ['internal']
        });
      }
    }

    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.requireResidentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }
    if (rr && typeof rr == 'boolean') {
      asFlag = true;
      as.requireResidentKey = rr;
    }
    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      response.authenticatorSelection = as;
    }
    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      response.attestation = cp;
    }

    res.json(response);
  } catch (e) {
    res.status(400).send(e);
  }
});

/**
 * Register user credential.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       attestationObject: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post('/registerResponse', upload.array(), sessionCheck, async (req, res) => {
  const username = req.cookies.username;
  const challenge = coerceToArrayBuffer(req.cookies.challenge, 'challenge');
  const credId = req.body.id;
  const type = req.body.type;

  try {
    const clientAttestationResponse = { response: {} };
    clientAttestationResponse.rawId =
      coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAttestationResponse.response.clientDataJSON =
      coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAttestationResponse.response.attestationObject =
      coerceToArrayBuffer(req.body.response.attestationObject, "attestationObject");

    const attestationExpectations = {
      challenge: challenge,
      origin: `https://${req.get('host')}`,
      factor: "either"
    };

    const regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations);

    const credential = {
      credId: coerceToBase64Url(regResult.authnrData.get("credId")),
      publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
      aaguid: regResult.authnrData.get("aaguid"),
      prevCounter: regResult.authnrData.get("counter")
    };

    const user = db.get('users')
      .find({ username: username })
      .value();

    user.credentials.push(credential);

    db.get('users')
      .find({ username: username })
      .assign(user)
      .write();

    res.clearCookie('challenge');

    // Respond with user info
    res.json(user);
  } catch (e) {
    res.status(400).send(e);
  }
});

/**
 * Respond with required information to call navigator.credential.get()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     challenge: String,
     userVerification: ('required'|'preferred'|'discouraged'),
     allowCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...]
 * }```
 **/
router.post('/signinRequest', upload.array(), sessionCheck, async (req, res) => {
  try {
    const user = db.get('users')
      .find({ username: req.cookies.username })
      .value();

    const response = await f2l.assertionOptions();

    // const response = {};
    response.userVerification = req.body.userVerification || 'preferred';
    response.challenge = coerceToBase64Url(response.challenge);
    res.cookie('challenge', response.challenge);
    
    response.allowCredentials = [];

    for (let cred of user.credentials) {
      response.allowCredentials.push({
        id: cred.credId,
        type: 'public-key',
        transports: ['internal']
      });
    }

    res.json(response);
  } catch (e) {
    res.status(400).send(e);
  }
});

/**
 * Authenticate the user.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       authenticatorData: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post('/signinResponse', upload.array(), sessionCheck, async (req, res) => {
  const credId = req.body.id;

  // Query the user
  const user = db.get('users')
    .find({ username: req.cookies.username })
    .value();

  let credential = null;
  for (let cred of user.credentials) {
    if (cred.credId === req.body.id) {
      credential = cred;
    }
  }

  if (!credential) {
    res.status(400).send('Authenticating credential not found.');
    return;
  }

  try {
    const challenge = coerceToArrayBuffer(req.cookies.challenge);
    const origin = `https://${req.get('host')}`; // TODO: Temporary work around for scheme
    
    const clientAssertionResponse = { response: {} };
    clientAssertionResponse.rawId =
      coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAssertionResponse.response.clientDataJSON =
      coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAssertionResponse.response.authenticatorData =
      coerceToArrayBuffer(req.body.response.authenticatorData, "authenticatorData");
    clientAssertionResponse.response.signature =
      coerceToArrayBuffer(req.body.response.signature, "signature");
    clientAssertionResponse.response.userHandle =
      coerceToArrayBuffer(req.body.response.userHandle, "userHandle");
    const assertionExpectations = {
      challenge: challenge,
      origin: origin,
      factor: "either",
      publicKey: credential.publicKey,
      prevCounter: credential.prevCounter,
      userHandle: coerceToArrayBuffer(user.id)
    };
    const result = await f2l.assertionResult(clientAssertionResponse, assertionExpectations);

    res.clearCookie('challenge');

    credential.counter = result.authnrData.get("counter");
    
    db.get('users')
      .find({ id: req.cookies.id })
      .assign(user)
      .write();

    res.json(user);
  } catch (e) {
    res.status(400).send(e);
  }
});

module.exports = router;
