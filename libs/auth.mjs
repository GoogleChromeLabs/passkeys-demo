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
import express from 'express';
const router = express.Router();
import crypto from 'crypto';
import fido2 from '@simplewebauthn/server';
import base64url from 'base64url';
import { Low, JSONFile } from 'lowdb';

const adapter = new JSONFile('.data/db.json');
const db = new Low(adapter);
await db.read();

router.use(express.json());

const RP_NAME = 'WebAuthn Codelab';
const TIMEOUT = 30 * 1000 * 60;

db.data ||= { users: [] } ;

function findUserByUsername(username) {
  const user = db.data.users.find(user => user.username === username);
  return user;
}

function findUserByUserId(user_id) {
  const user = db.data.users.find(user => user.id === user_id);
  return user;
}

async function updateUser(user) {
  let found = false;
  db.data.users = db.data.users.map(_user => {
    if (_user.id === user.id) {
      found = true;
      return user;
    } else {
      return _user;
    }
  });
  if (!found) {
    db.data.users.push(user);
  }
  return db.write();
}

const csrfCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    return res.status(400).json({ error: 'invalid access.' });
  }
  next();
};

/**
 * Checks CSRF protection using custom header `X-Requested-With`
 * If the session doesn't contain `signed-in`, consider the user is not authenticated.
 **/
const sessionCheck = (req, res, next) => {
  if (!req.session['signed-in']) {
    return res.status(401).json({ error: 'not signed in.' });
  }
  next();
};

const getOrigin = (userAgent) => {
  let origin = process.env.ORIGIN;
  
  const appRe = /^[a-zA-z0-9_.]+/;
  const match = userAgent.match(appRe);
  if (match) {
    // Check if UserAgent comes from a supported Android app.
    if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
      const package_names = process.env.ANDROID_PACKAGENAME.split(",").map(name => name.trim());
      const hashes = process.env.ANDROID_SHA256HASH.split(",").map(hash => hash.trim());
      const appName = match[0];
      for (let i = 0; i < package_names.length; i++) {
        if (appName === package_names[i]) {
          // We recognize this app, so use the corresponding hash.
          const octArray = hashes[i].split(':').map((h) =>
            parseInt(h, 16),
          );
          const androidHash = base64url.encode(octArray);
          origin = `android:apk-key-hash:${androidHash}`;
          break;
        }
      }
    }
  }
  
  return origin;
}

/**
 * Check username, create a new account if it doesn't exist.
 * Set a `username` in the session.
 **/
router.post('/username', async (req, res) => {
  const username = req.body.username;
console.log('[username] username', username);

  try {
     // Only check username, no need to check password as this is a mock
    if (username && /^[a-zA-Z0-9@\.\-_]+$/.test(username)) {
      // See if account already exists
      let user = findUserByUsername(username);
      // If user entry is not created yet, create one
      if (!user) {
        user = {
          username: username,
          displayName: username,
          id: base64url.encode(crypto.randomBytes(32)),
          credentials: [],
        };
        await updateUser(user);
      }
      // Set username in the session
      req.session.username = username;
      // If sign-in succeeded, redirect to `/home`.
      return res.json(user);
    } else {
      throw new Error('Invalid user name');
    }
  } catch (e) {
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

/**
 * Verifies user credential and let the user sign-in.
 * No preceding registration required.
 * This only checks if `username` is not empty string and ignores the password.
 **/
router.post('/password', (req, res) => {
  if (!req.body.password) {
    return res.status(401).json({ error: 'Enter at least one random letter.' });
  }
  const user = findUserByUsername(req.session.username);

  if (!user) {
    return res.status(401).json({ error: 'Enter username first.' });
  }

  req.session['signed-in'] = 'yes';
  return res.json(user);
});

router.post('/userinfo', csrfCheck, sessionCheck, (req, res) => {
  const user = findUserByUsername(req.session.username);
  return res.json(user);
});

router.post('/updateDisplayName', csrfCheck, sessionCheck, async (req, res) => {
  const { newName } = req.body;
  if (newName) {
    const user = findUserByUsername(req.session.username);
    user.displayName = newName;
    await updateUser(user);
    return res.json(user);
  } else {
    return res.status(400);
  }
});

router.get('/signout', (req, res) => {
  // Remove the session
  req.session.destroy()
  // Redirect to `/`
  return res.redirect(307, '/');
});

/**
 * Returns a credential id
 * (This server only stores one key per username.)
 * Response format:
 * ```{
 *   username: String,
 *   credentials: [Credential]
 * }```

 Credential
 ```
 {
   credId: String,
   publicKey: String,
   aaguid: ??,
   prevCounter: Int,
   name: String
 };
 ```
 **/
router.post('/getKeys', csrfCheck, sessionCheck, async (req, res) => {
  const user = findUserByUsername(req.session.username);
  return res.json(user || {});
});

router.post('/renameKey', csrfCheck, sessionCheck, async (req, res) => {
  const { credId, newName } = req.body;
  const username = req.session.username;
  const user = findUserByUsername(username);
  const newCreds = user.credentials.map(cred => {
    if (cred.credId === credId) {
console.log('[renameKey] credential renamed to:', newName);
      cred.name = newName;
    }
    return cred;
  });
  user.credentials = newCreds;
  await updateUser(user);
  return res.json({});
});

/**
 * Removes a credential id attached to the user
 * Responds with empty JSON `{}`
 **/
router.post('/removeKey', csrfCheck, sessionCheck, async (req, res) => {
  const credId = req.query.credId;
  const username = req.session.username;
  const user = findUserByUsername(username);

  const newCreds = user.credentials.filter((cred) => {
    // Leave credential ids that do not match
    return cred.credId !== credId;
  });
  user.credentials = newCreds;

  await updateUser(user);

  return res.json({});
});

router.get('/resetDB', async (req, res) => {
  db.data = { users: [] };
  await db.write();
  return res.json(db.data.users);
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
router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  const { username } = req.session;
  const user = findUserByUsername(username);
  try {
    const excludeCredentials = [];
    if (user.credentials.length > 0) {
      for (let cred of user.credentials) {
        excludeCredentials.push({
          id: base64url.toBuffer(cred.credId),
          type: 'public-key',
          transports: cred.transports,
        });
      }
    }
    const pubKeyCredParams = [];
    // const params = [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8];
    const params = [-7, -257];
    for (let param of params) {
      pubKeyCredParams.push({ type: 'public-key', alg: param });
    }
    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.residentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;
    let authenticatorSelection;
    let attestation = 'none';

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }
    if (rr && (rr == 'required' || rr === 'preferred' || rr === 'discouraged')) {
      asFlag = true;
      as.residentKey = rr;
    }
    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      authenticatorSelection = as;
    }
    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      attestation = cp;
    }

    const options = fido2.generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.id,
      userName: user.username,
      userDisplayName: user.displayName || user.username,
      timeout: TIMEOUT,
      // Prompt users for additional information about the authenticator.
      attestationType: attestation,
      // Prevent users from re-registering existing authenticators
      excludeCredentials,
      authenticatorSelection,
    });

    req.session.challenge = options.challenge;

    // Temporary hack until SimpleWebAuthn supports `pubKeyCredParams`
    options.pubKeyCredParams = [];
    for (let param of params) {
      options.pubKeyCredParams.push({ type: 'public-key', alg: param });
    }

    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).send({ error: e.message });
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
router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  const username = req.session.username;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credential = req.body;
  const { id: credId, type } = credential;

  try {

    const verification = await fido2.verifyRegistrationResponse({
      credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
    });

    const { verified, registrationInfo } = verification;

    if (!verified) {
      throw new Error('User verification failed.');
    }

    const { credentialPublicKey, credentialID, counter } = registrationInfo;
    const base64PublicKey = base64url.encode(credentialPublicKey);
    const base64CredentialID = base64url.encode(credentialID);

    const user = findUserByUsername(username);

    const existingCred = user.credentials.find(
      (cred) => cred.credID === base64CredentialID,
    );

    if (!existingCred) {
      /**
       * Add the returned device to the user's list of devices
       */
      user.credentials.push({
        publicKey: base64PublicKey,
        credId: base64CredentialID,
        name: credential.name || req.useragent.platform || 'Unknown platform',
        transports: credential.response.transports || []
      });
    }

    await updateUser(user);

    delete req.session.challenge;

    // Respond with user info
    return res.json(user);
  } catch (e) {
    delete req.session.challenge;
    console.error(e);
    return res.status(400).send({ error: e.message });
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
router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {
    const user = findUserByUsername(req.session.username);

    if (!user) {
      // Send empty response if user is not registered yet.
      res.status(400).json({ error: 'User not found.' });
      return;
    }

    const credId = req.query.credId;

    const userVerification = req.body.userVerification || 'required';

    const allowCredentials = [];
    for (let cred of user.credentials) {
      // `credId` is specified and matches
      if (credId && cred.credId == credId) {
        allowCredentials.push({
          id: base64url.toBuffer(cred.credId),
          type: 'public-key',
          transports: cred.transports
        });
      }
    }

    const options = await fido2.generateAuthenticationOptions({
      timeout: TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification,
    });
console.log('[discoveryRequest] options', options);
    req.session.challenge = options.challenge;

    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
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
router.post('/signinResponse', csrfCheck, async (req, res) => {
  const { body } = req;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;

  // Query the user
  const user = findUserByUsername(req.session.username);

  let credential = user.credentials.find(cred => cred.credId === req.body.id);
  
  credential.credentialPublicKey = base64url.toBuffer(credential.publicKey);
  credential.credentialID = base64url.toBuffer(credential.credId);
  credential.counter = credential.prevCounter;

  try {
    if (!credential) {
      throw new Error('Authenticating credential not found.');
    }

    const verification = await fido2.verifyAuthenticationResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator: credential,
    });

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      throw new Error('User verification failed.');
    }

    credential.prevCounter = authenticationInfo.newCounter;

    await updateUser(user);

    delete req.session.challenge;
    req.session['signed-in'] = 'yes';
    return res.json(user);
  } catch (e) {
    delete req.session.challenge;
    console.error(e);
    return res.status(400).json({ error: e.message });
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
router.post('/discoveryRequest', csrfCheck, async (req, res) => {
  try {
    const username = req.body.username;

console.log('[discoveryRequest] username', username);
    let user;
    if (username) {
      user = findUserByUsername(username);
      if (!user) {
        // Send empty response if user is not registered yet.
        res.status(400).json({ error: 'User not found.' });
        return;
      }
    }
    const userVerification = req.body.userVerification || 'preferred';
    let allowCredentials = [];
    if (user) {
      allowCredentials = user.credentials.map(cred => {
        return {
          id: base64url.toBuffer(cred.credId),
          type: 'public-key',
          transports: cred.transports,
        }
      });
    }
console.log('[discoveryRequest] allowCredentials', allowCredentials);
    const options = await fido2.generateAuthenticationOptions({
      timeout: TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification,
    });
    req.session.challenge = options.challenge;
console.log('[discoveryRequest] options', options);

    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
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
router.post('/discoveryResponse', csrfCheck, async (req, res) => {
  const { body: credential } = req;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;

  try {
    const user_id = credential.response.userHandle;
    const user = findUserByUserId(user_id);

console.log('[discoveryResponse] user', user);

    if (!user) {
      throw new Error('User not found.');
    }

    const auth = user.credentials.find((cred) => cred.credId === credential.id);

    if (!auth) {
      throw new Error('Credential not found.');
    }

    const authenticator = {
      credentialPublicKey: base64url.toBuffer(auth.publicKey),
      credentialID: base64url.toBuffer(auth.credId),
      counter: auth.prevCounter,
      transports: auth.transports,
    };

    const verification = await fido2.verifyAuthenticationResponse({
      credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator,
    });

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      throw new Error('User verification failed.');
    }

    auth.prevCounter = authenticatorInfo.newCounter;

    await updateUser(user);

    delete req.session.challenge;
    req.session.username = user.username;
    req.session['signed-in'] = 'yes';
    return res.json(user);
  } catch (e) {
    console.error(e);
    delete req.session.challenge;
    return res.status(400).json({ error: e.message });
  }
});

export { router as auth };
