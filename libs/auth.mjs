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
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import base64url from 'base64url';
import { Users, Credentials } from './db.mjs';
// import { Low } from 'lowdb';
// import { JSONFile } from 'lowdb/node'

// const adapter = new JSONFile('.data/db.json');
// const db = new Low(adapter);
// await db.read();

router.use(express.json());

const RP_NAME = 'Passkey Form Demo';
const TIMEOUT = 30 * 1000 * 60;

// db.data ||= { users: [] } ;

// function findUserByUsername(username) {
//   const user = db.data.users.find(user => user.username === username);
//   return user;
// }

// function findUserByUserId(user_id) {
//   const user = db.data.users.find(user => user.id === user_id);
//   return user;
// }

// async function updateUser(user) {
//   let found = false;
//   db.data.users = db.data.users.map(_user => {
//     if (_user.id === user.id) {
//       found = true;
//       return user;
//     } else {
//       return _user;
//     }
//   });
//   if (!found) {
//     db.data.users.push(user);
//   }
//   return db.write();
// }

function csrfCheck(req, res, next) {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    return res.status(400).json({ error: 'invalid access.' });
  }
  next();
};

/**
 * Checks CSRF protection using custom header `X-Requested-With`
 * If the session doesn't contain `signed-in`, consider the user is not authenticated.
 **/
function sessionCheck(req, res, next) {
  if (!req.session['signed-in'] || !req.session.username) {
    return res.status(401).json({ error: 'not signed in.' });
  }
  const user = Users.findByUsername(req.session.username);
  if (!user) {
    return res.status(401).json({ error: 'user not found.' });    
  }
  res.locals.user = user;
  next();
};

function getOrigin(userAgent) {
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
  const { username } = req.body;

  try {
     // Only check username, no need to check password as this is a mock
    if (username && /^[a-zA-Z0-9@\.\-_]+$/.test(username)) {
      // See if account already exists
      let user = Users.findByUsername(username);
      // If user entry is not created yet, create one
      if (!user) {
        user = {
          id: base64url.encode(crypto.randomBytes(32)),
          username,
          displayName: username,
        };
        await Users.update(user);
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
  const user = Users.findByUsername(req.session.username);

  if (!user) {
    return res.status(401).json({ error: 'Enter username first.' });
  }

  req.session['signed-in'] = 'yes';
  return res.json(user);
});

router.post('/userinfo', csrfCheck, sessionCheck, (req, res) => {
  const { user } = res.locals;
  return res.json(user);
});

router.post('/updateDisplayName', csrfCheck, sessionCheck, async (req, res) => {
  const { newName } = req.body;
  if (newName) {
    const { user } = res.locals;
    user.displayName = newName;
    await Users.update(user);
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
  const { user } = res.locals;
  const credentials = Credentials.findByUserId(user.id);
  return res.json(credentials || {});
});

router.post('/renameKey', csrfCheck, sessionCheck, async (req, res) => {
  const { credId, newName } = req.body;
  const { user } = res.locals;
  const credential = Credentials.findById(credId);
  console.log(user, credential);
  if (!user || user.id !== credential?.user_id) {
    return res.status(401).json({ error: 'User not authorized.' });
  }
  credential.name = newName;
  await Credentials.update(credential);
  return res.json(credential);
});

/**
 * Removes a credential id attached to the user
 * Responds with empty JSON `{}`
 **/
router.post('/removeKey', csrfCheck, sessionCheck, async (req, res) => {
  const credId = req.query.credId;
  const { user } = res.locals;

  await Credentials.remove(credId, user.id);

  return res.json({});
});

router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  const { user } = res.locals;
  try {
    const excludeCredentials = [];
    const credentials = Credentials.findByUserId(user.id);
    if (credentials.length > 0) {
      for (const cred of credentials) {
        excludeCredentials.push({
          id: base64url.toBuffer(cred.id),
          type: 'public-key',
          transports: cred.transports,
        });
      }
    }
    const pubKeyCredParams = [];
    const params = [-7, -257];
    for (const param of params) {
      pubKeyCredParams.push({ type: 'public-key', alg: param });
    }
    const authenticatorSelection = {
      authenticatorAttachment: 'platform',
      residentKey: true
    }
    const attestationType = 'none';

    const options = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.id,
      userName: user.username,
      userDisplayName: user.displayName || user.username,
      timeout: TIMEOUT,
      // Prompt users for additional information about the authenticator.
      attestationType,
      // Prevent users from re-registering existing authenticators
      excludeCredentials,
      authenticatorSelection,
    });

    req.session.challenge = options.challenge;

    // Temporary hack until SimpleWebAuthn supports `pubKeyCredParams`
    options.pubKeyCredParams = [];
    for (const param of params) {
      options.pubKeyCredParams.push({ type: 'public-key', alg: param });
    }

    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credential = req.body;
  const { id, type } = credential;

  try {

    const verification = await verifyRegistrationResponse({
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

    const { user } = res.locals;
    
    await Credentials.update({
      id: base64CredentialID,
      publicKey: base64PublicKey,
      name: req.useragent.platform,
      transports: credential.response.transports || [],
      user_id: user.id,
    });

    // const existingCred = user.credentials.find(
    //   (cred) => cred.credID === base64CredentialID,
    // );

    // if (!existingCred) {
    //   /**
    //    * Add the returned device to the user's list of devices
    //    */
    //   user.credentials.push({
    //     publicKey: base64PublicKey,
    //     credId: base64CredentialID,
    //     name: req.useragent.platform,
    //     transports: credential.response.transports || []
    //   });
    // }

    // await Users.update(user);

    delete req.session.challenge;

    // Respond with user info
    return res.json(user);
  } catch (e) {
    delete req.session.challenge;
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {
    const { username } = req.body;

    let allowCredentials = [];

    const user = Users.findByUsername(username);
    if (user) {
      const credentials = Credentials.findByUserId(user.id);
      allowCredentials = credentials.map(cred => {
        return {
          id: base64url.toBuffer(cred.id),
          type: 'public-key',
          transports: cred.transports,
        }
      });
    }

    const options = await generateAuthenticationOptions({
      timeout: TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      // userVerification,
    });
    req.session.challenge = options.challenge;

console.log('[discoveryRequest] options', options);

    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
});

router.post('/signinResponse', csrfCheck, async (req, res) => {
  const { body: credential } = req;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;

  try {
    const cred = Credentials.findById(credential.id);    
    const user = Users.findById(cred.user_id);

    if (!cred || !user) {
      throw new Error('Credential not found.');
    }

    const authenticator = {
      credentialPublicKey: base64url.toBuffer(cred.publicKey),
      credentialID: base64url.toBuffer(cred.id),
      counter: cred.prevCounter,
      transports: cred.transports,
    };

    const verification = await verifyAuthenticationResponse({
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
