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
import express from 'express';
const router = express.Router();
import crypto from 'crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { Users, Credentials } from './db.mjs';
import aaguids from 'aaguid' with { type: 'json' };

router.use(express.json());

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
async function sessionCheck(req, res, next) {
  if (!req.session['signed-in'] || !req.session.username) {
    return res.status(401).json({ error: 'not signed in.' });
  }
  const user = await Users.findByUsername(req.session.username);
  if (!user) {
    return res.status(401).json({ error: 'user not found.' });    
  }
  res.locals.user = user;
  next();
};

/**
 * Get the expected origin that the user agent is claiming to be at. If the
 * requester is Android, construct an expected `origin` parameter.
 * @param { string } userAgent A user agent string used to check if it's a web browser.
 * @returns A string that indicates an expected origin.
 */
function getOrigin(userAgent) {
  let origin = process.env.ORIGIN;
  
  const appRe = /^[a-zA-z0-9_.]+/;
  const match = userAgent.match(appRe);
  if (match) {
    // Check if UserAgent comes from a supported Android app.
    if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
      // `process.env.ANDROID_PACKAGENAME` is expected to have a comma separated package names.
      const package_names = process.env.ANDROID_PACKAGENAME.split(",").map(name => name.trim());
      // `process.env.ANDROID_SHA256HASH` is expected to have a comma separated hash values.
      const hashes = process.env.ANDROID_SHA256HASH.split(",").map(hash => hash.trim());
      const appName = match[0];
      // Find and construct the expected origin string.
      for (let i = 0; i < package_names.length; i++) {
        if (appName === package_names[i]) {
          // We recognize this app, so use the corresponding hash.
          const octArray = hashes[i].split(':').map((h) =>
            parseInt(h, 16),
          );
          const androidHash = isoBase64URL.fromBuffer(octArray);
          origin = `android:apk-key-hash:${androidHash}`;
          break;
        }
      }
    }
  }
  
  return origin;
}

router.get('/aaguids', (req, res) => {
  if (Object.keys(aaguids).length === 0) {
    return res.json();
  }
  return res.json(aaguids);
});

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
      let user = await Users.findByUsername(username);
      // If user entry is not created yet, create one
      if (!user) {
        user = {
          id: isoBase64URL.fromBuffer(crypto.randomBytes(32)),
          username,
          displayName: username,
        };
        await Users.update(user);
      }
      // Set username in the session
      req.session.username = username;

      return res.json(user);
    } else {
      throw new Error('Invalid username');
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
router.post('/password', async (req, res) => {
  if (!req.body.password) {
    return res.status(401).json({ error: 'Enter at least one random letter.' });
  }
  const user = await Users.findByUsername(req.session.username);

  if (!user) {
    return res.status(401).json({ error: 'Enter username first.' });
  }

  req.session['signed-in'] = 'yes';
  return res.json(user);
});

/**
 * Response with user information.
 */
router.post('/userinfo', csrfCheck, sessionCheck, (req, res) => {
  const { user } = res.locals;
  return res.json(user);
});

/**
 * Update the user's display name.
 */
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

/**
 * Sign out the user.
 */
router.get('/signout', (req, res) => {
  // Remove the session
  req.session.destroy()
  // Redirect to `/`
  return res.redirect(307, '/');
});

/**
 * Respond with a list of stored credentials.
 */
router.post('/getKeys', csrfCheck, sessionCheck, async (req, res) => {
  const { user } = res.locals;
  const credentials = await Credentials.findByUserId(user.id);
  return res.json(credentials || []);
});

/**
 * Update the name of a passkey.
 */
router.post('/renameKey', csrfCheck, sessionCheck, async (req, res) => {
  const { credId, newName } = req.body;
  const { user } = res.locals;
  const credential = await Credentials.findById(credId);
  if (!user || user.id !== credential?.user_id) {
    return res.status(401).json({ error: 'User not authorized.' });
  }
  credential.name = newName;
  await Credentials.update(credential);
  return res.json(credential);
});

/**
 * Removes a credential id attached to the user.
 * Responds with empty JSON `{}`.
 **/
router.post('/removeKey', csrfCheck, sessionCheck, async (req, res) => {
  const credId = req.query.credId;
  const { user } = res.locals;

  await Credentials.remove(credId, user.id);

  return res.json({});
});

/**
 * Start creating a new passkey by serving registration options.
 */
router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  const { user } = res.locals;
  try {
    // Create `excludeCredentials` from a list of stored credentials.
    const excludeCredentials = [];
    const credentials = await Credentials.findByUserId(user.id);
    for (const cred of credentials) {
      excludeCredentials.push({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      });
    }
    // Set `authenticatorSelection`.
    const authenticatorSelection = {
      authenticatorAttachment: 'platform',
      requireResidentKey: true
    }
    const attestationType = 'none';

    // Use SimpleWebAuthn's handy function to create registration options.
    const options = await generateRegistrationOptions({
      rpName: process.env.RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: isoBase64URL.toBuffer(user.id),
      userName: user.username,
      userDisplayName: user.displayName || user.username,
      // Prompt users for additional information about the authenticator.
      attestationType,
      // Prevent users from re-registering existing authenticators
      excludeCredentials,
      authenticatorSelection,
    });

    // Keep the challenge value in a session.
    req.session.challenge = options.challenge;

    // Respond with the registration options.
    return res.json(options);
  } catch (e) {
    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

/**
 * Register a new passkey to the server.
 */
router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  // Set expected values.
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credential = req.body;

  try {

    // Use SimpleWebAuthn's handy function to verify the registration request.
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
    });

    const { verified, registrationInfo } = verification;

    // If the verification failed, throw.
    if (!verified) {
      throw new Error('User verification failed.');
    }

    const {
      credentialPublicKey,
      credentialID,
      aaguid = '00000000-0000-0000-0000-000000000000', 
      credentialDeviceType,
    } = registrationInfo;

    // Base64URL encode ArrayBuffers.
    const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);

    const { user } = res.locals;

    // Determine the name of the authenticator from the AAGUID.
    const name = (Object.keys(aaguids).length > 0 && aaguids[aaguid]?.name)
                  || req.useragent.platform;
    
    // Store the registration result.
    await Credentials.update({
      id: credentialID,
      publicKey: base64PublicKey,
      name,
      transports: credential.response.transports || [],
      aaguid,
      created_on: req.useragent.platform,
      registered: (new Date()).getTime(),
      last_used: null,
      be: credentialDeviceType === 'multiDevice',
      user_id: user.id,
    });

    // Delete the challenge from the session.
    delete req.session.challenge;

    // Respond with the user information.
    return res.json(user);
  } catch (e) {
    delete req.session.challenge;

    console.error(e);
    return res.status(400).send({ error: e.message });
  }
});

/**
 * Start authenticating the user.
 */
router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {
    // Use SimpleWebAuthn's handy function to create a new authentication request.
    const options = await generateAuthenticationOptions({
      rpID: process.env.HOSTNAME,
      allowCredentials: [],
    });

    // Keep the challenge value in a session.
    req.session.challenge = options.challenge;

    return res.json(options)
  } catch (e) {
    console.error(e);

    return res.status(400).json({ error: e.message });
  }
});

/**
 * Verify the authentication request.
 */
router.post('/signinResponse', csrfCheck, async (req, res) => {
  // Set expected values.
  const credential = req.body;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;

  try {

    // Find the matching credential from the credential ID
    const cred = await Credentials.findById(credential.id);
    if (!cred) {
      throw new Error('Matching credential not found on the server. Try signing in with a password.');
    }

    // Find the matching user from the user ID contained in the credential.
    const user = await Users.findById(cred.user_id);
    if (!user) {
      throw new Error('User not found.');
    }

    // Decode ArrayBuffers and construct an authenticator object.
    const authenticator = {
      credentialID: cred.id,
      credentialPublicKey: isoBase64URL.toBuffer(cred.publicKey),
      transports: cred.transports,
    };

    // Use SimpleWebAuthn's handy function to verify the authentication request.
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator,
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;

    // If the authentication failed, throw.
    if (!verified) {
      throw new Error('User verification failed.');
    }

    // Update the last used timestamp.
    cred.last_used = (new Date()).getTime();
    await Credentials.update(cred);

    // Delete the challenge from the session.
    delete req.session.challenge;

    // Start a new session.
    req.session.username = user.username;
    req.session['signed-in'] = 'yes';

    return res.json(user);
  } catch (e) {
    delete req.session.challenge;

    console.error(e);
    return res.status(400).json({ error: e.message });
  }
});

export { router as auth };
