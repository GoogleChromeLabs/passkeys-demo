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
import { config } from '../config.js';

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
  user.rpId = config.hostname;
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
    return res.status(401).json({ message: 'User not authorized.' });
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
      rpName: config.rp_name,
      rpID: config.hostname,
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
    return res.status(400).send({ message: e.message });
  }
});

/**
 * Register a new passkey to the server.
 */
router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  // Set expected values.
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = config.associated_origins;
  const expectedRPID = config.hostname;
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
      publicKey: credentialPublicKey,
      id: credentialID,
    } = registrationInfo.credential;

    const {
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
    return res.status(400).send({ message: e.message });
  }
});

/**
 * Start authenticating the user.
 */
router.post('/signinRequest', csrfCheck, async (req, res) => {
  const allowCredentials = [];

  if (req.session['signed-in'] && req.session.username) {
    const user = await Users.findByUsername(req.session.username);
    if (!user) {
      return res.status(401).json({ error: 'Signed-in user not found.' });    
    }
    const credentials = await Credentials.findByUserId(user.id);
    for (const cred of credentials) {
      allowCredentials.push({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      });
    }
  }
  try {
    // Use SimpleWebAuthn's handy function to create a new authentication request.
    const options = await generateAuthenticationOptions({
      rpID: config.hostname,
      allowCredentials,
    });

    // Keep the challenge value in a session.
    req.session.challenge = options.challenge;

    return res.json(options)
  } catch (e) {
    console.error(e);

    return res.status(400).json({ message: e.message });
  }
});

/**
 * Verify the authentication request.
 */
router.post('/signinResponse', csrfCheck, async (req, res) => {
  // Set expected values.
  const response = req.body;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = config.associated_origins;
  const expectedRPID = config.hostname;

  try {
    // Find the matching credential from the credential ID
    const cred = await Credentials.findById(response.id);
    if (!cred) {
      delete req.session.challenge;

      const message = 'Matching credential not found. Try signing in with a password.';
      console.error(message);
      return res.status(404).json({ message });
    }

    // Find the matching user from the user ID contained in the credential.
    const user = await Users.findById(cred.user_id);
    if (!user) {
      throw new Error('User not found.');
    } else if (req.session['signed-in'] === 'yes' &&
        req.session.username !== user.username) {
      // If the user is trying to sign in as a different user, fail.
      throw new Error('Invalid sign-in attempt.');
    }

    // Decode ArrayBuffers and construct an authenticator object.
    const credential = {
      id: cred.id,
      publicKey: isoBase64URL.toBuffer(cred.publicKey),
      transports: cred.transports,
    };

    // Use SimpleWebAuthn's handy function to verify the authentication request.
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential,
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
