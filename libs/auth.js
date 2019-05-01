const express = require('express');
const router = express.Router();
const multer = require('multer');
const upload = multer();
const base64url = require('base64url');
const crypto = require('crypto');

const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('.data/db.json');
const db = low(adapter);
                                                                                                                              
db.defaults({
  users: []
}).write();

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

const verifyCredential = (credential, challenge, origin) => {
  const attestationObject = credential.attestationObject;
  const authenticatorData = credential.authenticatorData;
  if (!attestationObject && !authenticatorData)
    throw 'Invalid request.';

  const clientDataJSON = credential.clientDataJSON;
  // const signature = credential.signature;
  // const userHandle = credential.userHandle;
  const clientData = JSON.parse(base64url.decode(clientDataJSON));

  if (clientData.challenge !== challenge)
    throw 'Wrong challenge code.';

  if (clientData.origin !== origin)
    throw 'Wrong origin.';

  // Temporary workaround for inmature CBOR
  // const buffer = base64url.toBuffer(attestationObject || authenticatorData);
  // const response = cbor.decodeAllSync(buffer)[0];

  const response = {};
  response.fmt = 'none';

  return response;
};

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
router.post('/putKey', upload.array(), sessionCheck, (req, res) => {
  if (!req.body.credential) {
    res.status(400).json({ error: 'invalid request' });
    return;
  }
  const username = req.cookies.username;
  const credId = req.body.credential;
  const user = db.get('users')
    .find({ username: username })
    .value();
  user.credentials.push({
    id: credId
  });

  db.get('users')
    .find({ username: username })
    .assign({ credentials: user.credentials })
    .write();

  res.json(user);
});

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
  const credId = req.body.credId;
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
router.post('/registerRequest', sessionCheck, (req, res) => {
  const username = req.cookies.username;
  const user = db.get('users')
    .find({ username: username })
    .value();

  const response = {};
  response.rp = {
    id: req.host,
    name: 'Polykart'
  };
  response.user = {
    displayName: 'No name',
    id: base64url(crypto.randomBytes(32)),
    name: username
  };
  response.pubKeyCredParams = [{
    type: 'public-key', alg: -7
  }];
  response.timeout = (req.body && req.body.timeout) || 1000 * 30;
  response.challenge = base64url(crypto.randomBytes(32));
  res.cookie('challenge', response.challenge);
  response.excludeCredentials = [];

  // Only specify `excludeCredentials` when reauthFlag is `false`
  if (user.credentials.length > 0) {
    for (let cred of user.credentials) {
      response.excludeCredentials.push({
        id: cred.id,
        type: 'public-key',
        transports: 'internal'
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
router.post('/registerResponse', upload.array(), sessionCheck, (req, res) => {
  const username = req.cookies.username;
  const challenge = req.cookies.challenge;
  const credId = req.body.id;
  const type = req.body.type;
  const credential = req.body.response;
  if (!credId || !type || !credential) {
    res.status(400).send('`response` missing in request');
    return;
  }

  try {
    const origin = `${req.schema}://${req.get('host')}`;
    const response = verifyCredential(credential, challenge, origin);

    switch (response.fmt) {
      case 'none':
      case 'packed':
        // Ignore attestation
        break;
      case 'fido-u2f':
      case 'android-safetynet':
      default:
        // Not implemented yet
        throw 'Attestation not supported';
    }

    // Store user info
    const user = db.get('users')
      .find({ username: username })
      .value();
    
    user.credentials.push({
      id: credId
    });

    db.get('users')
      .find({ username: username })
      .assign({ credentials: user.credentials })
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
router.post('/signinRequest', upload.array(), sessionCheck, (req, res) => {
  const credId = req.query.credId;
  if (!credId) {
    res.status(400).send('`credId` missing in request');
    return;
  }

  const user = db.get('users')
    .find({ username: req.cookies.username })
    .value();

  const response = {};
  response.userVerification = req.body.userVerification || 'preferred';
  response.challenge = base64url(crypto.randomBytes(32));
  res.cookie('challenge', response.challenge);
  response.allowCredentials = [];

  if (user.credentials.length > 0) {
    for (let cred of user.credentials) {
      response.allowCredentials.push({
        id: cred.id,
        type: 'public-key',
        transports: ['internal']
      });
    }
  }

  res.json(response);
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
router.post('/signinResponse', upload.array(), sessionCheck, (req, res) => {
  const credId = req.body.id;
  const type = req.body.type;
  const credential = req.body.response;
  if (!credId || !type || !credential) {
    res.status(400).send('`response` missing in request');
    return;
  }

  // Query the user
  const user = db.get('users')
    .find({ username: req.cookies.username })
    .value();

  try {
    const challenge = req.cookies.challenge;
    const origin = `${req.schema}://${req.get('host')}`;
    const response = verifyCredential(credential, challenge, origin);

    switch (response.fmt) {
      case 'none':
      case 'packed':
        // Ignore attestation
        break;
      case 'fido-u2f':
      case 'android-safetynet':
      default:
        // Not implemented yet
        throw 'Attestation not supported';
    }

    res.clearCookie('challenge');

    // TODO: Implement real verification
    for (let cred of user.credentials) {
      if (cred.id === credId) {
        res.json(user);
        return;
      }
    }
    res.status(400).send('Matching authenticator not found');
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }
});

module.exports = router;
