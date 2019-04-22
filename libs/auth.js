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
 * If cookie doesn't contain `id`, consider the user is not authenticated.
 **/
const sessionCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
    return;
  }
  if (!req.cookies.id) {
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
 * This only checks if `id` is not empty string and ignores the password.
 **/
router.post('/signin', upload.array(), (req, res) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
    return;
  }
  // If cookie doesn't contain an id, let in as long as `id` present (Ignore password)
  if (!req.body.id) {
    // If sign-in failed, return 401.
    res.status(400).json({error: 'invalid id.'});
  // If cookie contains an id (already signed in, this is reauth), let the user sign-in
  } else {
    // If sign-in succeeded, redirect to `/home`.
    res.cookie('id', req.body.id);
    res.status(200).json({});
  }
  return;
});

// For test purposes
router.post('/putKey', upload.array(), sessionCheck, (req, res) => {
  if (!req.body.credential) {
    res.status(400).json({ error: 'invalid request' });
    return;
  }
  const stab = {
    id: req.cookies.id,
    credential: req.body.credential
  };
  db.get('users')
    .push(stab)
    .write();
  res.json(stab);
});

/**
 * Returns a credential id
 * (This server only stores one key per user id.)
 * Response format:
 * ```{
 *   id: String,
 *   credential: String
 * }```
 **/
router.post('/getKey', upload.array(), sessionCheck, (req, res) => {
  const user = db.get('users')
    .find({ id: req.cookies.id })
    .value();
  res.json(user || {});
});

/**
 * Removes a credential id attached to the user
 * Responds with empty JSON `{}`
 **/
router.post('/removeKey', upload.array(), sessionCheck, (req, res) => {
  db.get('users')
    .remove({ id: req.cookies.id })
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
router.post('/makeCred', upload.array(), sessionCheck, (req, res) => {
  const user = db.get('users')
    .find({ id: req.cookies.id })
    .value();

  const response = {};
  response.rp = {
    id: req.host,
    name: 'Polykart'
  };
  response.user = {
    displayName: 'No name',
    id: base64url(crypto.randomBytes(32)),
    name: user.id
  };
  response.pubKeyCredParams = [{
    type: 'public-key', alg: -7
  }];
  response.timeout = req.body.timeout || 1000 * 30;
  response.challenge = base64url(crypto.randomBytes(32));
  req.cookie('challenge', response.challenge);

  // Only specify `excludeCredentials` when reauthFlag is `false`
  if (!user.credential) {
    response.excludeCredentials.push({
      id: user.credential,
      type: 'public-key',
      transports: 'internal'
    });
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
router.post('/regCred', upload.array(), sessionCheck, (req, res) => {
  const credId = req.body.id;
  const type = req.body.type;
  const credential = req.body.response;
  if (!credId || !type || !credential) {
    res.status(400).send('`response` missing in request');
    return;
  }

  try {
    const challenge = req.cookies.challenge;
    const origin = `${req.protocol}://${req.get('host')}`;
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

    // Replace this `stab` with proper credential info to store
    const user = {
      id: req.cookies.id,
      credential: credId
    };
    // Store user info
    // TODO: This only adds new entry. Figure out ways to update existing entry.
    db.get('users')
      .push(user)
      .write();
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
router.post('/getAsst', upload.array(), sessionCheck, (req, res) => {
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
router.post('/authAsst', upload.array(), sessionCheck, (req, res) => {
  // Query the user
  const user = db.get('users')
    .find({ id: req.cookies.id })
    .value();

  // TODO: Verify the signature against public key included in the user info

  // Respond with user info if verified. Otherwise error.
  res.json(user || {});
});

module.exports = router;
