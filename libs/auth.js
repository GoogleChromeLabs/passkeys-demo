const express = require('express');
const router = express.Router();
const multer = require('multer');
const upload = multer();

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
  // Replace this `stab` with proper credential info to store
  const stab = {
    id: req.cookies.id,
    credential: req.body.credential
  };
  // Store user info
  // TODO: This only adds new entry. Figure out ways to update existing entry.
  db.get('users')
    .push(stab)
    .write();
  // Respond with user info
  res.json(stab);
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
