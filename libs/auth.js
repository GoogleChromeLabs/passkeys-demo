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

const sessionCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
  }
  if (!req.cookies.id) {
    res.status(400).json({error: 'not signed in.'});
    return;
  }
  next();
};

router.post('/signin', upload.array(), (req, res) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
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
});

// For tests
router.post('/putKey', upload.array(), sessionCheck, (req, res) => {
  if (!req.body.credential) {
    res.status(400).json({ error: 'invalid request' });
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

router.post('/getKey', upload.array(), sessionCheck, (req, res) => {
  const user = db.get('users')
    .find({ id: req.cookies.id })
    .value();
  res.json(user || {});
});

router.post('/removeKey', upload.array(), sessionCheck, (req, res) => {
  db.get('users')
    .remove({ id: req.cookies.id })
    .write();
  res.json({});
});

/**
 * Fetch required information before calling navigator.credential.create()
 * Return in format like:
 * {
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
     transports: [('ble'|'nfc'|'usb'|'internal'),...]
   }, ...],
   authenticatorSelection: {
     authenticatorAttachment: '',
     requireResidentKey: '',
     userVerification: ''
   },
   attestation: ''
 * }
 **/
router.post('/makeCred', upload.array(), sessionCheck, (req, res) => {
});

router.post('/regCred', upload.array(), sessionCheck, (req, res) => {
});

router.post('/getAsst', upload.array(), sessionCheck, (req, res) => {
});

router.post('/authAsst', upload.array(), sessionCheck, (req, res) => {
});

module.exports = router;
