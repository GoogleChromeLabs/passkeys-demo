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

const csrfCheck = (req, res, next) => {
  console.log(req.header('X-Requested-With'));
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
  } else {
    next();
  }
};

router.post('/signin', upload.array(), csrfCheck, (req, res) => {
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
router.post('/putKey', upload.array(), csrfCheck, (req, res) => {
  if (!req.cookies.id) {
    res.status(400).json({error: 'not signed in.'});
    return;
  }
  const stab = {
    id: req.cookies.id,
    credential: 'deadbeef'
  };
  db.get('users')
    .push(stab)
    .write();
  res.json(stab);
});

router.post('/getKey', upload.array(), csrfCheck, (req, res) => {
  if (!req.cookies.id) {
    res.status(400).json({error: 'not signed in.'});
    return;
  }
  const user = db.get('users')
    .find({ id: req.cookies.id })
    .value();
  res.json(user);
});

router.post('/removeKey', upload.array(), csrfCheck, (req, res) => {
  if (!req.cookies.id) {
    rres.status(400).json({error: 'not signed in.'});
    return;
  }
  db.get('users')
    .find({ id: req.cookies.id })
    .remove()
    .write();
  res.json({});
});

router.post('/makeCred', upload.array(), csrfCheck, (req, res) => {
});

router.post('/regCred', upload.array(), csrfCheck, (req, res) => {
});

router.post('/getAsst', upload.array(), csrfCheck, (req, res) => {
});

router.post('/authAsst', upload.array(), csrfCheck, (req, res) => {
});

module.exports = router;
