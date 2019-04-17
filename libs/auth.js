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
    res.send(400).send();
  } else {
    next();
  }
};

router.post('/signin', upload.array(), csrfCheck, (req, res) => {
  // If cookie doesn't contain an id, let in as long as `id` present (Ignore password)
  if (!req.body.id) {
    // If sign-in failed, return 401.
    res.status(401).send({
      error: 'invalid id'
    });
  // If cookie contains an id (already signed in, this is reauth), let the user sign-in
  } else {
    // If sign-in succeeded, redirect to `/home`.
    res.cookie('id', req.body.id);
    res.status(200).send({});
  }
});

router.post('/keys', upload.array(), csrfCheck, (req, res) => {
  const id = db.get('users')
    .find({ id: req.cookie.id })
    .value();
});

router.post('/removeKey', upload.array(), csrfCheck, (req, res) => {
  db.get('users')
    .push({ firstName: request.query.fName, lastName: request.query.lName })
    .write()
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
