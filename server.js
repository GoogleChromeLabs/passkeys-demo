// server.js
// where your node app starts

// init project
const express = require('express');
const cookieParser = require('cookie-parser');
const hbs = require('hbs');
const multer = require('multer');
const upload = multer();
const app = express();
app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');

// we've started you off with Express, 
// but feel free to use whatever libs or frameworks you'd like through `package.json`.

app.use(cookieParser());

// http://expressjs.com/en/starter/static-files.html
app.use(express.static('public'));

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', function(req, res) {
  if (req.cookies.id) {
    res.redirect(307, '/reauth');
    return;
  }
  // TODO: Check cookie
  // TODO: If user is not signed in, show `index.html` with id/password form.
  // TODO: If user is signed in, redirect to `/reauth`.
  // TODO: `index.html` shows id/password field along with "sign in" button.
  res.render('index.html');
});

app.post('/signin', upload.array(), function(req, res) {
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

app.get('/home', function(req, res) {
  // TODO: If user is not signed in, redirect to `/`.
  // TODO: If user is signed in, redirect to `/reauth`.
  // TODO: `home.html` shows sign-out link
  res.render('home.html', {id: req.cookies.id});
});

app.get('/signout', function(req, res) {
  // TODO: Remove cookie
  // TODO: Redirect to `/`
  
  res.render('logout.html');
});

app.get('/reauth', function(req, res) {
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  // TODO: When developed, do fingerprint reauth
  res.render('reauth.html', {id: req.cookies.id});
});

// listen for req :)
const listener = app.listen(process.env.PORT, function() {
  console.log('Your app is listening on port ' + listener.address().port);
});
