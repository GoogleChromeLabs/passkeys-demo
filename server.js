// server.js
// where your node app starts

// init project
const express = require('express');
const cookieParser = require('cookie-parser');
const hbs = require('hbs');
const auth = require('./libs/auth');
const app = express();

app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', function(req, res) {
  // Check cookie
  if (req.cookies.id) {
    // If user is signed in, redirect to `/reauth`.
    res.redirect(307, '/reauth');
    return;
  }
  // If user is not signed in, show `index.html` with id/password form.
  res.render('index.html');
});

app.get('/home', function(req, res) {
  if (!req.cookies.id) {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/');
  }
  // `home.html` shows sign-out link
  // TODO: When developed, allow user to register their authenticator
  res.render('home.html', {id: req.cookies.id});
});

app.get('/reauth', function(req, res) {
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  // TODO: When developed, do fingerprint reauth
  res.render('reauth.html', {id: req.cookies.id});
});

app.get('/signout', function(req, res) {
  // Remove cookie
  res.clearCookie('id');
  // Redirect to `/`
  res.redirect(307, '/');
});

app.use('/auth', auth);

// listen for req :)
const listener = app.listen(process.env.PORT, function() {
  console.log('Your app is listening on port ' + listener.address().port);
});
