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

app.use((req, res, next) => {
  if (req.get('x-forwarded-proto') &&
     (req.get('x-forwarded-proto')).split(',')[0] !== 'https') {
    return res.redirect(301, `https://${process.env.HOSTNAME}`);
  }
  req.schema = 'https';
  next();
});

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, res) => {
  // Check cookie
  if (req.cookies.username) {
    // If user is signed in, redirect to `/reauth`.
    res.redirect(307, '/reauth');
    return;
  }
  // If user is not signed in, show `index.html` with id/password form.
  res.render('index.html');
});

app.get('/home', (req, res) => {
  if (!req.cookies.username ||
      req.cookies['signed-in'] != 'yes') {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/');
    return;
  }
  // `home.html` shows sign-out link
  res.render('home.html', {username: req.cookies.username});
});

app.get('/reauth', (req, res) => {
  const username = req.cookies.username;
  if (!username) {
    res.redirect(302, '/');
    return;
  }
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  res.render('reauth.html', {username: username});
});

app.get('/.well-known/assetlinks.json', (req, res) => {
  const assetlinks = [];
  const relation = ['delegate_permission/common.handle_all_urls', 'delegate_permission/common.get_login_creds'];
  assetlinks.push({
    relation: relation,
    target: {
      namespace: 'web',
      site: `https://${process.env.HOSTNAME}`
    }
  });
  assetlinks.push({
    relation: relation,
    target: {
      namespace: 'android_app',
      package_name: process.env.ANDROID_PACKAGENAME,
      sha256_cert_fingerprints: [process.env.ANDROID_SHA256HASH]
    }
  });
  res.json(assetlinks);
});

app.use('/auth', auth);

// listen for req :)
const listener = app.listen(process.env.PORT, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});
