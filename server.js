// server.js
// where your node app starts

// init project
const express = require('express');
const cookieParser = require('cookie-parser');
const hbs = require('hbs');
const multer = require('multer');
const upload = multer();
const auth = require('./libs/auth');
const app = express();

app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

app.use((req, res, next) => {
  if ((req.get('x-forwarded-proto')).split(',')[0] !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  req.schema = 'https';
  next();
});

// http://expressjs.com/en/starter/basic-routing.html
app.all('/', (req, res) => {
  res.clearCookie('signed-in');
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
  if (!req.cookies.username) {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/');
    return;
  }
  // `home.html` shows sign-out link
  res.render('home.html', {username: req.cookies.username});
});

app.all('/reauth', upload.array(), (req, res) => {
  const username = req.body.username || req.cookies.username;
  if (!username) {
    res.redirect(307, '/');
    return;
  }
  res.cookie('username', username);
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  res.render('reauth.html', {username: username});
});

app.use('/auth', auth);

// listen for req :)
const listener = app.listen(process.env.PORT, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});
