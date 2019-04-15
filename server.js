// server.js
// where your node app starts

// init project
const express = require('express');
const app = express();

// we've started you off with Express, 
// but feel free to use whatever libs or frameworks you'd like through `package.json`.

// http://expressjs.com/en/starter/static-files.html
app.use(express.static('public'));

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', function(request, response) {
  // TODO: Check cookie
  // TODO: If user is not signed in, show `/views/index.html` with id/password form.
  // TODO: If user is signed in, redirect to `/reauth`.
  // TODO: `/views/index.html` shows id/password field along with "sign in" button.
  response.sendFile(__dirname + '/views/index.html');
});

app.post('/signin', function(request, response) {
  // TODO: If cookie contains an id (already signed in, this is reauth), let the user sign-in
  // TODO: If cookie doesn't contain an id, let in as long as `id` present (Ignore password)
  // TODO: If sign-in failed, return 401.
  // TODO: If sign-in succeeded, redirect to `/home`.
});

app.get('/home', function(request, response) {
  // TODO: If user is not signed in, redirect to `/`.
  // TODO: If user is signed in, redirect to `/reauth`.
  // TODO: `/views/home.html` shows sign-out link
  response.sendFile(__dirname + '/views/home.html');
});

app.get('/signout', function(request, response) {
  // TODO: Remove cookie
  // TODO: Redirect to `/`
  response.sendFile(__dirname + '/views/logout.html');
});

app.get('/reauth', function(request, response) {
  // TODO: Show `/views/reauth.html`.
  // TODO: User is supposed to enter a password (which will be ignored)
  // TODO: When developed, do fingerprint reauth
  // TODO: Make XHR POST to `/signin`
  response.sendFile(__dirname + '/views/reauth.html');
});

// listen for requests :)
const listener = app.listen(process.env.PORT, function() {
  console.log('Your app is listening on port ' + listener.address().port);
});
