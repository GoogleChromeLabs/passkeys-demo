/*
 * @license
 * Copyright 2023 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

// init project
import path from 'path';
import url from 'url';
const __dirname = url.fileURLToPath(new URL('.', import.meta.url));
import express from 'express';
import session from 'express-session';
import hbs from 'express-handlebars';
const app = express();
import useragent from 'express-useragent';
import { getFirestore } from 'firebase-admin/firestore';
import { FirestoreStore } from '@google-cloud/connect-firestore';
import { auth } from './libs/auth.mjs';

const views = path.join(__dirname, 'views');
app.set('view engine', 'html');
app.engine('html', hbs.engine({
  extname: 'html',
  defaultLayout: 'index',
  layoutsDir: path.join(views, 'layouts'),
  partialsDir: path.join(views, 'partials'),
}));
app.set('views', './views');
app.use(express.json());
app.use(useragent.express());
app.use(express.static('public'));
app.use(express.static('dist'));
app.use(session({
  secret: 'secret', // You should specify a real secret here
  resave: true,
  saveUninitialized: false,
  proxy: true,
  store: new FirestoreStore({
    dataset: getFirestore(),
    kind: 'express-sessions',
  }),
  cookie:{
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'localhost',
    maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
  }
}));

const RP_NAME = 'Passkeys Demo';

app.use((req, res, next) => {
  process.env.HOSTNAME = req.hostname;
  const protocol = process.env.NODE_ENV === 'localhost' ? 'http' : 'https';
  process.env.ORIGIN = `${protocol}://${req.headers.host}`;
  process.env.RP_NAME = RP_NAME;
  req.schema = 'https';
  return next();
});

app.get('/', (req, res) => {
  // Check session
  if (req.session.username) {
    // If username is known, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }
  // If the user is not signed in, show `index.html` with id/password form.
  return res.render('index.html', {
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/one-button', (req, res) => {
  // Check session
  if (req.session.username) {
    // If username is known, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }
  // If the user is not signed in, show `index.html` with id/password form.
  return res.render('one-button.html', {
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/reauth', (req, res) => {
  const username = req.session.username;
  if (!username) {
    res.redirect(302, '/');
    return;
  }
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  res.render('reauth.html', {
    username: username,
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/home', (req, res) => {
  if (!req.session.username || req.session['signed-in'] != 'yes') {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/');
    return;
  }
  // `home.html` shows sign-out link
  return res.render('home.html', {
    displayName: req.session.username,
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/.well-known/assetlinks.json', (req, res) => {
  const assetlinks = [];
  const relation = [
    'delegate_permission/common.handle_all_urls',
    'delegate_permission/common.get_login_creds',
  ];
  assetlinks.push({
    relation: relation,
    target: {
      namespace: 'web',
      site: process.env.ORIGIN,
    },
  });
  if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
    const package_names = process.env.ANDROID_PACKAGENAME.split(",").map(name => name.trim());
    const hashes = process.env.ANDROID_SHA256HASH.split(",").map(hash => hash.trim());
    for (let i = 0; i < package_names.length; i++) {
      assetlinks.push({
        relation: relation,
        target: {
          namespace: 'android_app',
          package_name: package_names[i],
          sha256_cert_fingerprints: [hashes[i]],
        },
      });
    }
  }
  return res.json(assetlinks);
});

app.get('/.well-known/passkey-endpoints', (req, res) => {
  const web_endpoint = `${process.env.ORIGIN}/home`;
  return res.json({ enroll: web_endpoint, manage: web_endpoint });
});

app.use('/auth', auth);

const listener = app.listen(process.env.PORT || 8080, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});
