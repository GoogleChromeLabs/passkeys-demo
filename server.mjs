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

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import express from 'express';
import helmet from 'helmet';

export const REDIRECT_URL = 'https://identity.chrome.dev/passkey-form-autofill';
const STATIC_FILE_EXT_RE =
  /\.(?:avif|cjs|css|eot|gif|ico|jpe?g|js|json|less|map|mjs|otf|pdf|png|sass|scss|svg|ttf|txt|wasm|webmanifest|webp|woff2?|xml)$/i;

const isLocalhost = process.env.NODE_ENV === 'localhost';

export const app = express();
app.disable('x-powered-by');

if (!isLocalhost) {
  app.use(helmet());
}

// Return 404 for static asset requests instead of redirecting them to an HTML page.
app.use((req, res) => {
  if (STATIC_FILE_EXT_RE.test(req.path)) {
    return res.sendStatus(404);
  }
  return res.redirect(308, REDIRECT_URL);
});

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return (
      fs.realpathSync(process.argv[1]) ===
      fs.realpathSync(url.fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isMainModule()) {
  const listener = app.listen(process.env.PORT || 8080, () => {
    console.log('Your app is listening on port ' + listener.address().port);
  });
}
