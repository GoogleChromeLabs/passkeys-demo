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
import 'mdui/components/button.js';
import 'mdui/components/text-field.js';
import 'mdui/components/list.js';
import 'mdui/components/list-item.js';
import 'mdui/components/button-icon.js';
import 'mdui/components/tooltip.js';
import 'mdui/components/top-app-bar.js';
import 'mdui/components/top-app-bar-title.js';
import 'mdui/components/navigation-drawer.js';
import 'mdui/components/linear-progress.js';
import 'webauthn-polyfills';
import { marked } from 'marked';

document.addEventListener('DOMContentLoaded', () => {
  const drawer = document.querySelector('#drawer');
  const drawerButton = document.querySelector('#drawer-button');
  drawerButton.addEventListener('click', () => {
    drawer.open = !drawer.open;
  });
  const content = document.querySelector('#help .help-content')?.innerText?.trim();
  const headline = document.querySelector('#help .help-headline')?.innerText?.trim();
  if (headline) {
    document.querySelector('#help-headline').innerHTML = headline;
  }
  if (content) {
    const serialized = content.split('\n').map((line) => line.trim()).join('\n');
    const mkContent = marked.parse(serialized)
    document.querySelector('#help-content').innerHTML = mkContent;
  }
});

