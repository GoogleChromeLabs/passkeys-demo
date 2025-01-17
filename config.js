import firebaseJson  from './firebase.json' with { type: 'json' };
import { getFirestore } from 'firebase-admin/firestore';
import { initializeApp } from 'firebase-admin/app';

const is_localhost = process.env.NODE_ENV === 'localhost';
const env = is_localhost ? 'development' : 'production';
let hostname, domain, origin, associated_domains = [], associated_origins = [];

function generateApkKeyHash(fingerprint) {
  const hexString = fingerprint.replace(/:/g, '');

  // Convert hex string to byte array
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
  }

  // Encode byte array to base64url
  const base64url = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `android:apk-key-hash:${base64url}`;
}

if (is_localhost) {
  hostname = 'localhost';
  associated_domains = [{
    package_name: 'com.google.credentialmanager.sample',
    sha256_cert_fingerprints: '4F:20:47:1F:D9:9A:BA:96:47:8D:59:27:C2:C8:A6:EA:8E:D2:8D:14:C0:B6:A2:39:99:9F:A3:4D:47:3D:FA:11'
  }, {
    package_name: 'com.example.android.authentication.shrine',
    sha256_cert_fingerprints: '4F:20:47:1F:D9:9A:BA:96:47:8D:59:27:C2:C8:A6:EA:8E:D2:8D:14:C0:B6:A2:39:99:9F:A3:4D:47:3D:FA:11'
  }];
} else {
  hostname = 'passkeys-demo.appspot.com';
  associated_domains = [{
    package_name: 'com.google.credentialmanager.sample',
    sha256_cert_fingerprints: '4F:20:47:1F:D9:9A:BA:96:47:8D:59:27:C2:C8:A6:EA:8E:D2:8D:14:C0:B6:A2:39:99:9F:A3:4D:47:3D:FA:11'
  }, {
    package_name: 'com.example.android.authentication.shrine',
    sha256_cert_fingerprints: '4F:20:47:1F:D9:9A:BA:96:47:8D:59:27:C2:C8:A6:EA:8E:D2:8D:14:C0:B6:A2:39:99:9F:A3:4D:47:3D:FA:11'
  }];
}

domain = is_localhost ? `${hostname}:8080` : hostname;
origin = is_localhost ? `http://${domain}` : `https://${domain}`;

for (let domain of associated_domains) {
  const associated_origin = generateApkKeyHash(domain.sha256_cert_fingerprints);
  associated_origins.push(associated_origin);
}

const config = {
  env,
  hostname,
  domain,
  origin,
  secret: 'set your own secret',
  rp_name: 'Passkeys Demo',
  project_name: 'passkeys-demo',
  associated_domains: [
    origin,
    ...associated_domains
  ],
  associated_origins: [
    origin,
    ...associated_origins
  ]
};

function initializeFirestore() {
  if (is_localhost) {
    process.env.GOOGLE_CLOUD_PROJECT = config.project_name;
    process.env.FIRESTORE_EMULATOR_HOST = `${firebaseJson.emulators.firestore.host}:${firebaseJson.emulators.firestore.port}`;
  }

  initializeApp();

  const store = getFirestore(process.env.FIRESTORE_DATABASENAME || '');
  store.settings({ignoreUndefinedProperties: true});
  return store;
}

const store = initializeFirestore();

export { config, store };
