import firebaseJson  from './firebase.json' with { type: 'json' };
import { getFirestore } from 'firebase-admin/firestore';
import { initializeApp } from 'firebase-admin/app';

const is_localhost = process.env.NODE_ENV === 'localhost';
const env = is_localhost ? 'development' : 'production';
const _config = (await import(`./${env}.config.json`, {with:{type: 'json'}})).default; 

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

const { hostname, port, associated_domains = [], secret, rp_name, project_name } = _config;

const domain = port ? `${hostname}:${port}` : hostname;
const origin = is_localhost ? `http://${domain}` : `https://${domain}`;

const associated_origins = [];
for (let domain of associated_domains) {
  const associated_origin = generateApkKeyHash(domain.sha256_cert_fingerprints);
  associated_origins.push(associated_origin);
}

const config = {
  env,
  hostname,
  is_localhost,
  debug: is_localhost,
  domain,
  origin,
  secret: secret || 'set your own secret in the config file',
  rp_name: rp_name || 'Passkeys Demo',
  project_name: project_name || 'passkeys-demo',
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
