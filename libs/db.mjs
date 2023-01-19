import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node'

const adapter = new JSONFile('.data/db.json');
const db = new Low(adapter);
await db.read();

db.data ||= { users: [] } ;

export function findUserByUsername(username) {
  const user = db.data.users.find(user => user.username === username);
  return user;
}

export function findUserByUserId(user_id) {
  const user = db.data.users.find(user => user.id === user_id);
  return user;
}

export async function updateUser(user) {
  let found = false;
  db.data.users = db.data.users.map(_user => {
    if (_user.id === user.id) {
      found = true;
      return user;
    } else {
      return _user;
    }
  });
  if (!found) {
    db.data.users.push(user);
  }
  return db.write();
}

export function findCredentialByCredentialId(credential_id) {
  const credential = db.data.credentials.find(credential => credential.id === credential_id);
  return credential;
}

export function findCredentialByUserId(user_id) {
  const credential = db.data.credentials.find(credential => credential.user_id === user_id);
  return credential;
}

export async function updateCredential(credential) {
  let found = false;
  db.data.credentials = db.data.credentials.map(_credential => {
    if (_credential.id === credential.id) {
      found = true;
      return credential;
    } else {
      return _credential;
    }
  });
  if (!found) {
    db.data.credentials.push(credential);
  }
  return db.write();
}
