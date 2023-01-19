import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node'

const adapter = new JSONFile('.data/db.json');
const db = new Low(adapter);
await db.read();

db.data ||= { users: [] } ;

/**
 * User data schema
 * {
 *   id: Base64URL encoded user ID,
 *   username: string,
 *   displayName: string,
 * }
 **/

export const Users = {
  findById: (user_id) => {
    const user = db.data.users.find(user => user.id === user_id);
    return user;
  },

  findByUsername: (username) => {
    const user = db.data.users.find(user => user.username === username);
    return user;
  },

  update: async (user) => {
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
}

/**
 * User data schema
 * {
 *   publicKey: base64PublicKey,
 *   credId: base64CredentialID,
 *   name: req.useragent.platform,
 *   transports: credential.response.transports || []
 * }
 **/

export const Credentials = {
  findById: (credential_id) => {
    const credential = db.data.credentials.find(credential => credential.id === credential_id);
    return credential;
  }

  findByUserId: (user_id) => {
    const credentials = db.data.credentials.filter(credential => credential.user_id === user_id);
    return credentials;
  }

  update: async (credential) => {
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
}
