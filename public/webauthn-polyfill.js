import { UAParser } from "ua-parser-js";

export class base64url {
  static encode(buffer) {
    const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  static decode(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binStr = window.atob(base64);
    const bin = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bin[i] = binStr.charCodeAt(i);
    }
    return bin.buffer;
  }
}

if (window.PublicKeyCredential) {
  const uap = new UAParser();
  const browser = uap.getBrowser();
  if (!browser?.version) {
    throw new Error('Browser major version not found.');
  }
  const browserName = browser.name;
  const browserVer = parseFloat(browser.version.replace(/^([0-9]+\.[0-9]+).*$/, '$1'));

  const engine = uap.getEngine();
  if (!engine?.version) {
    throw new Error('Engine version not found.');
  }
  const engineName = engine.name;
  const engineVer = parseFloat(engine.version.replace(/^([0-9]+\.[0-9]+)\.*$/, '$1'));

  if (!window.PublicKeyCredential?.parseCreationOptionsFromJSON) {
    PublicKeyCredential.parseCreationOptionsFromJSON = (options) => {
      const user = {
        ...options.user,
        id: base64url.decode(options.user.id),
      };
      const challenge = base64url.decode(options.challenge);
      const excludeCredentials =
        options.excludeCredentials?.map((cred) => {
          return {
            ...cred,
            id: base64url.decode(cred.id),
          };
        }) ?? [];
      return {
        ...options,
        user,
        challenge,
        excludeCredentials,
      };
    };
  }

  if (!window.PublicKeyCredential?.parseRequestOptionsFromJSON) {
    PublicKeyCredential.parseRequestOptionsFromJSON = (options) => {
      const challenge = base64url.decode(options.challenge);
      const allowCredentials =
        options.allowCredentials?.map((cred) => {
          return {
            ...cred,
            id: base64url.decode(cred.id),
          };
        }) ?? [];
      return {
        ...options,
        allowCredentials,
        challenge,
      };
    };
  }

  if (!window.PublicKeyCredential.prototype.toJSON) {
    PublicKeyCredential.prototype.toJSON = function() {
      try {
        const id = this.id;
        const rawId = base64url.encode(this.rawId);
        const authenticatorAttachment = this.authenticatorAttachment;
        const clientExtensionResults = {};
        const type = this.type;
        // This is authentication.
        if (this.response.signature) {
          return {
            id,
            rawId,
            response: {
              authenticatorData: base64url.encode(this.response.authenticatorData),
              clientDataJSON: base64url.encode(this.response.clientDataJSON),
              signature: base64url.encode(this.response.signature),
              userHandle: base64url.encode(this.response.userHandle),
            },
            authenticatorAttachment,
            clientExtensionResults,
            type,
          };
        } else {
          return {
            id,
            rawId,
            response: {
              clientDataJSON: base64url.encode(this.response.clientDataJSON),
              attestationObject: base64url.encode(this.response.attestationObject),
              transports: this.response?.getTransports() || [],
            },
            authenticatorAttachment,
            clientExtensionResults,
            type,
          };
        }
      } catch (error) {
        console.error(error);
        throw error;
      }
    }
  }

  if (!PublicKeyCredential.getClientCapabilities ||
      // If this is Safari 17.4+, there's a spec glitch.
      (browserName === 'Safari' && browserVer >= 17.4)) {
    PublicKeyCredential.getClientCapabilities = async () => {
      let conditionalCreate = false;
      let conditionalGet = false;
      let hybridTransport = false;
      let passkeyPlatformAuthenticator = false;
      let userVerifyingPlatformAuthenticator = false;
      let relatedOrigins = false;
      let signalAllAcceptedCredentials = false;
      let signalCurrentUserDetails = false;
      let signalUnknownCredential = false;
      if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
          PublicKeyCredential.isConditionalMediationAvailable) {
        // Are UVPAA and conditional UI available on this browser?
        const results = await Promise.all([
          PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
          PublicKeyCredential.isConditionalMediationAvailable()
        ]);
        userVerifyingPlatformAuthenticator = results[0];
        conditionalGet = results[1];
      }
      if (PublicKeyCredential.signalAllAcceptedCredentials) {
        signalAllAcceptedCredentials = true;
      }
      if (PublicKeyCredential.signalCurrentUserDetails) {
        signalCurrentUserDetails = true;
      }
      if (PublicKeyCredential.signalUknownCredential) {
        signalUnknownCredential = true;
      }

      // `conditionalCreate` is `true` on Safari 15+
      if (browserName === 'Safari' && browserVer >= 18) {
        conditionalCreate = true;
      }
      // `hybridTransport` is `true` on Firefox 119+, Chromium 108+ and Safari 16+
      if ((engineName === 'Blink' && engineVer >= 108) ||
          (browserName === 'Firefox' && browserVer >= 119) ||
          (browserName === 'Safari' && browserVer >= 16)) {
        hybridTransport = true;
      } 
      // `passkeyPlatformAuthenticator` is `true` if `hybridTransport` or `userVerifyingPlatformAuthenticator` is `true`.
      if (hybridTransport || userVerifyingPlatformAuthenticator) {
        passkeyPlatformAuthenticator = true;
      }
      // `relatedOrigins` is `true` on Chromium 128+
      if ((engineName === 'Blink' && engineVer >= 128)) {
        relatedOrigins = true;
      }
      return {
        conditionalCreate,
        conditionalGet,
        hybridTransport,
        passkeyPlatformAuthenticator,
        relatedOrigins,
        signalAllAcceptedCredentials,
        signalCurrentUserDetails,
        signalUnknownCredential,
        userVerifyingPlatformAuthenticator,
      }
    };
  }
}
