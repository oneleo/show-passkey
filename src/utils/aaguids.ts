// Refer:
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/combined_aaguid.json
import type { AuthenticatorData, AuthenticatorMap } from "./types";

let aaguidsCache: AuthenticatorMap | null = null;

export const getAuthenticatorData = async (
  aaguid: string,
): Promise<AuthenticatorData | undefined> => {
  if (!aaguidsCache) {
    const { default: loaded } = (await import("./aaguids.json")) as {
      default: AuthenticatorMap;
    };
    aaguidsCache = loaded;
  }
  return aaguidsCache[aaguid];
};

// --- AAGUID tools ---
// Explorer:
// https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/?combined
// https://webauthn.passwordless.id/demos/authenticators
// Source code:
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids
// https://github.com/passwordless-id/webauthn/blob/main/src/authenticatorMetadata.ts
