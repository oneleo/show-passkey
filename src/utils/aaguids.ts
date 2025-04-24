// Refer:
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/combined_aaguid.json
import combinedAaguid from "./aaguids.json";
import type { AuthenticatorMap } from "./types";

export const authenticators: AuthenticatorMap =
  combinedAaguid as AuthenticatorMap;

// --- AAGUID tools ---
// Explorer:
// https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/?combined
// https://webauthn.passwordless.id/demos/authenticators
// Source code:
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids
// https://github.com/passwordless-id/webauthn/blob/main/src/authenticatorMetadata.ts
